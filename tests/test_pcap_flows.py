from __future__ import annotations

import gzip
import io
import struct

import pytest
from helpers import T0, classic_pcap, pcapng, pkt

from flowpipe.flows import FlowTable, packets_to_flows
from flowpipe.pcap import (
    MAX_RECORD,
    CaptureError,
    ReadStats,
    decode_frame,
    decode_ip,
    open_capture,
    read_packets,
)
from flowpipe.sample import write_pcap

PACKETS = [
    pkt(0, length=1500, flags=0x02),
    pkt(40, src="203.0.113.9", dst="10.0.0.5", sport=443, dport=50000, length=66),
    pkt(900, proto=17, sport=5353, dport=53, length=90, flags=0),
    pkt(950, src="2001:db8::5", dst="2001:db8::9", sport=40000, dport=443, length=1280),
    pkt(990, proto=1, sport=0, dport=0x0800, length=84, flags=0),
]


def read(data: bytes):
    stats = ReadStats()
    return list(read_packets(io.BytesIO(data), stats)), stats


def same(a, b):
    return [(p.ts_ms, p.src, p.dst, p.sport, p.dport, p.proto, p.length) for p in a] == [
        (p.ts_ms, p.src, p.dst, p.sport, p.dport, p.proto, p.length) for p in b
    ]


@pytest.mark.parametrize("order", ["<", ">"])
def test_classic_pcap_roundtrip_both_byte_orders(order):
    got, stats = read(classic_pcap(PACKETS, order))
    assert same(got, PACKETS)
    assert stats.packets == 5 and stats.skipped == 0 and not stats.truncated_file
    assert got[0].tcp_flags == 0x02


def test_nanosecond_timestamps():
    got, _ = read(classic_pcap(PACKETS, nanos=True))
    assert [p.ts_ms for p in got] == [p.ts_ms for p in PACKETS]


@pytest.mark.parametrize("order", ["<", ">"])
@pytest.mark.parametrize("tsresol", [None, 9, 3])
def test_pcapng_roundtrip(order, tsresol):
    got, stats = read(pcapng(PACKETS, order, tsresol))
    assert same(got, PACKETS)
    assert stats.records == 5


def test_icmp_type_and_code_are_kept_in_dport():
    got, _ = read(classic_pcap([pkt(0, proto=1, sport=0, dport=0x0301, length=56, flags=0)]))
    assert got[0].dport == 0x0301


def test_wire_length_comes_from_the_ip_header_not_the_snaplen():
    got, _ = read(classic_pcap([pkt(0, length=64000)]))
    assert got[0].length == 64000


def test_file_written_by_sample_module_and_gzip(tmp_path):
    path = tmp_path / "x.pcap"
    assert write_pcap(path, PACKETS) == 5
    gz = tmp_path / "x.pcap.gz"
    gz.write_bytes(gzip.compress(path.read_bytes()))
    for target in (path, gz):
        with open_capture(target) as handle:
            assert len(list(read_packets(handle))) == 5


@pytest.mark.parametrize(
    "data, message",
    [(b"", "too short"), (b"abc", "too short"), (b"NOPE" * 8, "not a pcap")],
)
def test_bad_files_raise_capture_error(data, message):
    with pytest.raises(CaptureError, match=message):
        read(data)


def test_truncated_global_header():
    with pytest.raises(CaptureError):
        read(classic_pcap(PACKETS)[:10])


def test_truncated_record_stops_cleanly():
    data = classic_pcap(PACKETS)
    got, stats = read(data[:-5])
    assert len(got) == 4 and stats.truncated_file
    got, stats = read(data[: 24 + 7])  # inside a record header
    assert got == [] and stats.truncated_file


def test_oversized_record_is_refused_without_allocating():
    header = classic_pcap([])
    data = header + struct.pack("<IIII", 1, 0, MAX_RECORD + 1, MAX_RECORD + 1) + b"x" * 100
    got, stats = read(data)
    assert got == [] and stats.errors == 1 and stats.truncated_file


def test_truncated_pcapng():
    data = pcapng(PACKETS)
    got, stats = read(data[:-9])
    assert len(got) == 4 and stats.truncated_file
    got, stats = read(data[:30])  # inside the section header
    assert got == [] and stats.truncated_file


def test_pcapng_bad_block_length():
    data = pcapng(PACKETS[:1])
    evil = data[:-4] + b"\0"  # keep it parseable up to the end, then add a block with length 3
    evil += struct.pack("<II", 6, 3) + b"\0" * 8
    got, stats = read(evil)
    assert len(got) == 1 and stats.errors == 1


def test_pcapng_packet_for_unknown_interface_is_an_error():
    shb = pcapng([])
    body = struct.pack("<IIIII", 7, 0, 0, 4, 4) + b"abcd"
    pad_total = 12 + len(body)
    evil = shb + struct.pack("<II", 6, pad_total) + body + struct.pack("<I", pad_total)
    got, stats = read(evil)
    assert got == [] and stats.errors == 1


def test_pcapng_simple_packet_block():
    from helpers import _block

    from flowpipe.sample import _frame

    frame, wire = _frame(PACKETS[0])
    data = pcapng([]) + _block(3, struct.pack("<I", wire) + frame)
    got, _ = read(data)
    assert len(got) == 1 and got[0].src == "10.0.0.5"


def test_pcapng_section_header_with_nonsense_length():
    bad = struct.pack("<IIIHHq", 0x0A0D0D0A, 99_999_999, 0x1A2B3C4D, 1, 0, -1)
    with pytest.raises(CaptureError):
        read(bad)


# --- decoding hostile packets ---------------------------------------------------------


def ipv4(proto=6, payload=b"\0" * 20, ihl=5, frag=0x4000, total=None):
    total = total if total is not None else ihl * 4 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total, 0, frag, 64, proto, 0,
                         bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))  # fmt: skip
    return header + b"\0" * (ihl * 4 - 20) + payload


@pytest.mark.parametrize(
    "data, reason",
    [
        (b"", "empty"),
        (b"\x45" + b"\0" * 5, "short-ipv4"),
        (ipv4(ihl=4), "bad-ipv4-header"),
        (ipv4(frag=0x0010), "fragment"),
        (ipv4(payload=b"\0\1"), "short-transport"),
        (b"\x60" + b"\0" * 10, "short-ipv6"),
        (b"\x10" + b"\0" * 40, "not-ip"),
    ],
)
def test_decode_ip_rejects_bad_packets(data, reason):
    stats = ReadStats()
    assert decode_ip(data, 0, stats) is None
    assert stats.reasons.get(reason) == 1


def v6(next_header, rest):
    return (
        struct.pack("!IHB B16s16s", 6 << 28, len(rest), next_header, 64, b"\1" * 16, b"\2" * 16)
        + rest
    )


def test_ipv6_extension_headers_are_walked():
    udp = struct.pack("!HHHH", 1234, 53, 8, 0)
    hop = struct.pack("!BB6x", 17, 0)  # hop-by-hop, 8 bytes, next = UDP
    packet = decode_ip(v6(0, hop + udp), 5)
    assert packet is not None and packet.proto == 17 and packet.dport == 53


def test_ipv6_fragment_header_first_and_later_fragments():
    udp = struct.pack("!HHHH", 1234, 53, 8, 0)
    first = struct.pack("!BBHI", 17, 0, 0x0001, 7)  # offset 0, more fragments
    later = struct.pack("!BBHI", 17, 0, 0x0008, 7)  # offset 1
    assert decode_ip(v6(44, first + udp), 0) is not None
    stats = ReadStats()
    assert decode_ip(v6(44, later + udp), 0, stats) is None
    assert stats.reasons["fragment"] == 1


def test_ipv6_truncated_extension_header():
    stats = ReadStats()
    assert decode_ip(v6(0, b"\0"), 0, stats) is None
    assert stats.reasons["short-ipv6-ext"] == 1
    assert decode_ip(v6(44, b"\0" * 3), 0, stats) is None


def test_vlan_tagged_and_other_link_types():
    inner = ipv4(proto=17, payload=struct.pack("!HHHH", 1, 2, 8, 0))
    tagged = bytes(12) + struct.pack("!HHH", 0x8100, 5, 0x0800) + inner
    assert decode_frame(1, tagged, 0).dport == 2
    assert decode_frame(101, inner, 0).dport == 2
    assert decode_frame(0, b"\2\0\0\0" + inner, 0).dport == 2
    assert decode_frame(113, bytes(16) + inner, 0).dport == 2
    assert decode_frame(276, bytes(20) + inner, 0).dport == 2
    stats = ReadStats()
    assert decode_frame(147, inner, 0, stats) is None
    assert stats.reasons == {"link-type-147": 1}
    assert decode_frame(1, b"short", 0, stats) is None
    arp = bytes(12) + struct.pack("!H", 0x0806) + bytes(28)
    assert decode_frame(1, arp, 0, stats) is None


def test_fuzz_never_crashes():
    import random

    rng = random.Random(1)
    base = classic_pcap(PACKETS)
    for _ in range(300):
        data = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            read(bytes(data[: rng.randint(30, len(data))]))
        except CaptureError:
            pass
    ng = pcapng(PACKETS)
    for _ in range(300):
        data = bytearray(ng)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            read(bytes(data[: rng.randint(30, len(data))]))
        except CaptureError:
            pass


# --- flow table -----------------------------------------------------------------------


def test_packets_aggregate_into_one_flow():
    flows = list(packets_to_flows([pkt(0, flags=0x02), pkt(100, flags=0x10), pkt(200, flags=0x01)]))
    assert len(flows) == 1
    f = flows[0]
    assert (f.bytes, f.packets, f.tcp_flags) == (3000, 3, 0x13)
    assert (f.start_ms, f.end_ms) == (T0, T0 + 200)


def test_directions_are_separate_flows():
    flows = list(
        packets_to_flows(
            [pkt(0), pkt(10, src="203.0.113.9", dst="10.0.0.5", sport=443, dport=50000)]
        )
    )
    assert len(flows) == 2


def test_idle_timeout_splits_a_flow():
    flows = list(packets_to_flows([pkt(0), pkt(20_000)], idle_ms=15_000))
    assert [f.packets for f in flows] == [1, 1]


def test_active_timeout_splits_a_long_flow():
    packets = [pkt(second * 1000) for second in range(0, 195, 5)]
    flows = list(packets_to_flows(packets, idle_ms=15_000, active_ms=60_000))
    assert len(flows) == 3 and sum(f.packets for f in flows) == len(packets)


def test_expiry_emits_flows_while_streaming():
    table = FlowTable(idle_ms=5_000)
    emitted = list(table.add(pkt(0)))
    emitted += list(table.add(pkt(10_000, src="10.0.0.9")))  # a later packet expires the first
    assert len(emitted) == 1 and len(table) == 1
    assert len(list(table.flush())) == 1 and len(table) == 0


def test_flow_table_is_capped():
    table = FlowTable(max_flows=100)
    emitted = []
    for index in range(1000):  # a port scan: every packet is a new flow
        emitted += list(table.add(pkt(index, dport=index + 1)))
    assert len(table) <= 100 and len(emitted) >= 900
    assert len(emitted) + len(list(table.flush())) == 1000


def test_out_of_order_packets_extend_the_flow_backwards():
    flows = list(packets_to_flows([pkt(500), pkt(100)]))
    assert flows[0].start_ms == T0 + 100 and flows[0].end_ms == T0 + 500
