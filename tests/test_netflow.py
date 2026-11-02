from __future__ import annotations

import random
import struct

import pytest

from flowpipe.exporters import encode_ipfix, encode_v5, encode_v9, send_udp
from flowpipe.model import Flow
from flowpipe.netflow import (
    FlowParseError,
    Template,
    TemplateCache,
    parse_datagram,
    parse_ipfix,
    parse_v9,
)

NOW = 1_793_000_100_000
FLOWS = [
    Flow(NOW - 4000, NOW - 2500, "10.0.0.5", "203.0.113.9", 51000, 443, 6, 1500, 3, 0x1B),
    Flow(NOW - 3000, NOW - 2900, "10.0.0.6", "198.51.100.7", 5353, 53, 17, 200, 2, 0),
    Flow(NOW - 3500, NOW - 3400, "2001:db8::5", "2001:db8::9", 40000, 443, 6, 9000, 8, 0x10),
]


def key(f: Flow):
    return (f.src, f.dst, f.sport, f.dport, f.proto, f.bytes, f.packets, f.start_ms, f.end_ms)


def decode(datagrams, exporter="192.0.2.1"):
    cache = TemplateCache()
    out = []
    for datagram in datagrams:
        out += parse_datagram(datagram, exporter, cache)
    return out


def test_v5_roundtrip():
    got = decode(encode_v5(FLOWS, NOW))
    assert sorted(map(key, got)) == sorted(map(key, FLOWS[:2]))  # v5 has no IPv6
    assert all(f.source == "netflow" and f.exporter == "192.0.2.1" for f in got)


@pytest.mark.parametrize("encoder", [encode_v9, encode_ipfix])
def test_template_based_roundtrip_including_ipv6(encoder):
    got = decode(encoder(FLOWS, NOW))
    assert sorted(map(key, got)) == sorted(map(key, FLOWS))
    assert {f.tcp_flags for f in got} == {0x1B, 0, 0x10}


def test_many_flows_split_over_several_datagrams():
    many = [
        Flow(NOW - 10, NOW, "10.0.0.5", "203.0.113.9", 1000 + i, 443, 6, 100, 1) for i in range(95)
    ]
    assert len(decode(encode_v5(many, NOW))) == 95
    assert len(encode_v5(many, NOW)) == 4  # 30 per datagram
    assert len(decode(encode_ipfix(many, NOW, per_packet=20))) == 95


def test_data_before_template_is_dropped_not_fatal():
    first, second = encode_ipfix(FLOWS, NOW, per_packet=1)[:2]  # only the first has the template
    cache = TemplateCache()
    assert parse_datagram(second, "r", cache) == []  # template unknown yet
    assert len(parse_datagram(first, "r", cache)) == 1
    assert len(parse_datagram(second, "r", cache)) == 1  # now it is known


def test_templates_are_per_exporter_and_domain():
    datagrams = encode_ipfix(FLOWS, NOW)
    cache = TemplateCache()
    parse_datagram(datagrams[0], "router-a", cache)
    assert parse_datagram(datagrams[-1], "router-b", cache) == []


def test_template_cache_is_bounded():
    cache = TemplateCache(limit=3)
    for index in range(10):
        cache.put("r", 1, 256 + index, Template(((1, 4),), 4))
    assert len(cache) == 3 and cache.get("r", 1, 256) is None and cache.get("r", 1, 265)


def test_v5_sampling_interval_scales_counters():
    datagram = bytearray(encode_v5(FLOWS[:1], NOW)[0])
    struct.pack_into("!H", datagram, 22, 100)  # sampling interval 100
    got = parse_datagram(bytes(datagram), "r", TemplateCache())
    assert got[0].bytes == 150_000 and got[0].packets == 300


# --- hostile input --------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\0",
        b"\0\5",
        b"\0\x08" + b"\0" * 30,
        b"\xff\xff" + b"\0" * 30,
        b"\0\5\0\x1f" + b"\0" * 20,
    ],
)
def test_garbage_is_rejected(data):
    with pytest.raises(FlowParseError):
        parse_datagram(data, "r", TemplateCache())


def test_v5_count_larger_than_datagram():
    datagram = encode_v5(FLOWS[:1], NOW)[0]
    forged = datagram[:2] + struct.pack("!H", 30) + datagram[4:]
    with pytest.raises(FlowParseError):
        parse_datagram(forged, "r", TemplateCache())


def test_ipfix_length_field_lies():
    datagram = bytearray(encode_ipfix(FLOWS, NOW)[0])
    struct.pack_into("!H", datagram, 2, len(datagram) + 100)
    with pytest.raises(FlowParseError):
        parse_datagram(bytes(datagram), "r", TemplateCache())


def test_set_length_overruns_the_datagram():
    datagram = bytearray(encode_ipfix(FLOWS, NOW)[0])
    struct.pack_into("!H", datagram, 18, 60_000)
    with pytest.raises(FlowParseError):
        parse_datagram(bytes(datagram), "r", TemplateCache())


def test_template_with_too_many_fields():
    body = struct.pack("!HH", 256, 5000) + b"\0" * 40
    forged = (
        struct.pack("!HHIII", 10, 16 + 4 + len(body), 0, 0, 1)
        + struct.pack("!HH", 2, 4 + len(body))
        + body
    )
    with pytest.raises(FlowParseError, match="too many"):
        parse_ipfix(forged, "r", TemplateCache())


def test_truncated_template():
    body = struct.pack("!HH", 256, 3) + struct.pack("!HH", 8, 4)  # promises 3 fields, has 1
    forged = (
        struct.pack("!HHIII", 10, 16 + 4 + len(body), 0, 0, 1)
        + struct.pack("!HH", 2, 4 + len(body))
        + body
    )
    with pytest.raises(FlowParseError, match="truncated"):
        parse_ipfix(forged, "r", TemplateCache())


def test_template_id_below_256():
    body = struct.pack("!HH", 100, 1) + struct.pack("!HH", 8, 4)
    forged = (
        struct.pack("!HHIII", 10, 16 + 4 + len(body), 0, 0, 1)
        + struct.pack("!HH", 2, 4 + len(body))
        + body
    )
    with pytest.raises(FlowParseError, match="below 256"):
        parse_ipfix(forged, "r", TemplateCache())


def ipfix_message(template_fields, records, template_id=300, domain=1):
    tpl = struct.pack("!HH", template_id, len(template_fields)) + b"".join(
        struct.pack("!HH", e, n) for e, n in template_fields
    )
    sets = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    sets += struct.pack("!HH", template_id, 4 + len(records)) + records
    return struct.pack("!HHIII", 10, 16 + len(sets), NOW // 1000, 0, domain) + sets


def test_variable_length_and_enterprise_fields():
    fields = [(0x8001, 4), (8, 4), (12, 4), (1, 8), (2, 8), (0x0123, 0xFFFF)]
    # the enterprise field carries a 4-byte enterprise number after its element id in the template
    tpl_fields = struct.pack("!HHI", 0x8001, 4, 99) + b"".join(
        struct.pack("!HH", e, n) for e, n in fields[1:]
    )
    tpl = struct.pack("!HH", 300, len(fields)) + tpl_fields
    record = b"\xde\xad\xbe\xef" + bytes([10, 0, 0, 1]) + bytes([203, 0, 113, 5])
    record += struct.pack("!QQ", 500, 4) + bytes([3]) + b"abc"
    sets = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
    sets += struct.pack("!HH", 300, 4 + len(record)) + record
    message = struct.pack("!HHIII", 10, 16 + len(sets), NOW // 1000, 0, 1) + sets
    got = parse_datagram(message, "r", TemplateCache())
    assert len(got) == 1 and (got[0].src, got[0].bytes, got[0].packets) == ("10.0.0.1", 500, 4)


def test_variable_length_field_overrunning_the_set():
    fields = [(8, 4), (12, 4), (1, 8), (2, 8), (0x0123, 0xFFFF)]
    record = (
        bytes([10, 0, 0, 1])
        + bytes([203, 0, 113, 5])
        + struct.pack("!QQ", 5, 1)
        + bytes([200])
        + b"x"
    )
    with pytest.raises(FlowParseError, match="overruns"):
        parse_datagram(ipfix_message(fields, record), "r", TemplateCache())


def test_records_without_addresses_are_skipped():
    fields = [(1, 8), (2, 8)]  # an options-style record: counters only
    got = parse_datagram(ipfix_message(fields, struct.pack("!QQ", 5, 1)), "r", TemplateCache())
    assert got == []


def test_template_withdrawal():
    cache = TemplateCache()
    parse_datagram(encode_ipfix(FLOWS, NOW)[0], "r", cache)
    assert len(cache) == 2
    withdraw = struct.pack("!HH", 2, 8) + struct.pack("!HH", 2, 0)
    parse_datagram(struct.pack("!HHIII", 10, 16 + len(withdraw), 0, 0, 1) + withdraw, "r", cache)
    assert len(cache) == 0


def test_v9_options_templates_are_ignored():
    options = struct.pack("!HH", 1, 12) + b"\0" * 8
    datagram = struct.pack("!HHIIII", 9, 1, 0, NOW // 1000, 0, 1) + options
    assert parse_v9(datagram, "r", TemplateCache()) == []


def test_random_mutations_never_crash():
    rng = random.Random(5)
    corpus = encode_v5(FLOWS, NOW) + encode_v9(FLOWS, NOW) + encode_ipfix(FLOWS, NOW)
    cache = TemplateCache()
    for datagram in corpus:  # learn real templates first, so data sets get decoded
        parse_datagram(datagram, "r", cache)
    for _ in range(3000):
        data = bytearray(rng.choice(corpus))
        for _ in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        try:
            parse_datagram(bytes(data[: rng.randint(4, len(data))]), "r", cache)
        except FlowParseError:
            pass


def test_send_udp(monkeypatch):
    import socket

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(2)
    port = receiver.getsockname()[1]
    assert send_udp([b"abc", b"def"], "127.0.0.1", port) == 2
    assert receiver.recv(10) == b"abc"
    receiver.close()
