"""Pure-Python reader for pcap and pcapng files, down to TCP/UDP/ICMP headers.

Capture files are untrusted input: every length is checked, truncated or malformed
records are counted and skipped, and nothing here allocates more than one record at a time.
"""

from __future__ import annotations

import gzip
import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

MAX_RECORD = 262_144  # larger than any real frame (even with jumbo frames and headers)

LINK_NULL = 0
LINK_ETHERNET = 1
LINK_RAW = 101
LINK_LINUX_SLL = 113
LINK_RAW_V4 = 228
LINK_RAW_V6 = 229
LINK_LINUX_SLL2 = 276

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER = 0x1A2B3C4D


class CaptureError(ValueError):
    """The file is not a readable capture."""


@dataclass(frozen=True, slots=True)
class Packet:
    ts_ms: int
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    length: int  # IP total length: counts the bytes that were on the wire, not the snaplen
    tcp_flags: int = 0


@dataclass
class ReadStats:
    records: int = 0
    packets: int = 0
    skipped: int = 0  # not IP, fragments after the first, truncated headers
    errors: int = 0  # damaged records
    truncated_file: bool = False
    reasons: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


def _ip(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def decode_ip(data: bytes, ts_ms: int, stats: ReadStats | None = None) -> Packet | None:
    """Decode an IPv4 or IPv6 packet. Returns None for anything that is not usable."""

    def reject(reason: str) -> None:
        if stats is not None:
            stats.skip(reason)

    if not data:
        reject("empty")
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            reject("short-ipv4")
            return None
        header_len = (data[0] & 0x0F) * 4
        if header_len < 20 or len(data) < header_len:
            reject("bad-ipv4-header")
            return None
        total = struct.unpack_from("!H", data, 2)[0]
        frag = struct.unpack_from("!H", data, 6)[0]
        if frag & 0x1FFF:  # not the first fragment: no transport header here
            reject("fragment")
            return None
        proto = data[9]
        src, dst = _ip(data[12:16]), _ip(data[16:20])
        payload = data[header_len:]
        length = total or len(data)
    elif version == 6:
        if len(data) < 40:
            reject("short-ipv6")
            return None
        payload_len = struct.unpack_from("!H", data, 4)[0]
        proto = data[6]
        src, dst = _ip(data[8:24]), _ip(data[24:40])
        offset = 40
        # Walk the extension headers until the transport protocol.
        for _ in range(8):
            if proto in (0, 43, 60):  # hop-by-hop, routing, destination options
                if len(data) < offset + 2:
                    reject("short-ipv6-ext")
                    return None
                proto, ext = data[offset], (data[offset + 1] + 1) * 8
                offset += ext
            elif proto == 44:  # fragment header
                if len(data) < offset + 8:
                    reject("short-ipv6-ext")
                    return None
                if struct.unpack_from("!H", data, offset + 2)[0] & 0xFFF8:
                    reject("fragment")
                    return None
                proto = data[offset]
                offset += 8
            else:
                break
        payload = data[offset:]
        length = 40 + payload_len if payload_len else len(data)
    else:
        reject("not-ip")
        return None

    sport = dport = flags = 0
    if proto in (6, 17, 132):
        if len(payload) < 4:
            reject("short-transport")
            return None
        sport, dport = struct.unpack_from("!HH", payload, 0)
        if proto == 6 and len(payload) >= 14:
            flags = payload[13]
    elif proto in (1, 58):
        if len(payload) >= 2:
            dport = payload[0] * 256 + payload[1]  # ICMP type and code, kept for analysis
    return Packet(ts_ms, src, dst, sport, dport, proto, length, flags)


def decode_frame(
    link_type: int, frame: bytes, ts_ms: int, stats: ReadStats | None = None
) -> Packet | None:
    """Strip the link layer and decode the IP packet inside."""
    if link_type == LINK_ETHERNET:
        if len(frame) < 14:
            if stats is not None:
                stats.skip("short-ethernet")
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        for _ in range(2):  # 802.1Q and QinQ tags
            if ethertype in (0x8100, 0x88A8, 0x9100):
                if len(frame) < offset + 4:
                    return None
                ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
                offset += 4
        if ethertype not in (0x0800, 0x86DD):
            if stats is not None:
                stats.skip("not-ip")
            return None
        return decode_ip(frame[offset:], ts_ms, stats)
    if link_type in (LINK_RAW, LINK_RAW_V4, LINK_RAW_V6):
        return decode_ip(frame, ts_ms, stats)
    if link_type == LINK_NULL:
        return decode_ip(frame[4:], ts_ms, stats)
    if link_type == LINK_LINUX_SLL:
        return decode_ip(frame[16:], ts_ms, stats)
    if link_type == LINK_LINUX_SLL2:
        return decode_ip(frame[20:], ts_ms, stats)
    if stats is not None:
        stats.skip(f"link-type-{link_type}")
    return None


def _read_exact(stream: BinaryIO, size: int) -> bytes | None:
    data = stream.read(size)
    return data if len(data) == size else None


def _classic(stream: BinaryIO, magic: bytes, stats: ReadStats) -> Iterator[Packet]:
    order, unit = PCAP_MAGICS[magic]
    header = _read_exact(stream, 20)
    if header is None:
        raise CaptureError("truncated pcap header")
    link_type = struct.unpack(order + "I", header[16:20])[0] & 0x0FFFFFFF
    record = struct.Struct(order + "IIII")
    while True:
        head = stream.read(16)
        if not head:
            return
        if len(head) < 16:
            stats.truncated_file = True
            return
        seconds, fraction, caplen, _orig = record.unpack(head)
        if caplen > MAX_RECORD:
            stats.errors += 1
            stats.truncated_file = True  # cannot resynchronise after a bad length
            return
        frame = _read_exact(stream, caplen)
        if frame is None:
            stats.truncated_file = True
            return
        stats.records += 1
        ts_ms = seconds * 1000 + (fraction // unit if unit == 1_000 else fraction // 1_000_000)
        packet = decode_frame(link_type, frame, ts_ms, stats)
        if packet is not None:
            stats.packets += 1
            yield packet


def _pcapng(stream: BinaryIO, first: bytes, stats: ReadStats) -> Iterator[Packet]:
    order = "<"
    interfaces: list[tuple[int, int]] = []  # (link type, timestamp units per second)
    pending = first  # the 4 bytes already read to detect the format
    while True:
        head = pending + stream.read(8 - len(pending))
        pending = b""
        if not head:
            return
        if len(head) < 8:
            stats.truncated_file = True
            return
        block_type = struct.unpack("<I", head[:4])[0]
        if block_type == PCAPNG_SHB:
            magic = stream.read(4)
            if len(magic) < 4:
                stats.truncated_file = True
                return
            order = "<" if struct.unpack("<I", magic)[0] == PCAPNG_BYTE_ORDER else ">"
            total = struct.unpack(order + "I", head[4:8])[0]
            if total < 12 or total > MAX_RECORD:
                raise CaptureError("bad pcapng section header")
            if _read_exact(stream, total - 12) is None:
                stats.truncated_file = True
                return
            interfaces = []  # interface ids restart in every section
            continue
        block_type, total = struct.unpack(order + "II", head)
        if total < 12 or total > MAX_RECORD or total % 4:
            stats.errors += 1
            stats.truncated_file = True
            return
        body = _read_exact(stream, total - 8)
        if body is None:
            stats.truncated_file = True
            return
        body = body[:-4]  # drop the trailing block length
        if block_type == 1 and len(body) >= 8:  # interface description
            link_type = struct.unpack_from(order + "H", body, 0)[0]
            units = 1_000_000  # default if_tsresol is 6
            position = 8
            while position + 4 <= len(body):
                code, size = struct.unpack_from(order + "HH", body, position)
                position += 4
                if code == 0:
                    break
                if code == 9 and size >= 1 and position < len(body):
                    value = body[position]
                    units = 2 ** (value & 0x7F) if value & 0x80 else 10 ** (value & 0x7F)
                position += (size + 3) // 4 * 4
            interfaces.append((link_type, max(1, units)))
        elif block_type == 6 and len(body) >= 20:  # enhanced packet block
            interface, high, low, caplen, _orig = struct.unpack_from(order + "IIIII", body, 0)
            if interface >= len(interfaces) or 20 + caplen > len(body):
                stats.errors += 1
                continue
            link_type, units = interfaces[interface]
            ticks = (high << 32) | low
            stats.records += 1
            packet = decode_frame(link_type, body[20 : 20 + caplen], ticks * 1000 // units, stats)
            if packet is not None:
                stats.packets += 1
                yield packet
        elif block_type == 3 and len(body) >= 4 and interfaces:  # simple packet block
            link_type, _ = interfaces[0]
            stats.records += 1
            packet = decode_frame(link_type, body[4:], 0, stats)
            if packet is not None:
                stats.packets += 1
                yield packet


def read_packets(stream: BinaryIO, stats: ReadStats | None = None) -> Iterator[Packet]:
    """Yield the packets of a pcap or pcapng stream (any byte order, µs or ns timestamps)."""
    stats = stats if stats is not None else ReadStats()
    magic = stream.read(4)
    if len(magic) < 4:
        raise CaptureError("file is too short to be a capture")
    if magic in PCAP_MAGICS:
        yield from _classic(stream, magic, stats)
    elif struct.unpack("<I", magic)[0] == PCAPNG_SHB:
        yield from _pcapng(stream, magic, stats)
    else:
        raise CaptureError("not a pcap or pcapng file")


def open_capture(path: Path) -> BinaryIO:
    """Open a capture, transparently handling .gz."""
    handle: BinaryIO
    handle = gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")  # type: ignore[assignment]
    return handle
