"""Encoders for NetFlow v5, v9 and IPFIX: used to replay sample data and in the tests."""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Iterable, Iterator

from .model import Flow

V9_FIELDS_V4 = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (1, 8), (2, 8), (22, 4), (21, 4),
]  # fmt: skip
IPFIX_FIELDS_V4 = [
    (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (1, 8), (2, 8), (152, 8), (153, 8),
]  # fmt: skip
V9_FIELDS_V6 = [
    (27, 16),
    (28, 16),
    (7, 2),
    (11, 2),
    (4, 1),
    (6, 1),
    (1, 8),
    (2, 8),
    (22, 4),
    (21, 4),
]
IPFIX_FIELDS_V6 = [
    (27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (6, 1), (1, 8), (2, 8), (152, 8), (153, 8),
]  # fmt: skip


def _chunks(items: list[Flow], size: int) -> Iterator[list[Flow]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def encode_v5(flows: Iterable[Flow], export_ms: int, uptime_ms: int = 3_600_000) -> list[bytes]:
    """IPv4 flows only (v5 has no IPv6). At most 30 records per datagram."""
    items = [f for f in flows if ipaddress.ip_address(f.src).version == 4]
    datagrams = []
    for sequence, chunk in enumerate(_chunks(items, 30)):
        header = struct.pack(
            "!HHIIIIBBH", 5, len(chunk), uptime_ms, export_ms // 1000,
            (export_ms % 1000) * 1_000_000, sequence, 0, 0, 0,
        )  # fmt: skip
        body = b""
        for f in chunk:
            first = (uptime_ms - (export_ms - f.start_ms)) & 0xFFFFFFFF
            last = (uptime_ms - (export_ms - f.end_ms)) & 0xFFFFFFFF
            body += struct.pack(
                "!4s4s4sHHIIIIHHBBBBHHBBH",
                ipaddress.ip_address(f.src).packed, ipaddress.ip_address(f.dst).packed,
                b"\0" * 4, 0, 0, f.packets, f.bytes, first, last, f.sport, f.dport,
                0, f.tcp_flags, f.proto, 0, 0, 0, 0, 0, 0,
            )  # fmt: skip
        datagrams.append(header + body)
    return datagrams


def _record(f: Flow, ipfix: bool, export_ms: int, uptime_ms: int) -> bytes:
    head = (
        ipaddress.ip_address(f.src).packed
        + ipaddress.ip_address(f.dst).packed
        + struct.pack("!HHBBQQ", f.sport, f.dport, f.proto, f.tcp_flags, f.bytes, f.packets)
    )
    if ipfix:
        return head + struct.pack("!QQ", f.start_ms, f.end_ms)
    first = (uptime_ms - (export_ms - f.start_ms)) & 0xFFFFFFFF
    last = (uptime_ms - (export_ms - f.end_ms)) & 0xFFFFFFFF
    return head + struct.pack("!II", first, last)


def _template_set(ipfix: bool, template_id: int, fields: list[tuple[int, int]]) -> bytes:
    body = struct.pack("!HH", template_id, len(fields))
    for element, length in fields:
        body += struct.pack("!HH", element, length)
    set_id = 2 if ipfix else 0
    return struct.pack("!HH", set_id, 4 + len(body)) + body


def _datagrams(
    v4: list[Flow], v6: list[Flow], export_ms: int, uptime_ms: int, ipfix: bool,
    domain: int, per_packet: int,
) -> list[bytes]:  # fmt: skip
    f4 = IPFIX_FIELDS_V4 if ipfix else V9_FIELDS_V4
    f6 = IPFIX_FIELDS_V6 if ipfix else V9_FIELDS_V6
    templates = _template_set(ipfix, 257, f4) + _template_set(ipfix, 258, f6)
    result = []
    groups = [(257, chunk) for chunk in _chunks(v4, per_packet)]
    groups += [(258, chunk) for chunk in _chunks(v6, per_packet)]
    first = True
    for sequence, (template_id, chunk) in enumerate(groups or [(257, [])]):
        records = b"".join(_record(f, ipfix, export_ms, uptime_ms) for f in chunk)
        data_set = struct.pack("!HH", template_id, 4 + len(records)) + records if chunk else b""
        sets = (templates if first else b"") + data_set
        first = False
        if ipfix:
            header = struct.pack("!HHIII", 10, 16 + len(sets), export_ms // 1000, sequence, domain)
        else:
            header = struct.pack(
                "!HHIIII", 9, len(chunk) + 2, uptime_ms, export_ms // 1000, sequence, domain
            )
        result.append(header + sets)
    return result


def encode_v9(
    flows: Iterable[Flow], export_ms: int, uptime_ms: int = 3_600_000,
    source_id: int = 1, per_packet: int = 20,
) -> list[bytes]:  # fmt: skip
    items = list(flows)
    v4 = [f for f in items if ipaddress.ip_address(f.src).version == 4]
    v6 = [f for f in items if ipaddress.ip_address(f.src).version == 6]
    return _datagrams(v4, v6, export_ms, uptime_ms, False, source_id, per_packet)


def encode_ipfix(
    flows: Iterable[Flow], export_ms: int, domain: int = 1, per_packet: int = 20
) -> list[bytes]:
    items = list(flows)
    v4 = [f for f in items if ipaddress.ip_address(f.src).version == 4]
    v6 = [f for f in items if ipaddress.ip_address(f.src).version == 6]
    return _datagrams(v4, v6, export_ms, 0, True, domain, per_packet)


def send_udp(datagrams: Iterable[bytes], host: str, port: int) -> int:
    """Send datagrams to a collector. Returns how many were sent."""
    count = 0
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        for datagram in datagrams:
            sock.sendto(datagram, (host, port))
            count += 1
    return count
