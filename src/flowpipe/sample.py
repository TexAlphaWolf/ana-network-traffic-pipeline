"""Synthetic but realistic traffic for demos and tests: a small office day with two incidents.

Everything uses documentation address ranges (RFC 5737 / RFC 3849) and private ranges, so
the sample data contains nothing real. The random generator is seeded, so the same
arguments always produce the same capture.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from collections.abc import Iterable, Iterator
from pathlib import Path

from .pcap import LINK_ETHERNET, Packet

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01

ROUTER = "10.20.0.1"
LAPTOP = "10.20.0.10"
PHONE = "10.20.0.21"
TV = "10.20.0.30"
NAS = "10.20.0.50"
CAMERA = "10.20.0.60"
SCANNER = "198.51.100.66"  # the "attacker" in the port scan
EXFIL = "203.0.113.200"  # where the laptop suddenly uploads gigabytes
STREAMING = "198.51.100.20"
BACKUP = "203.0.113.80"
DNS_UPSTREAM = "198.51.100.53"
NTP = "203.0.113.123"
MQTT = "203.0.113.99"
WEB = [f"203.0.113.{n}" for n in (10, 11, 12, 13, 14, 15, 16, 17)]


def _packets_for(
    rng: random.Random, start_ms: int, src: str, dst: str, sport: int, dport: int,
    proto: int, total_bytes: int, duration_ms: int, mtu: int = 1400, reply: bool = True,
) -> Iterator[Packet]:  # fmt: skip
    """One conversation: `total_bytes` from src to dst, with a small reply stream back."""
    count = max(1, total_bytes // mtu)
    size = max(60, min(mtu, total_bytes // count))
    flags = (ACK | PSH) if proto == 6 else 0
    if proto == 6:
        yield Packet(start_ms, src, dst, sport, dport, 6, 60, SYN)
    for index in range(count):
        offset = start_ms + (duration_ms * index // count) + rng.randrange(0, 20)
        yield Packet(offset, src, dst, sport, dport, proto, size, flags)
        if reply and index % 2 == 0:
            yield Packet(offset + 5, dst, src, dport, sport, proto, 66, ACK if proto == 6 else 0)
    if proto == 6:
        yield Packet(start_ms + duration_ms, src, dst, sport, dport, 6, 52, FIN | ACK)


def generate_packets(start_ms: int, minutes: int = 30, seed: int = 7) -> list[Packet]:
    """Traffic for `minutes` minutes: background load, one big upload and one port scan."""
    rng = random.Random(seed)
    out: list[Packet] = []
    for minute in range(minutes):
        base = start_ms + minute * 60_000

        def at(seconds: float, base: int = base) -> int:
            return base + int(seconds * 1000)

        # Web browsing from the laptop and the phone, spread over the minute.
        for _ in range(rng.randint(3, 6)):
            host = rng.choice([LAPTOP, LAPTOP, PHONE])
            out += _packets_for(
                rng, at(rng.uniform(0, 55)), host, rng.choice(WEB), rng.randint(40000, 60000),
                443, 6, rng.randint(10_000, 200_000), rng.randint(500, 4000),
            )  # fmt: skip
        # DNS lookups.
        for _ in range(rng.randint(10, 20)):
            host = rng.choice([LAPTOP, PHONE, TV, CAMERA])
            sport = rng.randint(40000, 60000)
            out += _packets_for(rng, at(rng.uniform(0, 59)), host, ROUTER, sport, 53, 17, 90, 200)
        out += _packets_for(rng, at(1), ROUTER, DNS_UPSTREAM, 33333, 53, 17, 3_000, 40_000)
        # Streaming on the TV: a steady, heavy download (large packets from the server).
        out += _packets_for(
            rng, at(0), STREAMING, TV, 443, 50000, 6, 6_000_000, 58_000, 9000, False
        )
        # Camera heartbeat and NTP.
        out += _packets_for(rng, at(3), CAMERA, MQTT, 45000, 8883, 6, 2_000, 1000)
        if minute % 5 == 0:
            out += _packets_for(rng, at(10), PHONE, NTP, 123, 123, 17, 90, 200)
        # NAS backup in the second half of the capture.
        if minute >= minutes // 2:
            out += _packets_for(
                rng, at(5), NAS, BACKUP, 52000 + minute, 22, 6, 2_500_000, 50_000, 9000, False
            )  # fmt: skip

    # Incident 1: the laptop uploads far more than usual for three minutes.
    spike_at = start_ms + int(minutes * 0.6) * 60_000
    for extra in range(3):
        out += _packets_for(
            rng, spike_at + extra * 60_000, LAPTOP, EXFIL, 55555 + extra, 443, 6,
            90_000_000, 58_000, 16_000, False,
        )  # fmt: skip

    # Incident 2: someone scans the router's ports from the internet.
    scan_at = start_ms + int(minutes * 0.35) * 60_000 + 20_000
    for index, port in enumerate(rng.sample(range(1, 10_000), 400)):
        out.append(Packet(scan_at + index * 100, SCANNER, ROUTER, 44444, port, 6, 44, SYN))
        out.append(Packet(scan_at + index * 100 + 2, ROUTER, SCANNER, port, 44444, 6, 40, 0x14))

    out.sort(key=lambda packet: packet.ts_ms)
    return out


def _frame(packet: Packet) -> tuple[bytes, int]:
    """Ethernet frame with headers only; returns (captured bytes, original wire length)."""
    version = ipaddress.ip_address(packet.src).version
    if packet.proto == 6:
        transport = struct.pack(
            "!HHIIBBHHH", packet.sport, packet.dport, 0, 0, 5 << 4, packet.tcp_flags, 65535, 0, 0
        )
    elif packet.proto == 17:
        transport = struct.pack("!HHHH", packet.sport, packet.dport, max(8, packet.length - 20), 0)
    else:
        transport = struct.pack("!BBHI", packet.dport >> 8, packet.dport & 0xFF, 0, 0)
    src = ipaddress.ip_address(packet.src).packed
    dst = ipaddress.ip_address(packet.dst).packed
    if version == 4:
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, packet.length, 0, 0x4000, 64, packet.proto, 0, src, dst
        )
        ethertype = 0x0800
    else:
        ip = struct.pack(
            "!IHBB16s16s", 6 << 28, max(0, packet.length - 40), packet.proto, 64, src, dst
        )
        ethertype = 0x86DD
    ether = bytes(6) + bytes(6) + struct.pack("!H", ethertype)
    captured = ether + ip + transport
    return captured, len(ether) + packet.length


def write_pcap(path: Path, packets: Iterable[Packet]) -> int:
    """Write packets as a classic pcap (microseconds, Ethernet). Returns the packet count."""
    count = 0
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINK_ETHERNET))
        for packet in packets:
            frame, wire = _frame(packet)
            seconds, millis = divmod(packet.ts_ms, 1000)
            handle.write(struct.pack("<IIII", seconds, millis * 1000, len(frame), wire))
            handle.write(frame)
            count += 1
    return count
