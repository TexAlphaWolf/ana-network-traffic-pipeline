"""Builders for capture files and packets used across the tests."""

from __future__ import annotations

import struct

from flowpipe.pcap import Packet
from flowpipe.sample import _frame

T0 = 1_793_000_000_000  # an arbitrary fixed instant (ms)


def pkt(offset_ms: int = 0, src="10.0.0.5", dst="203.0.113.9", sport=50000, dport=443,
        proto=6, length=1000, flags=0x10) -> Packet:  # fmt: skip
    return Packet(T0 + offset_ms, src, dst, sport, dport, proto, length, flags)


def classic_pcap(packets, order="<", nanos=False, link=1) -> bytes:
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, link)
    for p in packets:
        frame, wire = _frame(p)
        seconds, millis = divmod(p.ts_ms, 1000)
        fraction = millis * (1_000_000 if nanos else 1_000)
        out += struct.pack(order + "IIII", seconds, fraction, len(frame), wire) + frame
    return out


def _block(kind: int, body: bytes, order="<") -> bytes:
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return (
        struct.pack(order + "II", kind, total)
        + body
        + b"\0" * pad
        + struct.pack(order + "I", total)
    )


def pcapng(packets, order="<", tsresol: int | None = None) -> bytes:
    shb = struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    out = _block(0x0A0D0D0A, shb, order)
    options = b""
    if tsresol is not None:
        options = struct.pack(order + "HHB3x", 9, 1, tsresol) + struct.pack(order + "HH", 0, 0)
    out += _block(1, struct.pack(order + "HHI", 1, 0, 65535) + options, order)
    units = 10 ** (tsresol if tsresol is not None else 6)
    for p in packets:
        frame, wire = _frame(p)
        ticks = p.ts_ms * units // 1000
        body = struct.pack(order + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), wire)
        out += _block(6, body + frame, order)
    return out
