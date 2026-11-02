"""Turn packets into flows, the way a router's flow cache does."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from .model import Flow
from .pcap import Packet

Key = tuple[str, str, int, int, int]


class _Entry:
    __slots__ = ("bytes", "end", "flags", "packets", "start")

    def __init__(self, packet: Packet) -> None:
        self.start = self.end = packet.ts_ms
        self.bytes = packet.length
        self.packets = 1
        self.flags = packet.tcp_flags


class FlowTable:
    """Aggregates packets into unidirectional flows.

    A flow ends when it has been idle for `idle_ms`, or when it has been running for
    `active_ms` (long transfers are split, so they show up while they happen). The table
    is capped at `max_flows`; beyond that the oldest entries are exported early, so a
    port-scan capture cannot exhaust memory.
    """

    def __init__(
        self,
        idle_ms: int = 15_000,
        active_ms: int = 60_000,
        max_flows: int = 200_000,
        source: str = "pcap",
        exporter: str = "",
    ) -> None:
        self.idle_ms = idle_ms
        self.active_ms = active_ms
        self.max_flows = max_flows
        self.source = source
        self.exporter = exporter
        self._entries: dict[Key, _Entry] = {}
        self._last_expiry = 0

    def __len__(self) -> int:
        return len(self._entries)

    def _flow(self, key: Key, entry: _Entry) -> Flow:
        return Flow(
            entry.start, entry.end, key[0], key[1], key[2], key[3], key[4],
            entry.bytes, entry.packets, entry.flags, self.source, self.exporter,
        )  # fmt: skip

    def add(self, packet: Packet) -> Iterator[Flow]:
        """Add a packet; yield any flows that finished because of it."""
        key = (packet.src, packet.dst, packet.sport, packet.dport, packet.proto)
        entry = self._entries.get(key)
        if entry is not None:
            if (
                packet.ts_ms - entry.end > self.idle_ms
                or packet.ts_ms - entry.start > self.active_ms
            ):
                del self._entries[key]
                yield self._flow(key, entry)
                entry = None
        if entry is None:
            self._entries[key] = _Entry(packet)
        else:
            entry.end = max(entry.end, packet.ts_ms)
            entry.start = min(entry.start, packet.ts_ms)
            entry.bytes += packet.length
            entry.packets += 1
            entry.flags |= packet.tcp_flags
        # Housekeeping once per simulated second keeps the cost per packet constant.
        if packet.ts_ms - self._last_expiry >= 1_000:
            self._last_expiry = packet.ts_ms
            yield from self.expire(packet.ts_ms)
        if len(self._entries) > self.max_flows:
            yield from self._evict(len(self._entries) - self.max_flows)

    def expire(self, now_ms: int) -> Iterator[Flow]:
        stale = [
            key
            for key, entry in self._entries.items()
            if now_ms - entry.end > self.idle_ms or now_ms - entry.start > self.active_ms
        ]
        for key in stale:
            yield self._flow(key, self._entries.pop(key))

    def _evict(self, count: int) -> Iterator[Flow]:
        oldest = sorted(self._entries, key=lambda item: self._entries[item].end)[:count]
        for key in oldest:
            yield self._flow(key, self._entries.pop(key))

    def flush(self) -> Iterator[Flow]:
        """Export everything still in the table (end of file or shutdown)."""
        for key in list(self._entries):
            yield self._flow(key, self._entries.pop(key))


def packets_to_flows(
    packets: Iterable[Packet],
    idle_ms: int = 15_000,
    active_ms: int = 60_000,
    max_flows: int = 200_000,
    exporter: str = "",
) -> Iterator[Flow]:
    table = FlowTable(idle_ms, active_ms, max_flows, exporter=exporter)
    for packet in packets:
        yield from table.add(packet)
    yield from table.flush()
