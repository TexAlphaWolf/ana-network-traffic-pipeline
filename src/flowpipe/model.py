"""The one record type every source is turned into."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


def from_ms(milliseconds: int) -> datetime:
    """UTC datetime from epoch milliseconds."""
    return datetime.fromtimestamp(milliseconds / 1000, tz=UTC)


def to_ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


MIN_TIME_MS = 946_684_800_000  # 2000-01-01: anything older is a broken clock or corrupt data
MAX_TIME_MS = 4_102_444_800_000  # 2100-01-01
MAX_COUNTER = 2**62  # far beyond any real counter, safely inside ClickHouse's UInt64


@dataclass(frozen=True, slots=True)
class Flow:
    """One unidirectional flow: all packets of a 5-tuple seen between start and end."""

    start_ms: int
    end_ms: int
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    bytes: int
    packets: int
    tcp_flags: int = 0
    source: str = "pcap"  # "pcap" or "netflow"
    exporter: str = ""  # which router/file the flow came from

    def plausible(self) -> bool:
        """False for flows ClickHouse would refuse or that would be deleted at once by the TTL."""
        return (
            MIN_TIME_MS <= self.start_ms <= MAX_TIME_MS
            and MIN_TIME_MS <= self.end_ms <= MAX_TIME_MS
        )
