"""Load capture files into ClickHouse."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from .anonymise import Anonymiser
from .flows import FlowTable
from .model import Flow
from .pcap import CaptureError, ReadStats, open_capture, read_packets
from .store import Store

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")


@dataclass
class IngestResult:
    name: str
    flows: int = 0
    packets: int = 0
    skipped: int = 0
    errors: int = 0
    truncated: bool = False
    duplicate: bool = False


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def anonymise_flow(flow: Flow, mapper: Anonymiser) -> Flow:
    return Flow(
        flow.start_ms, flow.end_ms, mapper(flow.src), mapper(flow.dst), flow.sport, flow.dport,
        flow.proto, flow.bytes, flow.packets, flow.tcp_flags, flow.source, flow.exporter,
    )  # fmt: skip


def ingest_pcap(
    store: Store,
    path: Path,
    *,
    anonymiser: Anonymiser | None = None,
    batch_size: int = 5000,
    idle_seconds: int = 15,
    active_seconds: int = 60,
    max_flows: int = 200_000,
    force: bool = False,
) -> IngestResult:
    """Read one pcap/pcapng(.gz) file, build flows and insert them in batches.

    A file already loaded (same SHA-256) is skipped unless `force` is set, so running the
    same command twice never doubles the numbers.
    """
    result = IngestResult(path.name)
    digest = file_sha256(path)
    if not force and store.file_seen(digest):
        result.duplicate = True
        return result
    table = FlowTable(idle_seconds * 1000, active_seconds * 1000, max_flows, exporter=path.name)
    stats = ReadStats()
    batch: list[Flow] = []

    def push(flows: Iterator[Flow]) -> None:
        for flow in flows:
            batch.append(anonymise_flow(flow, anonymiser) if anonymiser else flow)
            if len(batch) >= batch_size:
                result.flows += store.insert_flows(batch)
                batch.clear()

    try:
        with open_capture(path) as handle:
            for packet in read_packets(handle, stats):
                push(table.add(packet))
    except (CaptureError, EOFError, OSError) as error:
        raise CaptureError(f"{path.name}: {error}") from None
    push(table.flush())
    if batch:
        result.flows += store.insert_flows(batch)
    result.packets, result.skipped = stats.packets, stats.skipped
    result.errors, result.truncated = stats.errors, stats.truncated_file
    store.record_file(digest, path.name, result.flows, result.packets)
    return result


def is_capture(path: Path) -> bool:
    return path.is_file() and path.name.lower().endswith(CAPTURE_SUFFIXES)


def watch_folder(
    store: Store,
    folder: Path,
    stop: Event,
    interval: float = 10.0,
    settle_seconds: float = 3.0,
    report: Callable[[IngestResult], None] = lambda result: None,
    **options: object,
) -> None:
    """Ingest capture files as they appear (for example tcpdump -G rotated files).

    Files modified in the last few seconds are left alone: they are probably still being
    written. Files are never deleted or moved.
    """
    failed: set[tuple[str, int]] = set()
    while not stop.is_set():
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            entries = []
        for path in entries:
            try:
                if not is_capture(path):
                    continue
                stat = path.stat()
            except OSError:  # removed while we were looking
                continue
            if (
                time.time() - stat.st_mtime < settle_seconds
                or (path.name, stat.st_mtime_ns) in failed
            ):
                continue
            try:
                outcome = ingest_pcap(store, path, **options)  # type: ignore[arg-type]
            except CaptureError:
                failed.add((path.name, stat.st_mtime_ns))
                continue
            if not outcome.duplicate:
                report(outcome)
        stop.wait(interval)
