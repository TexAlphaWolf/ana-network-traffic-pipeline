"""Spike and scan detection.

Spikes use a rolling median and MAD (median absolute deviation) per minute: both are
barely moved by the spike itself, so a few abnormal minutes do not hide each other the way
they would with a mean and standard deviation.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .store import Anomaly, Store, time_literal

MAD_TO_SIGMA = 1.4826


@dataclass(frozen=True)
class SpikeSettings:
    window: int = 30  # minutes of history used as baseline
    min_history: int = 8  # minutes needed before judging
    threshold: float = 6.0  # robust z-score
    min_ratio: float = 2.0  # and at least this many times the baseline
    min_bytes: int = 1_000_000  # ignore tiny absolute differences


DEFAULT_SPIKES = SpikeSettings()


def fill_minutes(points: dict[datetime, float]) -> list[tuple[datetime, float]]:
    """Add the missing minutes as zero so quiet periods count as quiet, not as absent."""
    if not points:
        return []
    first, last = min(points), max(points)
    series = []
    moment = first
    while moment <= last:
        series.append((moment, points.get(moment, 0.0)))
        moment += timedelta(minutes=1)
    return series


def find_spikes(
    series: list[tuple[datetime, float]], settings: SpikeSettings = DEFAULT_SPIKES
) -> list[tuple[datetime, float, float, float]]:
    """Return (minute, value, baseline, score) for every abnormal minute."""
    found = []
    for index, (minute, value) in enumerate(series):
        history = [v for _, v in series[max(0, index - settings.window) : index]]
        if len(history) < settings.min_history:
            continue
        median = statistics.median(history)
        mad = statistics.median(abs(v - median) for v in history)
        # Floor on the spread: a perfectly flat history must not give infinite scores.
        spread = max(mad * MAD_TO_SIGMA, median * 0.1, 1.0)
        score = (value - median) / spread
        if score >= settings.threshold and value >= max(
            median * settings.min_ratio, settings.min_bytes
        ):
            found.append((minute, value, median, score))
    return found


def _parse_minute(text: str) -> datetime:
    return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def detect_spikes(
    store: Store,
    since: datetime | None = None,
    until: datetime | None = None,
    settings: SpikeSettings = DEFAULT_SPIKES,
) -> list[Anomaly]:
    from .queries import per_minute

    # Judge the window against the minutes before it: without history there is no baseline.
    history_from = since - timedelta(minutes=settings.window) if since is not None else None
    rows = per_minute(store, history_from, until)
    points = {_parse_minute(r["minute"]): float(r["bytes"]) for r in rows}
    result = []
    for minute, value, baseline, score in find_spikes(fill_minutes(points), settings):
        if since is not None and minute < since:
            continue
        culprit = store.backend.query(
            f"""
            SELECT src_ip, dst_ip, sum(bytes) AS bytes
            FROM {store.database}.flows
            WHERE toStartOfMinute(start) = {time_literal(minute)}
            GROUP BY src_ip, dst_ip ORDER BY bytes DESC LIMIT 1
            """
        )
        detail = ""
        subject = "total"
        if culprit:
            subject = str(culprit[0]["src_ip"])
            detail = (
                f"{culprit[0]['src_ip']} -> {culprit[0]['dst_ip']}: "
                f"{int(culprit[0]['bytes']) / 1e6:.1f} MB in the minute"
            )
        result.append(Anomaly(minute, "traffic_spike", subject, value, baseline, score, detail))
    return result


def detect_scans(
    store: Store,
    since: datetime | None = None,
    until: datetime | None = None,
    threshold: int = 100,
) -> list[Anomaly]:
    """One source touching many (host, port) pairs within a minute looks like a scan."""
    clauses = ["proto IN (6, 17)"]
    if since is not None:
        clauses.append(f"start >= {time_literal(since)}")
    if until is not None:
        clauses.append(f"start < {time_literal(until)}")
    rows = store.backend.query(
        f"""
        SELECT toString(toStartOfMinute(start)) AS minute, src_ip,
               uniqExact(dst_ip, dport) AS targets, uniqExact(dst_ip) AS hosts, count() AS flows
        FROM {store.database}.flows
        WHERE {" AND ".join(clauses)}
        GROUP BY minute, src_ip
        HAVING targets >= {int(threshold)}
        ORDER BY minute, targets DESC
        """
    )
    return [
        Anomaly(
            _parse_minute(row["minute"]),
            "port_scan",
            str(row["src_ip"]),
            float(row["targets"]),
            float(threshold),
            float(row["targets"]) / threshold,
            f"{row['src_ip']} touched {row['targets']} host/port pairs on {row['hosts']} host(s)",
        )
        for row in rows
    ]


def detect(
    store: Store,
    since: datetime | None = None,
    until: datetime | None = None,
    settings: SpikeSettings = DEFAULT_SPIKES,
    scan_threshold: int = 100,
) -> list[Anomaly]:
    """Run every detector and store what was found. Re-running replaces the same rows."""
    found = detect_spikes(store, since, until, settings) + detect_scans(
        store, since, until, scan_threshold
    )
    store.insert_anomalies(found)
    return found


__all__ = ["Anomaly", "SpikeSettings", "detect", "detect_scans", "detect_spikes"]
