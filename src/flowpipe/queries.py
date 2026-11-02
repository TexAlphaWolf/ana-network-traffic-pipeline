"""Analytics queries used by the CLI reports. Grafana uses the same SQL in its panels."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .store import Store, time_literal

TALKER_MODES = {"src", "dst", "pair"}


def _where(since: datetime | None, until: datetime | None, column: str = "start") -> str:
    clauses = []
    if since is not None:
        clauses.append(f"{column} >= {time_literal(since)}")
    if until is not None:
        clauses.append(f"{column} < {time_literal(until)}")
    return "WHERE " + " AND ".join(clauses) if clauses else ""


def _limit(value: int) -> int:
    return max(1, min(int(value), 1000))


def summary(
    store: Store, since: datetime | None = None, until: datetime | None = None
) -> dict[str, Any]:
    rows = store.backend.query(
        f"""
        SELECT count() AS flows, sum(bytes) AS bytes, sum(packets) AS packets,
               uniqExact(src_ip) AS sources, uniqExact(dst_ip) AS destinations,
               toString(min(start)) AS first, toString(max(end)) AS last
        FROM {store.database}.flows {_where(since, until)}
        """
    )
    return rows[0] if rows else {}


def top_talkers(
    store: Store,
    mode: str = "src",
    limit: int = 10,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[dict[str, Any]]:
    if mode not in TALKER_MODES:
        raise ValueError(f"mode must be one of {sorted(TALKER_MODES)}")
    keys = {"src": "src_ip", "dst": "dst_ip", "pair": "src_ip, dst_ip"}[mode]
    return store.backend.query(
        f"""
        SELECT {keys}, sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows
        FROM {store.database}.flows {_where(since, until)}
        GROUP BY {keys} ORDER BY bytes DESC LIMIT {_limit(limit)}
        """
    )


def protocols(
    store: Store, since: datetime | None = None, until: datetime | None = None
) -> list[dict[str, Any]]:
    return store.backend.query(
        f"""
        SELECT proto_name, sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows
        FROM {store.database}.flows {_where(since, until)}
        GROUP BY proto_name ORDER BY bytes DESC
        """
    )


def services(
    store: Store, limit: int = 15, since: datetime | None = None, until: datetime | None = None
) -> list[dict[str, Any]]:
    return store.backend.query(
        f"""
        SELECT service, sum(bytes) AS bytes, count() AS flows
        FROM {store.database}.flows {_where(since, until)}
        GROUP BY service ORDER BY bytes DESC LIMIT {_limit(limit)}
        """
    )


def external_destinations(
    store: Store, limit: int = 10, since: datetime | None = None, until: datetime | None = None
) -> list[dict[str, Any]]:
    """Where the internal hosts send data on the internet (outbound bytes)."""
    clauses = _where(since, until)
    extra = "src_internal = 1 AND dst_internal = 0"
    where = f"{clauses} AND {extra}" if clauses else f"WHERE {extra}"
    return store.backend.query(
        f"""
        SELECT dst_ip, sum(bytes) AS bytes, count() AS flows, uniqExact(src_ip) AS clients
        FROM {store.database}.flows {where}
        GROUP BY dst_ip ORDER BY bytes DESC LIMIT {_limit(limit)}
        """
    )


def per_minute(
    store: Store, since: datetime | None = None, until: datetime | None = None
) -> list[dict[str, Any]]:
    """Bytes per minute, from the rollup table (fast even over months of data)."""
    return store.backend.query(
        f"""
        SELECT toString(minute) AS minute, sum(bytes) AS bytes, sum(flows) AS flows
        FROM {store.database}.flows_1m {_where(since, until, "flows_1m.minute")}
        GROUP BY minute ORDER BY minute
        """
    )


def anomalies(
    store: Store, since: datetime | None = None, until: datetime | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    return store.backend.query(
        f"""
        SELECT toString(minute) AS minute, kind, subject, value, baseline, score, detail
        FROM {store.database}.anomalies FINAL {_where(since, until, "anomalies.minute")}
        ORDER BY minute DESC, score DESC LIMIT {_limit(limit)}
        """
    )
