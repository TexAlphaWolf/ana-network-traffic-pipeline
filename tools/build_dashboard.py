"""Generate grafana/dashboards/flowpipe-overview.json (run: python tools/build_dashboard.py)."""

from __future__ import annotations

import json
from pathlib import Path

DS = {"type": "grafana-clickhouse-datasource", "uid": "flowpipe-clickhouse"}
DB = "flowpipe"
OUT = Path(__file__).resolve().parent.parent / "grafana" / "dashboards" / "flowpipe-overview.json"

_next_id = 0


def target(sql: str, kind: str = "table") -> dict:
    return {
        "datasource": DS,
        "editorType": "sql",
        "format": 1 if kind == "table" else 0,
        "queryType": kind,
        "rawSql": " ".join(sql.split()),
        "refId": "A",
    }


def panel(kind: str, title: str, x: int, y: int, w: int, h: int, sql: str, **extra) -> dict:
    global _next_id
    _next_id += 1
    qtype = "timeseries" if kind == "timeseries" else "table"
    base = {
        "id": _next_id,
        "type": kind,
        "title": title,
        "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [target(sql, qtype)],
        "fieldConfig": {"defaults": {}, "overrides": []},
        "options": {},
    }
    for key, value in extra.items():
        base[key] = value
    return base


def stat(title: str, x: int, sql: str, unit: str = "short", color: str = "blue") -> dict:
    return panel(
        "stat", title, x, 0, 6, 4, sql,
        fieldConfig={
            "defaults": {"unit": unit, "color": {"mode": "fixed", "fixedColor": color}},
            "overrides": [],
        },
        options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                 "colorMode": "value", "graphMode": "none", "textMode": "value"},
    )  # fmt: skip


def table(title: str, x: int, y: int, w: int, h: int, sql: str, bytes_cols=("bytes",)) -> dict:
    overrides = [
        {
            "matcher": {"id": "byName", "options": name},
            "properties": [{"id": "unit", "value": "decbytes"}],
        }
        for name in bytes_cols
    ]
    return panel(
        "table", title, x, y, w, h, sql,
        fieldConfig={"defaults": {}, "overrides": overrides},
        options={"showHeader": True, "cellHeight": "sm"},
    )  # fmt: skip


PANELS = [
    stat("Traffic", 0,
         f"SELECT sum(bytes) AS traffic FROM {DB}.flows_1m WHERE $__timeFilter(minute)",
         "decbytes"),
    stat("Flows", 6,
         f"SELECT sum(flows) AS flows FROM {DB}.flows_1m WHERE $__timeFilter(minute)"),
    stat("Internal hosts sending", 12,
         f"SELECT uniqExact(src_ip) AS hosts FROM {DB}.flows "
         f"WHERE $__timeFilter(start) AND src_internal = 1", color="green"),
    stat("Anomalies", 18,
         f"SELECT count() AS anomalies FROM {DB}.anomalies FINAL WHERE $__timeFilter(minute)",
         color="red"),
    panel(
        "timeseries", "Traffic by service (bytes per minute)", 0, 4, 16, 9,
        f"SELECT toStartOfInterval(minute, INTERVAL greatest($__interval_s, 60) SECOND) AS time, "
        f"service, sum(bytes) AS bytes FROM {DB}.flows_1m WHERE $__timeFilter(minute) "
        f"GROUP BY time, service ORDER BY time",
        fieldConfig={"defaults": {"unit": "decbytes", "custom": {
            "drawStyle": "bars", "fillOpacity": 70, "stacking": {"mode": "normal"}}},
            "overrides": []},
        options={"legend": {"displayMode": "table", "placement": "right",
                            "calcs": ["sum"]}, "tooltip": {"mode": "multi"}},
    ),  # fmt: skip
    panel(
        "piechart", "Services share", 16, 4, 8, 9,
        f"SELECT service, sum(bytes) AS bytes FROM {DB}.flows_1m "
        f"WHERE $__timeFilter(minute) GROUP BY service ORDER BY bytes DESC LIMIT 12",
        fieldConfig={"defaults": {"unit": "decbytes"}, "overrides": []},
        options={"pieType": "donut", "legend": {"displayMode": "table", "placement": "right",
                                                "values": ["percent"]},
                 "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True}},
    ),  # fmt: skip
    table("Top senders", 0, 13, 8, 9,
          f"SELECT src_ip AS host, sum(bytes) AS bytes, count() AS flows FROM {DB}.flows "
          f"WHERE $__timeFilter(start) GROUP BY host ORDER BY bytes DESC LIMIT 10"),
    table("Top receivers", 8, 13, 8, 9,
          f"SELECT dst_ip AS host, sum(bytes) AS bytes, count() AS flows FROM {DB}.flows "
          f"WHERE $__timeFilter(start) GROUP BY host ORDER BY bytes DESC LIMIT 10"),
    table("Outbound to the internet", 16, 13, 8, 9,
          f"SELECT dst_ip AS destination, sum(bytes) AS bytes, uniqExact(src_ip) AS clients "
          f"FROM {DB}.flows WHERE $__timeFilter(start) AND src_internal = 1 AND dst_internal = 0 "
          f"GROUP BY destination ORDER BY bytes DESC LIMIT 10"),
    table("Anomalies (traffic spikes and port scans)", 0, 22, 24, 8,
          f"SELECT minute AS time, kind, subject, round(score, 1) AS score, detail "
          f"FROM {DB}.anomalies FINAL WHERE $__timeFilter(minute) ORDER BY time DESC LIMIT 50",
          bytes_cols=()),
]  # fmt: skip

DASHBOARD = {
    "uid": "flowpipe-overview",
    "title": "Network traffic",
    "tags": ["flowpipe", "network"],
    "timezone": "utc",
    "schemaVersion": 39,
    "version": 1,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "editable": True,
    "panels": PANELS,
}

if __name__ == "__main__":
    OUT.write_text(json.dumps(DASHBOARD, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
