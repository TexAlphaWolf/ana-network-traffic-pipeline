"""The dashboard is data: check it is valid and that every panel query really runs."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from flowpipe.flows import packets_to_flows
from flowpipe.sample import EXFIL, LAPTOP, generate_packets

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = json.loads((ROOT / "grafana/dashboards/flowpipe-overview.json").read_text())
START = datetime(2026, 11, 2, 7, 0, tzinfo=UTC)
FROM, TO = int(START.timestamp()), int(START.timestamp()) + 3600

QUERIES = [
    (panel["title"], target["rawSql"])
    for panel in DASHBOARD["panels"]
    for target in panel["targets"]
]


def expand(sql: str, database: str) -> str:
    """What the Grafana ClickHouse plugin does with its macros."""
    sql = re.sub(
        r"\$__timeFilter\((\w+)\)",
        rf"\1 >= toDateTime({FROM}) AND \1 <= toDateTime({TO})",
        sql,
    )
    sql = sql.replace("$__interval_s", "60")
    return sql.replace("flowpipe.", f"{database}.")


def test_dashboard_structure():
    assert DASHBOARD["uid"] == "flowpipe-overview" and len(DASHBOARD["panels"]) == 10
    ids = [p["id"] for p in DASHBOARD["panels"]]
    assert len(set(ids)) == len(ids)
    for panel in DASHBOARD["panels"]:
        grid = panel["gridPos"]
        assert 0 <= grid["x"] and grid["x"] + grid["w"] <= 24 and grid["h"] > 0
        assert panel["datasource"]["uid"] == "flowpipe-clickhouse"


def test_dashboard_file_is_what_the_generator_produces():
    import importlib.util

    spec = importlib.util.spec_from_file_location("build", ROOT / "tools/build_dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert json.loads(json.dumps(module.DASHBOARD)) == DASHBOARD


def test_provisioning_files_match_the_dashboard():
    text = (ROOT / "grafana/provisioning/datasources/clickhouse.yml").read_text()
    assert "uid: flowpipe-clickhouse" in text and "${GRAFANA_CLICKHOUSE_PASSWORD}" in text
    passwords = [line.strip() for line in text.splitlines() if "password:" in line]
    assert passwords == ["password: ${GRAFANA_CLICKHOUSE_PASSWORD}"]  # never a literal secret


@pytest.mark.clickhouse
@pytest.mark.parametrize("title, sql", QUERIES, ids=[q[0] for q in QUERIES])
def test_every_panel_query_runs(store, title, sql):
    flows = list(packets_to_flows(generate_packets(int(START.timestamp() * 1000), 30, seed=7)))
    store.insert_flows(flows)
    from flowpipe import anomaly

    anomaly.detect(store)
    rows = store.backend.query(expand(sql, store.database))
    assert rows, f"{title} returned nothing"
    if title == "Top senders":
        assert rows[0]["host"] == LAPTOP
    if title == "Outbound to the internet":
        assert rows[0]["destination"] == EXFIL
    if title == "Anomalies (traffic spikes and port scans)":
        assert {r["kind"] for r in rows} == {"traffic_spike", "port_scan"}
    if title == "Anomalies":
        assert int(rows[0]["anomalies"]) == 4
