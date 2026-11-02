"""Queries and detectors on a real ClickHouse engine (chdb, or a server in CI)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flowpipe import anomaly, queries
from flowpipe.anomaly import SpikeSettings, fill_minutes, find_spikes
from flowpipe.flows import packets_to_flows
from flowpipe.sample import (
    EXFIL,
    LAPTOP,
    SCANNER,
    STREAMING,
    TV,
    generate_packets,
)

START = datetime(2026, 11, 2, 7, 0, tzinfo=UTC)
START_MS = int(START.timestamp() * 1000)

pytestmark = pytest.mark.clickhouse


@pytest.fixture
def loaded(store):
    flows = list(packets_to_flows(generate_packets(START_MS, 30, seed=7)))
    store.insert_flows(flows)
    return store


def test_summary(loaded):
    s = queries.summary(loaded)
    assert int(s["flows"]) == 2146 and int(s["packets"]) == 57459
    assert s["first"].startswith("2026-11-02 07:00") and int(s["sources"]) == 19


def test_time_window_filters(loaded):
    s = queries.summary(loaded, START, START + timedelta(minutes=5))
    assert 0 < int(s["flows"]) < 2146
    assert (
        queries.summary(loaded, START + timedelta(hours=5))["flows"] == "0"
        or int(queries.summary(loaded, START + timedelta(hours=5))["flows"]) == 0
    )


def test_top_talkers_modes(loaded):
    senders = queries.top_talkers(loaded, "src", 3)
    assert senders[0]["src_ip"] == LAPTOP and len(senders) == 3
    assert senders[1]["src_ip"] == STREAMING
    receivers = queries.top_talkers(loaded, "dst", 1)
    assert receivers[0]["dst_ip"] == EXFIL
    pair = queries.top_talkers(loaded, "pair", 1)[0]
    assert (pair["src_ip"], pair["dst_ip"]) == (LAPTOP, EXFIL)
    with pytest.raises(ValueError):
        queries.top_talkers(loaded, "bogus")


def test_limit_is_clamped(loaded):
    assert len(queries.top_talkers(loaded, "src", 0)) == 1
    assert len(queries.top_talkers(loaded, "src", 10_000)) <= 1000


def test_protocols_services_and_external(loaded):
    assert {p["proto_name"] for p in queries.protocols(loaded)} == {"TCP", "UDP"}
    services = [s["service"] for s in queries.services(loaded, 3)]
    assert services[0] == "https" and "ssh" in services
    external = queries.external_destinations(loaded, 2)
    assert external[0]["dst_ip"] == EXFIL and abs(int(external[0]["bytes"]) - 270_000_000) < 1000


def test_rollup_matches_the_raw_table(loaded):
    raw = int(queries.summary(loaded)["bytes"])
    rolled = sum(int(m["bytes"]) for m in queries.per_minute(loaded))
    assert raw == rolled


def test_detectors_find_exactly_the_two_incidents(loaded):
    found = anomaly.detect(loaded)
    spikes = [a for a in found if a.kind == "traffic_spike"]
    scans = [a for a in found if a.kind == "port_scan"]
    assert [a.minute.strftime("%H:%M") for a in spikes] == ["07:18", "07:19", "07:20"]
    assert all(a.subject == LAPTOP and EXFIL in a.detail for a in spikes)
    assert len(scans) == 1 and scans[0].subject == SCANNER and scans[0].value == 400


def test_detect_is_idempotent(loaded):
    anomaly.detect(loaded)
    anomaly.detect(loaded)
    stored = queries.anomalies(loaded)
    assert len(stored) == 4


def test_quiet_traffic_has_no_anomalies(store):
    flows = list(packets_to_flows(generate_packets(START_MS, 30, seed=7)))
    quiet = [f for f in flows if f.dst != EXFIL and f.src != SCANNER and f.dst != SCANNER]
    store.insert_flows(quiet)
    assert anomaly.detect(store) == []


def test_scan_threshold_is_respected(loaded):
    assert anomaly.detect_scans(loaded, threshold=500) == []
    assert len(anomaly.detect_scans(loaded, threshold=100)) == 1


def test_file_bookkeeping(store):
    assert not store.file_seen("abc")
    store.record_file("abc", "x.pcap", 3, 9)
    assert store.file_seen("abc")


# --- the maths, without a database ----------------------------------------------------


def series(values, start=START):
    return [(start + timedelta(minutes=i), float(v)) for i, v in enumerate(values)]


def test_flat_traffic_never_alerts():
    assert find_spikes(series([5_000_000] * 60)) == []


def test_a_real_spike_is_found_and_scores_high():
    values = [5_000_000] * 20 + [60_000_000] + [5_000_000] * 5
    found = find_spikes(series(values))
    assert [m for m, *_ in found] == [START + timedelta(minutes=20)]
    assert found[0][3] > 20


def test_a_spike_does_not_hide_the_next_one():
    values = [5_000_000] * 15 + [60_000_000, 60_000_000, 60_000_000] + [5_000_000] * 3
    assert len(find_spikes(series(values))) == 3  # median/MAD are robust to a short burst


def test_not_enough_history_means_no_verdict():
    assert find_spikes(series([1, 1, 1, 900_000_000])) == []


def test_small_absolute_changes_are_ignored():
    values = [1000] * 20 + [50_000]  # 50x, but only 50 KB
    assert find_spikes(series(values)) == []


def test_gradual_growth_is_not_a_spike():
    values = [5_000_000 + i * 150_000 for i in range(60)]
    assert find_spikes(series(values)) == []


def test_ratio_and_threshold_settings():
    values = [5_000_000] * 20 + [11_000_000]
    assert find_spikes(series(values), SpikeSettings(min_ratio=3.0)) == []
    assert len(find_spikes(series(values), SpikeSettings(min_ratio=2.0, threshold=3.0))) == 1


def test_fill_minutes_adds_zeros():
    points = {START: 5.0, START + timedelta(minutes=3): 7.0}
    assert [v for _, v in fill_minutes(points)] == [5.0, 0.0, 0.0, 7.0]
    assert fill_minutes({}) == []


def test_ttv_constants():
    assert TV == "10.20.0.30"
