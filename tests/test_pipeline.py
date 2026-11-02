"""Ingest, watcher, collector (over a real UDP socket) and CLI."""

from __future__ import annotations

import os
import socket
import threading
import time
from datetime import UTC, datetime

import pytest
from helpers import classic_pcap, pkt

from flowpipe import cli, queries
from flowpipe.anonymise import Anonymiser
from flowpipe.collector import MAX_PENDING, Collector
from flowpipe.exporters import encode_ipfix, encode_v5, send_udp
from flowpipe.ingest import ingest_pcap, is_capture, watch_folder
from flowpipe.model import Flow
from flowpipe.pcap import CaptureError
from flowpipe.sample import generate_packets, write_pcap
from flowpipe.store import StoreError

pytestmark = pytest.mark.clickhouse
START_MS = int(datetime(2026, 11, 2, 7, 0, tzinfo=UTC).timestamp() * 1000)
NOW = START_MS + 3_600_000


def sample_file(tmp_path, minutes=6, name="s.pcap"):
    path = tmp_path / name
    write_pcap(path, generate_packets(START_MS, minutes, seed=2))
    return path


def count(store):
    return int(queries.summary(store)["flows"])


def test_ingest_is_idempotent(store, tmp_path):
    path = sample_file(tmp_path)
    first = ingest_pcap(store, path)
    assert first.flows > 100 and not first.duplicate and first.packets > 1000
    stored = count(store)
    assert stored == first.flows
    again = ingest_pcap(store, path)
    assert again.duplicate and count(store) == stored
    forced = ingest_pcap(store, path, force=True)
    assert not forced.duplicate and count(store) == stored * 2


def test_ingest_in_small_batches_gives_the_same_result(store, tmp_path):
    path = sample_file(tmp_path)
    result = ingest_pcap(store, path, batch_size=7)
    assert count(store) == result.flows


def test_ingest_anonymises_before_storing(store, tmp_path):
    path = sample_file(tmp_path)
    ingest_pcap(store, path, anonymiser=Anonymiser("secret-key-1"))
    rows = store.backend.query(f"SELECT DISTINCT src_ip FROM {store.database}.flows")
    addresses = {r["src_ip"] for r in rows}
    assert addresses and not any(a.startswith("203.0.113.") or a == "10.20.0.10" for a in addresses)
    external = queries.external_destinations(store, 3)
    assert external  # the internal/external split survives the pseudonyms


def test_ingest_reports_truncated_files(store, tmp_path):
    path = tmp_path / "cut.pcap"
    path.write_bytes(classic_pcap([pkt(i * 10) for i in range(20)])[:-7])
    result = ingest_pcap(store, path)
    assert result.truncated and result.packets == 19


def test_ingest_rejects_non_captures(store, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture at all")
    with pytest.raises(CaptureError, match="bad.pcap"):
        ingest_pcap(store, bad)
    assert not store.file_seen("x")


def test_is_capture(tmp_path):
    for name, expected in [("a.pcap", True), ("a.PCAPNG", True), ("a.pcap.gz", True),
                           ("a.txt", False), ("a.pcap.bak", False)]:  # fmt: skip
        (tmp_path / name).write_bytes(b"x")
        assert is_capture(tmp_path / name) is expected
    assert not is_capture(tmp_path)


def test_watch_folder_loads_new_files_and_skips_fresh_or_broken_ones(store, tmp_path):
    good = sample_file(tmp_path, 3, "good.pcap")
    (tmp_path / "broken.pcap").write_bytes(b"garbage garbage")
    (tmp_path / "notes.txt").write_text("hello")
    fresh = sample_file(tmp_path, 3, "fresh.pcap")
    old = time.time() - 60
    for path in (good, tmp_path / "broken.pcap"):
        os.utime(path, (old, old))
    seen = []
    stop = threading.Event()
    thread = threading.Thread(
        target=watch_folder,
        args=(store, tmp_path, stop, 0.05, 5.0, seen.append),
        daemon=True,
    )
    thread.start()
    deadline = time.time() + 15
    while not seen and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)  # several more passes: nothing should be loaded twice
    stop.set()
    thread.join(5)
    assert [r.name for r in seen] == ["good.pcap"]
    assert fresh.exists() and good.exists()  # files are never touched


# --- collector -------------------------------------------------------------------------

FLOWS = [Flow(NOW - 3000, NOW - 2000, "10.0.0.5", "203.0.113.9", 51000, 443, 6, 1500, 3)]


class BrokenStore:
    def __init__(self):
        self.calls = 0

    def insert_flows(self, flows):
        self.calls += 1
        raise StoreError("down")


def test_collector_handles_and_stores(store):
    collector = Collector(store, allowed=("192.0.2.0/24",))
    template, data = encode_ipfix(FLOWS * 3, NOW, per_packet=1)[:2]
    assert collector.handle(template, "192.0.2.1") == 1
    assert collector.handle(data, "192.0.2.1") == 1
    assert collector.handle(data, "198.51.100.9") == 0  # not an allowed exporter
    assert collector.handle(b"junk-junk-junk", "192.0.2.1") == 0
    assert (collector.received, collector.rejected, collector.malformed) == (3, 1, 1)
    assert collector.flush(force=True) == 2
    assert count(store) == 2 and collector.stored == 2


def test_collector_allowlist_rules():
    collector = Collector(None, allowed=("192.0.2.0/24", "2001:db8::/32"))  # type: ignore[arg-type]
    assert collector.permitted("192.0.2.77") and collector.permitted("2001:db8::1")
    assert collector.permitted("::ffff:192.0.2.5")
    assert not collector.permitted("192.0.3.1") and not collector.permitted("nonsense")
    assert not collector.permitted("2001:db9::1")
    assert Collector(None).permitted("8.8.8.8")  # type: ignore[arg-type]


def test_collector_anonymises():
    collector = Collector(None, anonymiser=Anonymiser("secret-key-1"))  # type: ignore[arg-type]
    collector.handle(encode_v5(FLOWS, NOW)[0], "192.0.2.1")
    assert collector.pending[0].src != "10.0.0.5" and collector.pending[0].src.startswith("10.")


def test_collector_keeps_flows_while_the_database_is_down():
    broken = BrokenStore()
    collector = Collector(broken, flush_seconds=0.0)  # type: ignore[arg-type]
    collector.handle(encode_v5(FLOWS, NOW)[0], "192.0.2.1")
    assert collector.flush(force=True) == 0 and len(collector.pending) == 1
    assert broken.calls == 1 and collector.stored == 0


def test_collector_memory_is_bounded():
    collector = Collector(None)  # type: ignore[arg-type]
    collector.pending = [FLOWS[0]] * (MAX_PENDING + 5)
    collector.handle(encode_v5(FLOWS, NOW)[0], "192.0.2.1")
    assert len(collector.pending) == MAX_PENDING and collector.dropped == 6


def test_collector_over_udp(store):
    collector = Collector(store, flush_seconds=0.2)
    stop, ready = threading.Event(), threading.Event()
    thread = threading.Thread(
        target=collector.serve, args=("127.0.0.1", 0, stop, ready), daemon=True
    )
    thread.start()
    assert ready.wait(5)
    flows = [Flow(NOW - 3000, NOW - 2000, "10.0.0.5", "203.0.113.9", 1000 + i, 443, 6, 100, 1)
             for i in range(50)]  # fmt: skip
    send_udp(encode_ipfix(flows, NOW), "127.0.0.1", collector.bound_port)
    send_udp(encode_v5(flows, NOW), "127.0.0.1", collector.bound_port)
    deadline = time.time() + 10
    while collector.stored < 100 and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    thread.join(5)
    assert count(store) == 100


def test_collector_can_listen_on_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback not available")
    collector = Collector(None)  # type: ignore[arg-type]
    stop, ready = threading.Event(), threading.Event()
    thread = threading.Thread(target=collector.serve, args=("::1", 0, stop, ready), daemon=True)
    thread.start()
    try:
        assert ready.wait(5)
    finally:
        stop.set()
        thread.join(5)


# --- command line ----------------------------------------------------------------------


@pytest.fixture
def run(store, monkeypatch, capsys):
    monkeypatch.setattr(cli, "make_store", lambda settings: store)
    monkeypatch.setattr(cli, "load_env_file", lambda *a, **k: False)
    for name in list(os.environ):
        if name.startswith("FLOWPIPE_"):
            monkeypatch.delenv(name)

    def call(*args):
        code = cli.main(list(args))
        out = capsys.readouterr()
        return code, out.out, out.err

    return call


def test_cli_end_to_end(run, tmp_path):
    pcap = tmp_path / "office.pcap"
    code, out, _ = run(
        "sample", "pcap", str(pcap), "--minutes", "30", "--start", "2026-11-02T07:00"
    )
    assert code == 0 and "wrote 57,459 packets" in out
    code, out, _ = run("init-db")
    assert code == 0 and "ready" in out
    code, out, _ = run("ingest", str(pcap))
    assert code == 0 and "2,146 flows" in out
    code, out, _ = run("ingest", str(pcap))
    assert "already loaded" in out
    code, out, _ = run("status")
    assert "flows: 2146" in out
    code, out, _ = run("anomalies")
    assert "4 anomalies found" in out and "port_scan" in out and "traffic_spike" in out
    code, out, _ = run(
        "anomalies", "--no-save", "--since", "2026-11-02T07:15", "--until", "2026-11-02T07:25"
    )
    assert "3 anomalies found" in out
    code, out, _ = run("top", "--by", "pair", "--limit", "2")
    assert "10.20.0.10 -> 203.0.113.200" in out
    code, out, _ = run(
        "top", "--by", "src", "--since", "2026-11-02T07:00", "--until", "2026-11-02T07:05"
    )
    assert "10.20.0.10" in out
    code, out, _ = run("report")
    assert "Top senders" in out and "Anomalies" in out and "203.0.113.200" in out
    html = tmp_path / "r.html"
    code, out, _ = run("report", "--format", "html", "-o", str(html))
    assert code == 0 and html.read_text().startswith("<!doctype html>")
    code, out, _ = run("report", "--since", "2030-01-01T00:00")
    assert "No flows" in out


def test_cli_ingest_errors(run, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a capture")
    code, _, err = run("ingest", str(bad), str(tmp_path / "missing.pcap"))
    assert code == 1 and "bad.pcap" in err and "missing.pcap" in err


def test_cli_sample_send_and_collect_guard(run, monkeypatch):
    sent = []
    monkeypatch.setattr(
        cli,
        "send_udp",
        lambda datagrams, host, port: (sent.append(len(datagrams)), len(datagrams))[1],
    )
    for fmt in ("v5", "v9", "ipfix"):
        code, out, _ = run("sample", "send", "127.0.0.1", "2055", "--format", fmt, "--minutes", "5")
        assert code == 0 and "flows in" in out
    assert len(sent) == 3
    monkeypatch.setenv("FLOWPIPE_LISTEN", "0.0.0.0")
    code, _, err = run("collect")
    assert code == 2 and "FLOWPIPE_ALLOWED_EXPORTERS" in err


def test_cli_config_errors_are_friendly(run, monkeypatch):
    monkeypatch.setenv("FLOWPIPE_PORT", "nope")
    code, _, err = run("status")
    assert code == 1 and "FLOWPIPE_PORT" in err


def test_duration_and_time_parsers():
    import argparse

    assert cli.parse_duration("90m").total_seconds() == 5400
    assert cli.parse_duration("7d").days == 7
    for bad in ("", "5", "h", "5x", "-1h"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli.parse_duration(bad)
    assert cli.parse_time("2026-11-02T08:00").tzinfo is not None
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_time("yesterday")
    since, until = cli._window(
        argparse.Namespace(last=cli.parse_duration("1h"), since=None, until=None)
    )
    assert until - since == cli.parse_duration("1h")


# --- hostile values that are well-formed on the wire ----------------------------------


def test_implausible_timestamps_are_not_sent_to_the_database(store):
    good = FLOWS[0]
    ancient = Flow(0, 1000, "10.0.0.5", "203.0.113.9", 1, 2, 6, 10, 1)
    far_future = Flow(2**50, 2**50, "10.0.0.5", "203.0.113.9", 1, 2, 6, 10, 1)
    assert store.insert_flows([good, ancient, far_future]) == 1
    assert count(store) == 1


def test_huge_counters_are_clamped_not_rejected(store):
    import struct

    from flowpipe.netflow import TemplateCache, parse_datagram

    record = (
        bytes([10, 0, 0, 1]) + bytes([203, 0, 113, 5]) + struct.pack("!QQ", 2**64 - 1, 2**64 - 1)
    )
    tpl = struct.pack("!HH", 300, 4) + b"".join(
        struct.pack("!HH", e, n) for e, n in [(8, 4), (12, 4), (1, 8), (2, 8)]
    )
    body = (
        struct.pack("!HH", 2, 4 + len(tpl))
        + tpl
        + struct.pack("!HH", 300, 4 + len(record))
        + record
    )
    message = struct.pack("!HHIII", 10, 16 + len(body), NOW // 1000, 0, 1) + body
    flows = parse_datagram(message, "r", TemplateCache())
    assert len(flows) == 1 and flows[0].bytes < 2**63
    assert store.insert_flows(flows) == 1


class RejectingStore:
    def __init__(self, retryable):
        self.retryable = retryable
        self.calls = 0

    def insert_flows(self, flows):
        self.calls += 1
        raise StoreError("rejected", retryable=self.retryable)


def test_a_rejected_batch_is_dropped_instead_of_blocking_the_queue():
    collector = Collector(RejectingStore(retryable=False), flush_seconds=0.0)  # type: ignore[arg-type]
    collector.handle(encode_v5(FLOWS, NOW)[0], "192.0.2.1")
    assert collector.flush(force=True) == 0
    assert collector.pending == [] and collector.dropped == 1


def test_a_server_that_is_down_keeps_the_batch():
    collector = Collector(RejectingStore(retryable=True), flush_seconds=0.0)  # type: ignore[arg-type]
    collector.handle(encode_v5(FLOWS, NOW)[0], "192.0.2.1")
    collector.flush(force=True)
    assert len(collector.pending) == 1 and collector.dropped == 0


def test_serve_survives_an_unexpected_error(store, monkeypatch):
    collector = Collector(store, flush_seconds=0.2)
    real = collector.handle
    calls = []

    def flaky(data, address):
        calls.append(data)
        if len(calls) == 1:
            raise RuntimeError("bug")
        return real(data, address)

    monkeypatch.setattr(collector, "handle", flaky)
    stop, ready = threading.Event(), threading.Event()
    thread = threading.Thread(
        target=collector.serve, args=("127.0.0.1", 0, stop, ready), daemon=True
    )
    thread.start()
    assert ready.wait(5)
    send_udp([b"first"], "127.0.0.1", collector.bound_port)
    time.sleep(0.3)
    send_udp(encode_v5(FLOWS, NOW), "127.0.0.1", collector.bound_port)
    deadline = time.time() + 10
    while collector.stored < 1 and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    thread.join(5)
    assert collector.stored == 1 and collector.malformed >= 1


def test_watch_folder_survives_a_missing_folder(store, tmp_path):
    stop = threading.Event()
    thread = threading.Thread(
        target=watch_folder, args=(store, tmp_path / "nope", stop, 0.05), daemon=True
    )
    thread.start()
    time.sleep(0.3)
    stop.set()
    thread.join(5)
    assert not thread.is_alive()
