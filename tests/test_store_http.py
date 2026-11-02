"""The HTTP client against a tiny fake ClickHouse: headers, errors, redirects, escaping."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from helpers import T0, pkt

from flowpipe.flows import packets_to_flows
from flowpipe.store import ClickHouse, Store, StoreError, flow_row, quote, time_literal


class Fake(BaseHTTPRequestHandler):
    log: list[dict] = []
    mode = "ok"

    def log_message(self, *args):  # silence
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        parsed = urlparse(self.path)
        Fake.log.append(
            {
                "query": parse_qs(parsed.query).get("query", [""])[0],
                "body": body.decode(),
                "user": self.headers.get("X-ClickHouse-User"),
                "key": self.headers.get("X-ClickHouse-Key"),
                "path": self.path,
            }
        )
        if Fake.mode == "error":
            payload = b"Code: 60. DB::Exception: Table x doesn't exist. (UNKNOWN_TABLE)\nstack..."
            self.send_response(404)
        elif Fake.mode == "bad-data":
            payload = b"Code: 117. DB::Exception: Cannot parse input"
            self.send_response(400)
        elif Fake.mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            payload = b""
        else:
            self.send_response(200)
            payload = b'{"n":"1"}\n{"n":"2"}\n'
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def server():
    Fake.log = []
    Fake.mode = "ok"
    httpd = HTTPServer(("127.0.0.1", 0), Fake)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def client(url):
    return ClickHouse(url, "writer", "s3cret", "flowpipe", timeout=5)


def test_credentials_travel_in_headers_not_in_the_url(server):
    client(server).command("SELECT 1")
    entry = Fake.log[0]
    assert entry["user"] == "writer" and entry["key"] == "s3cret"
    assert "s3cret" not in entry["path"] and "writer" not in entry["path"]
    assert entry["body"] == "SELECT 1"


def test_query_parses_json_each_row(server):
    rows = client(server).query("SELECT n FROM t;")
    assert rows == [{"n": "1"}, {"n": "2"}]
    assert Fake.log[0]["body"] == "SELECT n FROM t FORMAT JSONEachRow"


def test_insert_sends_rows_in_the_body(server):
    client(server).insert("flows", [{"a": 1}, {"a": 2}])
    entry = Fake.log[0]
    assert entry["query"] == "INSERT INTO flowpipe.flows FORMAT JSONEachRow"
    assert [json.loads(line) for line in entry["body"].splitlines()] == [{"a": 1}, {"a": 2}]
    client(server).insert("flows", [])  # nothing to send
    assert len(Fake.log) == 1


def test_bad_table_name_is_refused(server):
    with pytest.raises(StoreError):
        client(server).insert("flows; DROP TABLE x", [{"a": 1}])


def test_errors_are_short_and_clean(server):
    Fake.mode = "error"
    with pytest.raises(StoreError) as caught:
        client(server).query("SELECT 1")
    text = str(caught.value)
    assert "404" in text and "UNKNOWN_TABLE" in text and "s3cret" not in text
    assert "stack" not in text  # only the first line


def test_only_data_errors_are_marked_not_retryable(server):
    Fake.mode = "error"  # the fake answers 404
    with pytest.raises(StoreError) as caught:
        client(server).query("SELECT 1")
    assert caught.value.retryable
    Fake.mode = "bad-data"
    with pytest.raises(StoreError) as caught:
        client(server).insert("flows", [{"a": 1}])
    assert not caught.value.retryable


def test_redirects_are_not_followed(server):
    Fake.mode = "redirect"
    with pytest.raises(StoreError):
        client(server).command("SELECT 1")
    assert len(Fake.log) == 1


def test_unreachable_server_message_has_no_credentials():
    with pytest.raises(StoreError) as caught:
        ClickHouse("http://127.0.0.1:1", "u", "pw-123", "flowpipe", timeout=1).command("SELECT 1")
    assert "cannot reach ClickHouse" in str(caught.value) and "pw-123" not in str(caught.value)


@pytest.mark.parametrize(
    "url, database",
    [
        ("ftp://x", "flowpipe"),
        ("localhost:8123", "flowpipe"),
        ("http://x", "a; DROP"),
        ("http://x", ""),
    ],
)
def test_constructor_validates(url, database):
    with pytest.raises(StoreError):
        ClickHouse(url, "u", "p", database)


def test_quote_and_time_literal():
    assert quote("o'brien\\") == "'o\\'brien\\\\'"
    from datetime import UTC, datetime

    assert time_literal(datetime(2026, 11, 2, 8, 30, 5, 123000, tzinfo=UTC)) == (
        "toDateTime64('2026-11-02 08:30:05.123', 3, 'UTC')"
    )


def test_flow_row_labels_and_timestamps():
    flow = next(iter(packets_to_flows([pkt(250, length=1000)])))
    row = flow_row(flow)
    assert row["proto_name"] == "TCP" and row["service"] == "https"
    assert row["src_internal"] == 1 and row["dst_internal"] == 0
    assert row["start"].endswith(".250") and len(row["start"]) == 23
    assert (T0 + 250) // 1000 == int(
        __import__("datetime").datetime.fromisoformat(row["start"][:19] + "+00:00").timestamp()
    )


def test_init_schema_runs_every_statement_with_substitutions():
    class Recorder:
        def __init__(self):
            self.commands = []

        def command(self, sql):
            self.commands.append(sql)

    recorder = Recorder()
    Store(recorder, "mydb").init_schema(30)  # type: ignore[arg-type]
    assert len(recorder.commands) == 6
    assert recorder.commands[0] == "CREATE DATABASE IF NOT EXISTS mydb"
    joined = "\n".join(recorder.commands)
    assert "{database}" not in joined and "{retention_days}" not in joined
    assert "INTERVAL 30 DAY" in joined and "mydb.flows_1m_mv" in joined
    with pytest.raises(StoreError):
        Store(recorder, "mydb").init_schema(0)  # type: ignore[arg-type]
    with pytest.raises(StoreError):
        Store(recorder, "bad name")  # type: ignore[arg-type]
