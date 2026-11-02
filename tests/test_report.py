from __future__ import annotations

from flowpipe.report import html_report, human_bytes, text_report

EMPTY = {"summary": {"flows": "0"}}
HOSTILE = "<script>alert(1)</script>"
DATA = {
    "summary": {
        "flows": "2",
        "bytes": "3000",
        "packets": "5",
        "sources": "1",
        "destinations": "1",
        "first": "2026-11-02 07:00:00.000",
        "last": "2026-11-02 07:05:00.000",
    },  # fmt: skip
    "talkers": [{"src_ip": HOSTILE, "bytes": "2000", "flows": "1"}],
    "receivers": [{"dst_ip": "203.0.113.9", "bytes": "1000", "flows": "1"}],
    "protocols": [{"proto_name": "TCP", "bytes": "3000", "flows": "2"}],
    "services": [{"service": HOSTILE, "bytes": "3000", "flows": "2"}],
    "external": [],
    "minutes": [
        {"minute": "2026-11-02 07:00:00", "bytes": "1000", "flows": "1"},
        {"minute": "2026-11-02 07:01:00", "bytes": "2000", "flows": "1"},
    ],
    "anomalies": [
        {
            "minute": "2026-11-02 07:01:00",
            "kind": "traffic_spike",
            "subject": "x",
            "detail": HOSTILE,
        }
    ],
}


def test_human_bytes():
    assert [human_bytes(v) for v in (0, 999, 1500, 2_500_000, 3e9, 5e12, 7e15)] == [
        "0 B", "999 B", "1.5 KB", "2.5 MB", "3.0 GB", "5.0 TB", "7000.0 TB",
    ]  # fmt: skip


def test_empty_reports():
    assert "No flows" in text_report(EMPTY)
    assert "No flows" in html_report(EMPTY)
    assert "No flows" in text_report({"summary": {}})


def test_text_report_sections_and_no_data_marker():
    text = text_report(DATA)
    assert (
        "Top senders" in text and "Anomalies" in text and "(no data)" in text
    )  # external is empty


def test_html_report_escapes_everything_it_prints():
    page = html_report(DATA, title=HOSTILE)
    assert "<script>alert" not in page and page.count("&lt;script&gt;") >= 4
    assert "src=" not in page and "http://" not in page and "https://" not in page


def test_html_report_marks_spike_minutes_and_handles_missing_data():
    page = html_report(DATA)
    assert "var(--warn)" in page and "peak" in page
    page = html_report({**DATA, "minutes": [], "talkers": [], "anomalies": []})
    assert "Nothing unusual found." in page and "No data." in page
