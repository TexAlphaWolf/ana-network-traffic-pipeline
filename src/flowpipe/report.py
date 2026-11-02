"""Text and HTML reports from the same queries Grafana uses."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

from . import queries
from .store import Store


def human_bytes(value: float) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{size:.1f} TB"  # pragma: no cover


def collect(
    store: Store, since: datetime | None, until: datetime | None, limit: int = 10
) -> dict[str, Any]:
    return {
        "summary": queries.summary(store, since, until),
        "talkers": queries.top_talkers(store, "src", limit, since, until),
        "receivers": queries.top_talkers(store, "dst", limit, since, until),
        "protocols": queries.protocols(store, since, until),
        "services": queries.services(store, limit, since, until),
        "external": queries.external_destinations(store, limit, since, until),
        "minutes": queries.per_minute(store, since, until),
        "anomalies": queries.anomalies(store, since, until),
    }


def _table(title: str, rows: list[dict[str, Any]], columns: list[str]) -> list[str]:
    lines = [title, "-" * len(title)]
    if not rows:
        return [*lines, "(no data)", ""]
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column, "")
            cells.append(human_bytes(float(value)) if column == "bytes" else str(value))
        lines.append("  " + "   ".join(cells))
    return [*lines, ""]


def text_report(data: dict[str, Any]) -> str:
    s = data["summary"]
    lines = ["flowpipe report", "===============", ""]
    if not s or not int(s.get("flows", 0)):
        return "\n".join([*lines, "No flows in this period.", ""])
    lines += [
        f"Period: {s['first']} to {s['last']} (UTC)",
        f"Flows: {int(s['flows']):,}   Traffic: {human_bytes(float(s['bytes']))}"
        f"   Packets: {int(s['packets']):,}",
        f"Distinct sources: {s['sources']}   Distinct destinations: {s['destinations']}",
        "",
    ]
    lines += _table("Top senders", data["talkers"], ["src_ip", "bytes", "flows"])
    lines += _table("Top receivers", data["receivers"], ["dst_ip", "bytes", "flows"])
    lines += _table("Protocols", data["protocols"], ["proto_name", "bytes", "flows"])
    lines += _table("Services", data["services"], ["service", "bytes", "flows"])
    lines += _table("Outbound to the internet", data["external"], ["dst_ip", "bytes", "clients"])
    lines += _table("Anomalies", data["anomalies"], ["minute", "kind", "subject", "detail"])
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#667085;--line:#e4e7ec;--accent:#2f6fed;--warn:#d92d20}
@media (prefers-color-scheme: dark){:root{--bg:#0f141b;--card:#171e28;--ink:#e6e9ef;--mute:#9aa4b2;--line:#2a3340;--accent:#6ea0ff;--warn:#ff6b60}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--mute);margin-bottom:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.stat b{display:block;font-size:22px}.stat span{color:var(--mute);font-size:13px}
h2{font-size:15px;margin:0 0 10px}.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:5px 6px;text-align:left;border-bottom:1px solid var(--line)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.bar{height:6px;background:var(--accent);border-radius:3px;opacity:.85}
.warn{color:var(--warn);font-weight:600}svg{width:100%;height:auto;display:block}
"""


def _bars(rows: list[dict[str, Any]], label: str) -> str:
    if not rows:
        return "<p class='sub'>No data.</p>"
    top = max(float(r["bytes"]) for r in rows) or 1.0
    body = []
    for row in rows:
        width = max(1.0, float(row["bytes"]) / top * 100)
        body.append(
            f"<tr><td>{escape(str(row[label]))}"
            f"<div class='bar' style='width:{width:.0f}%'></div></td>"
            f"<td class='n'>{escape(human_bytes(float(row['bytes'])))}</td></tr>"
        )
    return f"<table>{''.join(body)}</table>"


def _timeline(minutes: list[dict[str, Any]], flagged: set[str]) -> str:
    if not minutes:
        return "<p class='sub'>No data.</p>"
    width, height, pad = 1000, 220, 30
    top = max(float(m["bytes"]) for m in minutes) or 1.0
    step = (width - pad) / len(minutes)
    bars = []
    for index, minute in enumerate(minutes):
        value = float(minute["bytes"])
        bar_h = value / top * (height - pad - 10)
        x = pad + index * step
        colour = "var(--warn)" if minute["minute"] in flagged else "var(--accent)"
        bars.append(
            f"<rect x='{x:.1f}' y='{height - pad - bar_h:.1f}' width='{max(step - 1, 1):.1f}' "
            f"height='{bar_h:.1f}' fill='{colour}'><title>{escape(minute['minute'])}: "
            f"{escape(human_bytes(value))}</title></rect>"
        )
    first, last = escape(minutes[0]["minute"][11:16]), escape(minutes[-1]["minute"][11:16])
    return (
        f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='Traffic per minute'>"
        f"<line x1='{pad}' y1='{height - pad}' x2='{width}' y2='{height - pad}' stroke='var(--line)'/>"
        f"{''.join(bars)}"
        f"<text x='{pad}' y='{height - 8}' fill='var(--mute)' font-size='13'>{first} UTC</text>"
        f"<text x='{width}' y='{height - 8}' fill='var(--mute)' font-size='13' text-anchor='end'>{last}</text>"
        f"<text x='{pad}' y='14' fill='var(--mute)' font-size='13'>peak {escape(human_bytes(top))}/min</text>"
        "</svg>"
    )


def html_report(data: dict[str, Any], title: str = "Network traffic report") -> str:
    s = data["summary"]
    if not s or not int(s.get("flows", 0)):
        body = "<p class='sub'>No flows in this period.</p>"
    else:
        flagged = {a["minute"] for a in data["anomalies"] if a["kind"] == "traffic_spike"}
        stats = [
            (f"{int(s['flows']):,}", "flows"),
            (human_bytes(float(s["bytes"])), "traffic"),
            (str(s["sources"]), "sources"),
            (str(s["destinations"]), "destinations"),
            (str(len(data["anomalies"])), "anomalies"),
        ]
        cards = "".join(
            f"<div class='card stat'><b>{escape(v)}</b><span>{escape(k)}</span></div>"
            for v, k in stats
        )
        rows = (
            "".join(
                f"<tr><td>{escape(a['minute'][11:16])}</td><td class='warn'>{escape(a['kind'])}</td>"
                f"<td>{escape(a['detail'] or a['subject'])}</td></tr>"
                for a in data["anomalies"]
            )
            or "<tr><td>Nothing unusual found.</td></tr>"
        )
        body = (
            f"<p class='sub'>{escape(str(s['first']))} to {escape(str(s['last']))} (UTC)</p>"
            f"<div class='grid'>{cards}</div>"
            f"<div class='card'><h2>Traffic per minute (red = spike)</h2>"
            f"{_timeline(data['minutes'], flagged)}</div><div style='height:12px'></div>"
            "<div class='cols'>"
            f"<div class='card'><h2>Top senders</h2>{_bars(data['talkers'], 'src_ip')}</div>"
            f"<div class='card'><h2>Top receivers</h2>{_bars(data['receivers'], 'dst_ip')}</div>"
            f"<div class='card'><h2>Services</h2>{_bars(data['services'], 'service')}</div>"
            f"<div class='card'><h2>Outbound to the internet</h2>"
            f"{_bars(data['external'], 'dst_ip')}</div></div>"
            f"<div class='card'><h2>Anomalies</h2><table>{rows}</table></div>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{escape(title)}</title><style>{CSS}</style></head><body><main>"
        f"<h1>{escape(title)}</h1>{body}</main></body></html>"
    )
