"""Command line interface."""

from __future__ import annotations

import argparse
import logging
import re
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import __version__
from .anomaly import detect
from .anonymise import Anonymiser
from .collector import Collector
from .config import ConfigError, Settings, load_env_file, load_settings, make_store
from .exporters import encode_ipfix, encode_v5, encode_v9, send_udp
from .flows import packets_to_flows
from .ingest import ingest_pcap, watch_folder
from .pcap import CaptureError
from .report import collect, html_report, text_report
from .sample import generate_packets, write_pcap
from .store import Store, StoreError

DURATION = re.compile(r"^(\d+)([mhd])$")


def parse_duration(text: str) -> timedelta:
    match = DURATION.match(text.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("use a number and m, h or d, for example 90m, 6h or 7d")
    amount, unit = int(match.group(1)), match.group(2)
    return timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: amount})


def parse_time(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError("use an ISO time such as 2026-11-02T08:00") from None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _window(args: argparse.Namespace) -> tuple[datetime | None, datetime | None]:
    since, until = getattr(args, "since", None), getattr(args, "until", None)
    last = getattr(args, "last", None)
    if last is not None:
        until = until or datetime.now(UTC)
        since = until - last
    return since, until


def _add_window(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--last", type=parse_duration, help="only the last N m/h/d, e.g. 6h")
    parser.add_argument("--since", type=parse_time, help="start (UTC, ISO)")
    parser.add_argument("--until", type=parse_time, help="end (UTC, ISO)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flowpipe", description=__doc__)
    parser.add_argument("--version", action="version", version=f"flowpipe {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create the database and tables")
    ingest = sub.add_parser("ingest", help="load pcap/pcapng files")
    ingest.add_argument("files", nargs="+", type=Path)
    ingest.add_argument("--force", action="store_true", help="load again even if already loaded")
    watch = sub.add_parser("watch", help="load capture files as they appear in a folder")
    watch.add_argument("folder", type=Path)
    watch.add_argument("--interval", type=float, default=10.0)
    sub.add_parser("collect", help="receive NetFlow v5/v9/IPFIX over UDP")

    sample = sub.add_parser("sample", help="generate synthetic traffic")
    sample_sub = sample.add_subparsers(dest="what", required=True)
    for name, text in (("pcap", "write a pcap file"), ("send", "send it as NetFlow/IPFIX")):
        item = sample_sub.add_parser(name, help=text)
        item.add_argument("--minutes", type=int, default=30)
        item.add_argument("--seed", type=int, default=7)
        item.add_argument("--start", type=parse_time, help="default: ends now")
        if name == "pcap":
            item.add_argument("output", type=Path)
        else:
            item.add_argument("host")
            item.add_argument("port", type=int)
            item.add_argument("--format", choices=["v5", "v9", "ipfix"], default="ipfix")

    top = sub.add_parser("top", help="top talkers")
    top.add_argument("--by", choices=["src", "dst", "pair"], default="src")
    top.add_argument("--limit", type=int, default=10)
    _add_window(top)
    anomalies = sub.add_parser("anomalies", help="find spikes and scans")
    anomalies.add_argument("--no-save", action="store_true")
    _add_window(anomalies)
    report = sub.add_parser("report", help="summary report")
    report.add_argument("--format", choices=["text", "html"], default="text")
    report.add_argument("-o", "--output", type=Path)
    _add_window(report)
    sub.add_parser("status", help="show what is in the database")
    return parser


def _store(settings: Settings) -> Store:
    return make_store(settings)  # type: ignore[no-any-return]


def _anonymiser(settings: Settings) -> Anonymiser | None:
    return Anonymiser(settings.anonymise_key) if settings.anonymise_key else None


def _cmd_sample(args: argparse.Namespace) -> int:
    start = args.start or (datetime.now(UTC) - timedelta(minutes=args.minutes))
    start_ms = int(start.replace(second=0, microsecond=0).timestamp() * 1000)
    packets = generate_packets(start_ms, args.minutes, args.seed)
    if args.what == "pcap":
        count = write_pcap(args.output, packets)
        print(f"wrote {count:,} packets to {args.output}")
        return 0
    flows = list(packets_to_flows(packets, exporter="sample"))
    export_ms = max(flow.end_ms for flow in flows) + 1000
    if args.format == "v5":
        datagrams = encode_v5(flows, export_ms)
    elif args.format == "v9":
        datagrams = encode_v9(flows, export_ms)
    else:
        datagrams = encode_ipfix(flows, export_ms)
    sent = send_udp(datagrams, args.host, args.port)
    print(
        f"sent {len(flows):,} flows in {sent:,} {args.format} datagrams to {args.host}:{args.port}"
    )
    return 0


def run(args: argparse.Namespace) -> int:
    if args.command == "sample":
        return _cmd_sample(args)
    settings = load_settings()
    store = _store(settings)
    if args.command == "init-db":
        store.init_schema(settings.retention_days)
        print(f"database {settings.database} ready (retention {settings.retention_days} days)")
        return 0
    if args.command == "ingest":
        failed = 0
        for path in args.files:
            try:
                result = ingest_pcap(
                    store, path, anonymiser=_anonymiser(settings), batch_size=settings.batch_size,
                    idle_seconds=settings.idle_seconds, active_seconds=settings.active_seconds,
                    force=args.force,
                )  # fmt: skip
            except (CaptureError, OSError) as error:
                print(f"error: {error}", file=sys.stderr)
                failed += 1
                continue
            if result.duplicate:
                print(f"{path.name}: already loaded (use --force to load again)")
                continue
            note = " (file was truncated)" if result.truncated else ""
            print(
                f"{path.name}: {result.packets:,} packets -> {result.flows:,} flows"
                f", {result.skipped:,} skipped{note}"
            )
        return 1 if failed else 0
    if args.command == "watch":
        stop = threading.Event()
        print(f"watching {args.folder} (Ctrl+C to stop)")
        try:
            watch_folder(
                store, args.folder, stop, args.interval,
                report=lambda r: print(f"{r.name}: {r.packets:,} packets -> {r.flows:,} flows"),
                anonymiser=_anonymiser(settings), batch_size=settings.batch_size,
                idle_seconds=settings.idle_seconds, active_seconds=settings.active_seconds,
            )  # fmt: skip
        except KeyboardInterrupt:
            stop.set()
        return 0
    if args.command == "collect":
        return _cmd_collect(settings, store)
    since, until = _window(args)
    if args.command == "top":
        from . import queries
        from .report import human_bytes

        rows = queries.top_talkers(store, args.by, args.limit, since, until)
        for row in rows:
            keys = " -> ".join(str(row[k]) for k in ("src_ip", "dst_ip") if k in row)
            print(f"{keys:<45} {human_bytes(float(row['bytes'])):>10} {row['flows']:>8} flows")
        return 0
    if args.command == "anomalies":
        found = (
            detect(store, since, until, settings.spikes, settings.scan_threshold)
            if not args.no_save
            else []
        )
        if args.no_save:
            from .anomaly import detect_scans, detect_spikes

            found = detect_spikes(store, since, until, settings.spikes) + detect_scans(
                store, since, until, settings.scan_threshold
            )
        for item in found:
            print(f"{item.minute:%Y-%m-%d %H:%M} {item.kind:<13} {item.detail or item.subject}")
        print(f"{len(found)} anomalies found")
        return 0
    if args.command == "report":
        data = collect(store, since, until)
        text = html_report(data) if args.format == "html" else text_report(data)
        if args.output:
            args.output.write_text(text, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(text)
        return 0
    if args.command == "status":
        from . import queries

        info = queries.summary(store)
        print(
            f"flows: {info.get('flows', 0)}  first: {info.get('first')}  last: {info.get('last')}"
        )
        return 0
    return 2  # pragma: no cover


def _cmd_collect(settings: Settings, store: Store) -> int:
    loopback = settings.listen in {"127.0.0.1", "::1", "localhost"}
    if not settings.allowed_exporters and not loopback and not settings.allow_any_exporter:
        print(
            "error: listening on a network address without FLOWPIPE_ALLOWED_EXPORTERS would "
            "accept data from anyone. Set the router's address, or "
            "FLOWPIPE_ALLOW_ANY_EXPORTER=true.",
            file=sys.stderr,
        )
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    collector = Collector(
        store, settings.allowed_exporters, settings.batch_size, settings.flush_seconds,
        _anonymiser(settings),
    )  # fmt: skip
    stop = threading.Event()
    try:
        collector.serve(settings.listen, settings.port, stop)
    except KeyboardInterrupt:
        stop.set()
    except OSError as error:
        print(
            f"error: cannot listen on {settings.listen}:{settings.port}: {error}", file=sys.stderr
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    load_env_file()
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (ConfigError, StoreError, CaptureError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
