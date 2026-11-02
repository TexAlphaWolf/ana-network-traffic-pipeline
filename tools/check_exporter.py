"""Compare what a real exporter (softflowd) says it exported with what ClickHouse stored.

Usage: check_exporter.py DUMP_FILE PORT

`DUMP_FILE` is the output of `softflowctl dump-flows`; `PORT` is the TCP port of the test
server. Connection settings come from the usual FLOWPIPE_* environment variables. Every flow
softflowd reports for that port must be present in the database with identical byte and
packet counts. Standard library only.
"""

from __future__ import annotations

import base64
import collections
import os
import re
import sys
import urllib.parse
import urllib.request

LINE = re.compile(
    r"ACTIVE seq:\d+ \[[^\]]+\]:(\d+) <> \[[^\]]+\]:(\d+) proto:6 octets>:(\d+) packets>:(\d+)"
)


def expected(path: str, port: int) -> collections.Counter:
    found: collections.Counter = collections.Counter()
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = LINE.search(line)
            if match is None:
                continue
            sport, dport, octets, packets = (int(g) for g in match.groups())
            if port in (sport, dport):
                found[(sport, dport, octets, packets)] += 1
    return found


def stored(port: int) -> collections.Counter:
    url = os.environ.get("FLOWPIPE_CLICKHOUSE_URL", "http://127.0.0.1:8123")
    database = os.environ.get("FLOWPIPE_DATABASE", "flowpipe")
    query = (
        f"SELECT sport, dport, bytes, packets FROM {database}.flows "
        f"WHERE sport = {port} OR dport = {port} FORMAT TSV"
    )
    request = urllib.request.Request(url, data=query.encode(), method="POST")
    user = os.environ.get("FLOWPIPE_CLICKHOUSE_USER", "")
    if user:
        token = f"{user}:{os.environ.get('FLOWPIPE_CLICKHOUSE_PASSWORD', '')}".encode()
        request.add_header("Authorization", "Basic " + base64.b64encode(token).decode())
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode()
    rows: collections.Counter = collections.Counter()
    for line in text.splitlines():
        sport, dport, octets, packets = (int(x) for x in line.split("\t"))
        rows[(sport, dport, octets, packets)] += 1
    return rows


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    want = expected(sys.argv[1], int(sys.argv[2]))
    have = stored(int(sys.argv[2]))
    total = sum(want.values())
    missing = want - have
    extra = have - want
    print(f"exporter reported {total} flows, database holds {sum(have.values())}")
    if total == 0:
        print("FAIL: the exporter reported no flows")
        return 1
    for key, count in (missing + extra).items():
        print(f"mismatch x{count}: {key}")
    if missing or extra:
        print("FAIL")
        return 1
    print("OK: every exported flow is stored with identical byte and packet counts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
