#!/usr/bin/env bash
# End-to-end test with a real, independent NetFlow exporter (softflowd).
#
#   tools/check_exporter.sh <5|9|10>
#
# Needs: softflowd, curl, python3, root (or CAP_NET_RAW) to capture on the loopback interface,
# the flowpipe command on PATH, and a ClickHouse reachable through the FLOWPIPE_* variables.
# Real HTTP traffic is exported as NetFlow v5, v9 or IPFIX (10) to the collector and the stored
# flows are compared with softflowd's own flow table.
set -euo pipefail

version="${1:?usage: check_exporter.sh 5|9|10}"
port="${CHECK_PORT:-8099}"
work="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT

export FLOWPIPE_FLUSH_SECONDS=1
flowpipe init-db
flowpipe collect >"$work/collector.log" 2>&1 &
sleep 2

head -c 300000 /dev/urandom >"$work/blob.bin"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
sleep 1

# Long timeouts: flows are only exported when we ask, so they are never split.
softflowd -i lo -v "$version" -n 127.0.0.1:2055 -p "$work/sf.pid" -c "$work/sf.ctl" \
  -t maxlife=300 -t general=300 -t tcp=300 -t tcp.rst=300 -t tcp.fin=300
sleep 1
for _ in $(seq 1 15); do curl -fs -o /dev/null "http://127.0.0.1:$port/blob.bin"; done
sleep 2
softflowctl -c "$work/sf.ctl" dump-flows >"$work/dump.txt" 2>&1
softflowctl -c "$work/sf.ctl" expire-all >/dev/null 2>&1
sleep 5
softflowctl -c "$work/sf.ctl" shutdown >/dev/null 2>&1 || true

python3 "$(dirname "$0")/check_exporter.py" "$work/dump.txt" "$port"
