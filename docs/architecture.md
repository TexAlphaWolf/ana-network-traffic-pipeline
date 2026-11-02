# Architecture

## Data flow

1. **Sources become flows.** `pcap.py` reads capture files without third-party libraries and
   yields packets (timestamp, addresses, ports, protocol, IP length, TCP flags). `flows.py`
   aggregates them into unidirectional flows the way a router's flow cache does: a flow ends
   after `FLOWPIPE_IDLE_SECONDS` without packets or `FLOWPIPE_ACTIVE_SECONDS` of life. The
   table is capped at 200,000 entries; beyond that the oldest are exported early, so a capture
   full of scan traffic cannot exhaust memory. `netflow.py` decodes NetFlow v5, v9 and IPFIX
   datagrams into the same `Flow` record.
2. **Flows are stored.** `store.py` talks to ClickHouse over HTTP with the standard library
   (JSONEachRow bulk inserts, credentials in headers, no redirects). A flow row carries the
   address, ports, protocol, a service label, whether each end is internal, byte/packet counts
   and the source (file name or exporter).
3. **A rollup is maintained by the database.** A materialized view fills `flows_1m`
   (bytes, packets and flows per minute, protocol and service). Dashboards and spike detection
   read it, so they stay fast over months of data.
4. **Detectors read and write back.** `anomaly.py` writes findings into `anomalies`
   (`ReplacingMergeTree`: running the detectors again replaces rows instead of duplicating them).
5. **Presentation.** Grafana queries ClickHouse with a read-only user; `report.py` renders the
   same questions as text or a self-contained HTML page.

## Schema (`src/flowpipe/schema.sql`)

| Table | Engine | Purpose |
|---|---|---|
| `flows` | MergeTree, partition by month, TTL | One row per flow. Ordered by minute, source, destination. |
| `flows_1m` | SummingMergeTree, TTL | Per-minute totals by protocol and service. Filled by `flows_1m_mv`. |
| `ingested_files` | ReplacingMergeTree | SHA-256 of every loaded file, so re-loading is a no-op. |
| `anomalies` | ReplacingMergeTree, TTL | Spikes and scans with value, baseline, score, detail. |

IP addresses are stored as strings. That costs some space (compressed with ZSTD) and keeps the
data readable in any client, including Grafana panels written by hand.

## Detection

**Traffic spikes.** For each minute, the baseline is the *median* of the previous 30 minutes and
the spread is the *median absolute deviation* scaled by 1.4826. A minute is flagged when its
robust z-score is at least 6, it is at least twice the baseline, and it exceeds 1 MB. Mean and
standard deviation would be dragged up by the spike itself and miss the second and third minute
of a long transfer; the median and MAD are not (up to half the window can be abnormal). Missing
minutes count as zero, a floor on the spread keeps a perfectly flat history from producing
infinite scores, and a judged window is always compared with the minutes *before* it, so
`--last 20m` still has a baseline. The culprit (largest source/destination pair in that minute)
is added to the finding.

**Port scans.** One source address that touches at least 100 distinct (destination, port) pairs
within a minute, over TCP or UDP. It is plain SQL (`uniqExact`), easy to adapt.

## Trust boundaries

| Input | Treated as | What protects the process |
|---|---|---|
| pcap/pcapng files | Hostile | Length checks on every record, a 256 KB record limit, truncated files stop cleanly, damaged records are counted, flow table cap. Fuzz tests. |
| NetFlow/IPFIX datagrams | Hostile, and spoofable (UDP) | Exporter allow-list (the collector refuses to run on a network address without one), bounds-checked decoding, template count and field limits, bounded template cache, bounded in-memory queue while the database is down. |
| Configuration | Trusted but validated | Identifiers and numbers are validated at startup; SQL values built by the program are escaped, and user input never reaches SQL as text. |
| ClickHouse | Authenticated, not trusted with a redirect | Credentials only in headers, never in URLs or error messages; redirects are not followed; TLS certificate verification stays on (`FLOWPIPE_CA_BUNDLE` for a private CA). |

Spoofed NetFlow is the practical risk of the collector: UDP source addresses can be forged on a
shared network. The allow-list narrows it to your exporters; place the collector on a network
where only they can reach it.

## Why these choices

- **Pure-Python decoders instead of tshark/libpcap.** No system packages, runs the same on
  Windows and Linux, easy to fuzz, and the container has no capture privileges.
- **No runtime dependencies.** The HTTP client is 100 lines of standard library. The attack
  surface and the update burden stay small.
- **ClickHouse and Grafana.** Columnar storage with a materialized rollup is the right shape for
  time-series flow data, and it is what you would run for a larger network.
- **Detection in the database and in small functions.** The scan detector is one SQL statement;
  the spike maths is a pure function with its own unit tests.
