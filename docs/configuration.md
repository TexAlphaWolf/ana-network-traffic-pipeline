# Configuration

Settings are environment variables prefixed `FLOWPIPE_`. Running natively, flowpipe also reads a
`.env` file in the current folder (real environment variables win). With Docker Compose, put
them in `.env` next to `docker-compose.yml`.

## Compose variables (`.env`)

| Variable | Required | Meaning |
|---|---|---|
| `CLICKHOUSE_FLOWPIPE_PASSWORD` | yes | Password of the ClickHouse user flowpipe writes with |
| `GRAFANA_CLICKHOUSE_PASSWORD` | yes | Password of the read-only ClickHouse user Grafana uses |
| `GRAFANA_ADMIN_PASSWORD` | yes | Grafana login (user `admin`) |
| `FLOWPIPE_ALLOWED_EXPORTERS` | for `--profile netflow` | Exporter addresses or ranges |
| `FLOWPIPE_COLLECTOR_BIND` | no | Address to publish UDP 2055 on (default all) |

## flowpipe settings

| Variable | Default | Meaning |
|---|---|---|
| `FLOWPIPE_CLICKHOUSE_URL` | `http://localhost:8123` | HTTP(S) endpoint. Use `https://` across a network. |
| `FLOWPIPE_CLICKHOUSE_USER` | `default` | Database user |
| `FLOWPIPE_CLICKHOUSE_PASSWORD` | empty | Database password |
| `FLOWPIPE_DATABASE` | `flowpipe` | Database name (letters, digits, `_`) |
| `FLOWPIPE_CA_BUNDLE` | | PEM file with the CA that signed the server certificate |
| `FLOWPIPE_RETENTION_DAYS` | `90` | Applied as a TTL when `init-db` creates the tables |
| `FLOWPIPE_BATCH_SIZE` | `5000` | Rows per insert |
| `FLOWPIPE_FLUSH_SECONDS` | `5` | Collector: maximum time between inserts |
| `FLOWPIPE_IDLE_SECONDS` | `15` | pcap: a flow ends after this much silence |
| `FLOWPIPE_ACTIVE_SECONDS` | `60` | pcap: a flow is split after this much life |
| `FLOWPIPE_LISTEN` | `127.0.0.1` | Collector bind address |
| `FLOWPIPE_PORT` | `2055` | Collector UDP port |
| `FLOWPIPE_ALLOWED_EXPORTERS` | | Comma-separated addresses/ranges. Required when listening on a network address. |
| `FLOWPIPE_ALLOW_ANY_EXPORTER` | `false` | Accept datagrams from anyone (only on a network you control) |
| `FLOWPIPE_ANONYMISE_KEY` | | 8+ characters. Replaces every IP with a keyed pseudonym before storing. |
| `FLOWPIPE_SPIKE_WINDOW_MIN` | `30` | Minutes of history used as the baseline |
| `FLOWPIPE_SPIKE_THRESHOLD` | `6` | Robust z-score needed to flag a minute |
| `FLOWPIPE_SPIKE_MIN_BYTES` | `1000000` | Ignore spikes smaller than this per minute |
| `FLOWPIPE_SCAN_THRESHOLD` | `100` | Distinct host/port pairs per source per minute |

To change the retention of an existing database:

```sql
ALTER TABLE flowpipe.flows MODIFY TTL toDateTime(start) + INTERVAL 30 DAY DELETE;
```

## Tests only

`FLOWPIPE_TEST_CLICKHOUSE`, `FLOWPIPE_TEST_USER`, `FLOWPIPE_TEST_PASSWORD` point the test suite
at a real server instead of the embedded engine.
