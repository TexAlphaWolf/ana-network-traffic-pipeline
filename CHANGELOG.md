# Changelog

## [1.0.0] - 2026-11-02

### Added
- pcap/pcapng reader (both byte orders, µs/ns, VLAN, IPv4/IPv6, gzip) and flow aggregation.
- NetFlow v5, v9 and IPFIX decoder and UDP collector with exporter allow-list.
- ClickHouse schema with one-minute rollup, TTL retention and ingest bookkeeping.
- Spike (median/MAD) and port-scan detection.
- CLI: `init-db`, `ingest`, `watch`, `collect`, `anomalies`, `top`, `report`, `status`, `sample`.
- Text and HTML reports.
- Grafana dashboard, provisioned datasource, read-only database user.
- Interoperability test with a real exporter (softflowd, NetFlow v5/v9/IPFIX) in CI.
- Keyed IP anonymisation.
- Docker Compose stack, CI (tests on real ClickHouse, Windows, full stack), CodeQL, Dependabot.
