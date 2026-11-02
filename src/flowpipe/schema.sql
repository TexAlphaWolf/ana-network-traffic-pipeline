-- ClickHouse schema. Statements are separated by lines containing only "--;".
-- {database} and {retention_days} are filled in by `flowpipe init-db`.
CREATE DATABASE IF NOT EXISTS {database}
--;
CREATE TABLE IF NOT EXISTS {database}.flows
(
    start        DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    end          DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    src_ip       String CODEC(ZSTD),
    dst_ip       String CODEC(ZSTD),
    src_internal UInt8,
    dst_internal UInt8,
    sport        UInt16,
    dport        UInt16,
    proto        UInt8,
    proto_name   LowCardinality(String),
    service      LowCardinality(String),
    bytes        UInt64 CODEC(T64, ZSTD),
    packets      UInt64 CODEC(T64, ZSTD),
    tcp_flags    UInt8,
    source       LowCardinality(String),
    exporter     LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(start)
ORDER BY (toStartOfMinute(start), src_ip, dst_ip)
TTL toDateTime(start) + INTERVAL {retention_days} DAY DELETE
--;
CREATE TABLE IF NOT EXISTS {database}.flows_1m
(
    minute     DateTime('UTC'),
    proto_name LowCardinality(String),
    service    LowCardinality(String),
    bytes      UInt64,
    packets    UInt64,
    flows      UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, proto_name, service)
TTL minute + INTERVAL {retention_days} DAY DELETE
--;
CREATE MATERIALIZED VIEW IF NOT EXISTS {database}.flows_1m_mv TO {database}.flows_1m AS
SELECT
    toStartOfMinute(toDateTime(start, 'UTC')) AS minute,
    proto_name,
    service,
    sum(bytes) AS bytes,
    sum(packets) AS packets,
    count() AS flows
FROM {database}.flows
GROUP BY minute, proto_name, service
--;
CREATE TABLE IF NOT EXISTS {database}.ingested_files
(
    sha256      String,
    name        String,
    flows       UInt64,
    packets     UInt64,
    ingested_at DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY sha256
--;
CREATE TABLE IF NOT EXISTS {database}.anomalies
(
    minute      DateTime('UTC'),
    kind        LowCardinality(String),
    subject     String,
    value       Float64,
    baseline    Float64,
    score       Float64,
    detail      String,
    detected_at DateTime('UTC') DEFAULT now()
)
ENGINE = ReplacingMergeTree(detected_at)
PARTITION BY toYYYYMM(minute)
ORDER BY (kind, subject, minute)
TTL minute + INTERVAL {retention_days} DAY DELETE
