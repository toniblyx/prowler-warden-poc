"""ClickHouse access + schema."""
import clickhouse_connect

from . import config

SCHEMA = [
    f"CREATE DATABASE IF NOT EXISTS {config.CH_DB}",
    """CREATE TABLE IF NOT EXISTS findings (
        scan_id String,
        scan_time DateTime,
        account_id LowCardinality(String),
        region LowCardinality(String),
        check_id LowCardinality(String),
        service LowCardinality(String),
        severity LowCardinality(String),
        status LowCardinality(String),
        resource_uid String,
        resource_name String,
        status_extended String,
        risk String,
        remediation_desc String,
        remediation_cli String
    ) ENGINE = MergeTree
    PARTITION BY toYYYYMM(scan_time)
    ORDER BY (account_id, check_id, resource_uid, scan_time)""",
    """CREATE TABLE IF NOT EXISTS scans (
        scan_id String,
        scan_time DateTime,
        account_id LowCardinality(String),
        framework LowCardinality(String),
        source LowCardinality(String),
        findings UInt32
    ) ENGINE = MergeTree ORDER BY (account_id, scan_time)""",
    """CREATE TABLE IF NOT EXISTS framework_map (
        framework LowCardinality(String),
        req_id String,
        section String,
        description String,
        check_id LowCardinality(String),
        manual UInt8
    ) ENGINE = ReplacingMergeTree ORDER BY (framework, req_id, check_id)""",
    """CREATE TABLE IF NOT EXISTS actions (
        id UUID DEFAULT generateUUIDv4(),
        ts DateTime DEFAULT now(),
        account_id String,
        framework String,
        kind LowCardinality(String),
        check_id String,
        resource_uid String,
        summary String,
        command String,
        status LowCardinality(String)
    ) ENGINE = ReplacingMergeTree(ts) ORDER BY id""",
]


def client(database: str | None = config.CH_DB):
    return clickhouse_connect.get_client(
        host=config.CH_HOST, port=config.CH_PORT, username=config.CH_USER,
        password=config.CH_PASSWORD, database=database or "default",
    )


def init():
    c = client(None)
    c.command(SCHEMA[0])
    c = client()
    for ddl in SCHEMA[1:]:
        c.command(ddl)
    return c


def query(sql: str, params: dict | None = None) -> list[dict]:
    r = client().query(sql, parameters=params or {})
    return [dict(zip(r.column_names, row)) for row in r.result_rows]
