"""
Athena handler (LocalStack-compatible).

Creates an external table over the alert Parquet files in S3 and runs analytical
SQL against it. Targets the endpoint in ``AWS_ENDPOINT_URL`` (LocalStack by
default). Athena requires an S3 location for query results, which is created
automatically.

Note: Athena is a LocalStack Pro feature. When it is unavailable the calling
code (``scripts/export_alerts.py``) falls back to computing the same queries
locally with pandas, so the analytics output is always produced.
"""
from __future__ import annotations

import os
import time

from aws import s3_handler

DATABASE = os.environ.get("ATHENA_DB", "security_analytics")
ALERTS_TABLE = "security_alerts"
RESULTS_BUCKET = os.environ.get("ATHENA_RESULTS_BUCKET", "athena-query-results")
OUTPUT_LOCATION = f"s3://{RESULTS_BUCKET}/output/"

# --- Canonical analytical queries ----------------------------------------- #
QUERIES = {
    "top_10_dangerous_ips": f"""
        SELECT ip_address,
               MAX(threat_score)        AS max_threat_score,
               COUNT(*)                 AS alert_count,
               MAX(severity)            AS top_severity
        FROM {DATABASE}.{ALERTS_TABLE}
        GROUP BY ip_address
        ORDER BY max_threat_score DESC, alert_count DESC
        LIMIT 10
    """,
    "alert_count_by_severity": f"""
        SELECT severity, COUNT(*) AS alert_count
        FROM {DATABASE}.{ALERTS_TABLE}
        GROUP BY severity
        ORDER BY alert_count DESC
    """,
    "detection_rate_by_hour": f"""
        SELECT hour(from_iso8601_timestamp(replace(timestamp, ' ', 'T'))) AS hour_of_day,
               COUNT(*) AS alert_count
        FROM {DATABASE}.{ALERTS_TABLE}
        GROUP BY 1
        ORDER BY 1
    """,
}


def get_client():
    return s3_handler.get_client("athena")


def is_available() -> bool:
    try:
        get_client().list_data_catalogs()
        return True
    except Exception:  # noqa: BLE001 - any failure => Athena not usable here
        return False


def _run(sql: str, database: str | None = None) -> str:
    """Start a query, block until it finishes, return the execution id."""
    athena = get_client()
    kwargs = {
        "QueryString": sql,
        "ResultConfiguration": {"OutputLocation": OUTPUT_LOCATION},
    }
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}

    qid = athena.start_query_execution(**kwargs)["QueryExecutionId"]
    while True:
        state = athena.get_query_execution(QueryExecutionId=qid)[
            "QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1)
    if state != "SUCCEEDED":
        raise RuntimeError(f"Athena query {state}: {sql.strip()[:60]}...")
    return qid


def _rows(qid: str) -> list[list[str]]:
    athena = get_client()
    result = athena.get_query_results(QueryExecutionId=qid)
    rows = result["ResultSet"]["Rows"]
    return [[c.get("VarCharValue", "") for c in r["Data"]] for r in rows]


def setup_table() -> None:
    """Create the database and an external table over the alert Parquet files."""
    s3_handler.ensure_bucket(RESULTS_BUCKET)
    _run(f"CREATE DATABASE IF NOT EXISTS {DATABASE}")
    ddl = f"""
        CREATE EXTERNAL TABLE IF NOT EXISTS {DATABASE}.{ALERTS_TABLE} (
            timestamp   STRING,
            ip_address  STRING,
            url         STRING,
            status_code INT,
            threat_score INT,
            severity    STRING,
            attack_type STRING,
            top_flag    STRING
        )
        STORED AS PARQUET
        LOCATION 's3://{s3_handler.BUCKET}/{s3_handler.ALERTS_PREFIX}'
    """
    _run(ddl, database=DATABASE)
    print(f"[athena] Table ready: {DATABASE}.{ALERTS_TABLE}")


def run_named_query(name: str) -> list[list[str]]:
    qid = _run(QUERIES[name], database=DATABASE)
    return _rows(qid)


def run_all() -> dict[str, list[list[str]]]:
    setup_table()
    return {name: run_named_query(name) for name in QUERIES}
