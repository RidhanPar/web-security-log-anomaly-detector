"""
S3-triggered Lambda - alert triage.

Invoked when a new alert Parquet file lands in
``s3://security-logs-pipeline/alerts/``. The function reads the file, counts
alerts by severity, emits a log line when CRITICAL threats are present, and
returns the counts.

In production the Parquet read requires pyarrow (ship it as a Lambda layer). On
LocalStack the same handler is exercised by ``aws/setup_lambda.py``.
"""
from __future__ import annotations

import io
import os
import urllib.parse


def _s3_client():
    import boto3
    return boto3.client(
        "s3",
        endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )


def _summarise_parquet(body: bytes) -> dict:
    """Return severity counts and the single most dangerous IP from a Parquet blob."""
    import pyarrow.parquet as pq

    table = pq.read_table(io.BytesIO(body))
    cols = table.column_names
    severities = table.column("severity").to_pylist() if "severity" in cols else []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for sev in severities:
        if sev in counts:
            counts[sev] += 1

    top_ip, top_score = None, -1
    if "ip_address" in cols and "threat_score" in cols:
        ips = table.column("ip_address").to_pylist()
        scores = table.column("threat_score").to_pylist()
        for ip, score in zip(ips, scores):
            if score is not None and score > top_score:
                top_ip, top_score = ip, score

    return {"counts": counts, "top_ip": top_ip, "top_score": top_score,
            "unique_ips": len(set(table.column("ip_address").to_pylist()))
            if "ip_address" in cols else 0}


def handler(event, context):
    """AWS Lambda entry point."""
    s3 = _s3_client()

    total = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    worst_ip, worst_score, worst_unique = None, -1, 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        print(f"[lambda] New alert object: s3://{bucket}/{key}")

        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        summary = _summarise_parquet(body)

        for sev, cnt in summary["counts"].items():
            total[sev] += cnt
        if summary["top_score"] > worst_score:
            worst_ip = summary["top_ip"]
            worst_score = summary["top_score"]
            worst_unique = summary["unique_ips"]

    if total["CRITICAL"] > 0:
        print(
            f"SECURITY ALERT CRITICAL: {total['CRITICAL']} critical threats "
            f"detected from {worst_unique} unique IPs. "
            f"Top IP: {worst_ip} (score: {worst_score})"
        )
    else:
        print(f"[lambda] No critical threats. "
              f"HIGH={total['HIGH']} MEDIUM={total['MEDIUM']}")

    return {
        "statusCode": 200,
        "criticalCount": total["CRITICAL"],
        "highCount": total["HIGH"],
        "mediumCount": total["MEDIUM"],
    }


if __name__ == "__main__":
    # Local smoke test against a file in the alerts bucket prefix.
    demo_event = {
        "Records": [
            {"s3": {"bucket": {"name": os.environ.get("S3_BUCKET",
                                                      "security-logs-pipeline")},
                    "object": {"key": "alerts/part-00000.parquet"}}}
        ]
    }
    print(handler(demo_event, None))
