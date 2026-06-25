"""
Stage 4 - Alert export, S3 upload & Athena analytics.

Prints an analyst-facing alert summary, uploads the alert and raw-log Parquet
files to S3 (LocalStack), and runs three analytical queries via Athena. If the
AWS endpoint or Athena is unavailable, the same queries are computed locally
with pandas so the report is always produced.

Run:
    python scripts/export_alerts.py
    python scripts/export_alerts.py --skip-aws
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # make the `aws` package importable

ALERTS_DIR = ROOT / "data" / "output" / "security_alerts"
SCORED_DIR = ROOT / "data" / "output" / "scored_logs"
RAW_PARQUET = ROOT / "data" / "access_logs.parquet"


# --------------------------------------------------------------------------- #
# Local summary
# --------------------------------------------------------------------------- #
def print_summary(alerts: pd.DataFrame, scored: pd.DataFrame | None) -> None:
    print("\n" + "=" * 60)
    print(" SECURITY ALERT SUMMARY")
    print("=" * 60)
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        sub = alerts[alerts["severity"] == sev]
        print(f" {sev:<9} alerts: {len(sub):>6,}   "
              f"({sub['ip_address'].nunique():,} unique IPs)")

    print("\n Top 5 threat IPs (by max threat score):")
    top = (
        alerts.groupby("ip_address")["threat_score"].max()
        .sort_values(ascending=False).head(5)
    )
    for ip, score in top.items():
        print(f"   {ip:<18} score={int(score)}")

    if scored is not None:
        print("\n Attack-type detection rates (MEDIUM+ vs. ground truth):")
        flagged = scored["threat_score"] >= 25
        for attack in sorted(scored["attack_type"].unique()):
            if attack == "normal":
                continue
            sub = scored[scored["attack_type"] == attack]
            rate = flagged[sub.index].mean() * 100
            print(f"   {attack:<20}: {rate:5.1f}%")
        normal = scored[scored["attack_type"] == "normal"]
        print(f"   {'(false positives)':<20}: "
              f"{flagged[normal.index].mean() * 100:5.1f}%")
    print("=" * 60 + "\n")


# --------------------------------------------------------------------------- #
# AWS upload + analytics
# --------------------------------------------------------------------------- #
def upload_to_s3() -> None:
    from aws import s3_handler

    s3_handler.ensure_bucket(s3_handler.BUCKET)
    n = s3_handler.upload_dir(ALERTS_DIR, s3_handler.BUCKET, s3_handler.ALERTS_PREFIX)
    print(f"[export] Uploaded {n} alert file(s) to "
          f"s3://{s3_handler.BUCKET}/{s3_handler.ALERTS_PREFIX}")
    if RAW_PARQUET.exists():
        s3_handler.upload_file(
            RAW_PARQUET, s3_handler.BUCKET,
            s3_handler.RAW_LOGS_PREFIX + RAW_PARQUET.name,
        )


def run_athena_queries() -> None:
    from aws import athena_handler

    print("\n[export] Running Athena queries...")
    results = athena_handler.run_all()
    for name, rows in results.items():
        print(f"\n--- {name} ---")
        for row in rows:
            print("   " + " | ".join(row))


def run_local_queries(alerts: pd.DataFrame) -> None:
    """pandas equivalents of the three Athena analytical queries."""
    print("\n[export] Athena unavailable - computing queries locally (pandas):")

    print("\n--- top_10_dangerous_ips ---")
    top = (
        alerts.groupby("ip_address")
        .agg(max_threat_score=("threat_score", "max"),
             alert_count=("threat_score", "size"))
        .sort_values(["max_threat_score", "alert_count"], ascending=False)
        .head(10)
    )
    print(top.to_string())

    print("\n--- alert_count_by_severity ---")
    print(alerts["severity"].value_counts().to_string())

    print("\n--- alert_count_by_hour ---")
    hours = pd.to_datetime(alerts["timestamp"]).dt.hour
    print(hours.value_counts().sort_index().to_string())


# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Export & analyse security alerts")
    parser.add_argument("--skip-aws", action="store_true",
                        help="skip S3 upload and Athena queries")
    args = parser.parse_args()

    if not ALERTS_DIR.exists():
        raise SystemExit(
            "Alerts not found. Run `python scripts/anomaly_detection.py` first."
        )
    alerts = pd.read_parquet(ALERTS_DIR)
    scored = pd.read_parquet(SCORED_DIR) if SCORED_DIR.exists() else None

    print_summary(alerts, scored)

    if args.skip_aws:
        run_local_queries(alerts)
        return

    try:
        from aws import athena_handler, s3_handler
    except ImportError as exc:
        print(f"[export] boto3 not installed ({exc}); skipping AWS steps.")
        run_local_queries(alerts)
        return

    if s3_handler.is_available():
        upload_to_s3()
        if athena_handler.is_available():
            try:
                run_athena_queries()
            except Exception as exc:  # noqa: BLE001
                print(f"[export] Athena query failed ({exc}); using local fallback.")
                run_local_queries(alerts)
        else:
            run_local_queries(alerts)
    else:
        print(f"[export] AWS endpoint {s3_handler.ENDPOINT_URL} unreachable; "
              "skipping upload.")
        run_local_queries(alerts)


if __name__ == "__main__":
    main()
