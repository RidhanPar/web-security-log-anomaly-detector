"""
Stage 1 - Ingestion & data quality.

Reads the raw synthetic access log (``data/access_logs.parquet``), validates the
schema, parses the timestamp to a proper timestamp type, enriches each row with
user-agent and URL-derived fields, and writes a clean Parquet dataset to
``data/processed/clean_logs/``.

Primary implementation uses **PySpark**. If Spark/Java is not available on the
host (e.g. a laptop without a JVM) the script transparently falls back to an
equivalent **pandas** implementation so the pipeline remains runnable anywhere.

Run:
    python scripts/ingest_logs.py
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_PARQUET = ROOT / "data" / "access_logs.parquet"
RAW_CSV = ROOT / "data" / "access_logs.csv"
CLEAN_DIR = ROOT / "data" / "processed" / "clean_logs"

# Columns expected in the raw log (9 access-log fields + ground-truth label).
REQUIRED_COLUMNS = [
    "timestamp", "ip_address", "method", "url", "status_code",
    "response_bytes", "user_agent", "referrer", "session_id", "attack_type",
]
# Fields that must never be null.
NON_NULL_COLUMNS = ["timestamp", "ip_address", "url", "status_code"]

# User agents that identify automated clients.
BOT_TOKENS = ["python-requests", "curl", "wget", "scrapy", "bot", "crawler"]

# Tokens that mark a URL/query string as a likely injection probe.
SUSPICIOUS_TOKENS = [
    "1=1", "or 1=1", "union select", "drop table", "information_schema",
    "xp_cmdshell", "sleep(", "--", "';", "' or '", "/*", "*/", "@@version",
    "benchmark(", "load_file(", "0x",
]
TIMESTAMP_FMT = "yyyy-MM-dd HH:mm:ss.SSSSSS"


# --------------------------------------------------------------------------- #
# Shared pure-python helpers (used by the pandas fallback)
# --------------------------------------------------------------------------- #
def detect_browser(ua: str) -> str:
    ua = ua or ""
    low = ua.lower()
    if any(tok in low for tok in BOT_TOKENS) or low.startswith(("go-http", "scrapy")):
        return "Bot/Tool"
    if "sqlmap" in low or "nmap" in low or "zgrab" in low:
        return "Scanner"
    if "edg/" in low:
        return "Edge"
    if "opr/" in low or "opera" in low:
        return "Opera"
    if "chrome/" in low:
        return "Chrome"
    if "firefox/" in low:
        return "Firefox"
    if "safari/" in low:
        return "Safari"
    return "Other"


def is_bot_ua(ua: str) -> bool:
    low = (ua or "").lower()
    return any(tok in low for tok in BOT_TOKENS)


def base_path(url: str) -> str:
    return (url or "").split("?", 1)[0]


def has_suspicious_params(url: str) -> bool:
    low = (url or "").lower()
    return any(tok in low for tok in SUSPICIOUS_TOKENS)


# --------------------------------------------------------------------------- #
# Spark session helper
# --------------------------------------------------------------------------- #
def get_spark(app_name: str):
    """Return a SparkSession, or ``None`` if PySpark/Java is unavailable."""
    try:
        from pyspark.sql import SparkSession
        spark = (
            SparkSession.builder
            .appName(app_name)
            .master(os.environ.get("SPARK_MASTER", "local[*]"))
            .config("spark.sql.session.timeZone", "UTC")
            .config("spark.ui.showConsoleProgress", "false")
            .getOrCreate()
        )
        spark.sparkContext.setLogLevel("WARN")
        return spark
    except Exception as exc:  # noqa: BLE001 - any failure means fall back
        print(f"[ingest] PySpark unavailable ({type(exc).__name__}: {exc}).")
        print("[ingest] Falling back to the pandas implementation.")
        return None


def _clean_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# PySpark implementation
# --------------------------------------------------------------------------- #
def run_spark(spark) -> None:
    from pyspark.sql import functions as F

    src = str(RAW_PARQUET if RAW_PARQUET.exists() else RAW_CSV)
    if src.endswith(".csv"):
        df = spark.read.option("header", True).option("inferSchema", True).csv(src)
    else:
        df = spark.read.parquet(src)

    _validate_columns(df.columns)

    df = (
        df
        .withColumn("event_time", F.to_timestamp("timestamp", TIMESTAMP_FMT))
        .withColumn("status_code", F.col("status_code").cast("int"))
        .withColumn("response_bytes", F.col("response_bytes").cast("long"))
    )

    ua_low = F.lower(F.col("user_agent"))
    is_bot = F.lit(False)
    for tok in BOT_TOKENS:
        is_bot = is_bot | ua_low.contains(tok)
    df = df.withColumn("is_bot", is_bot)

    browser = (
        F.when(df.is_bot, F.lit("Bot/Tool"))
        .when(ua_low.contains("edg/"), F.lit("Edge"))
        .when(ua_low.contains("opr/") | ua_low.contains("opera"), F.lit("Opera"))
        .when(ua_low.contains("chrome/"), F.lit("Chrome"))
        .when(ua_low.contains("firefox/"), F.lit("Firefox"))
        .when(ua_low.contains("safari/"), F.lit("Safari"))
        .when(ua_low.contains("sqlmap") | ua_low.contains("nmap")
              | ua_low.contains("zgrab"), F.lit("Scanner"))
        .otherwise(F.lit("Other"))
    )
    df = df.withColumn("browser_type", browser)

    df = df.withColumn("base_url", F.split(F.col("url"), "\\?").getItem(0))

    url_low = F.lower(F.col("url"))
    suspicious = F.lit(False)
    for tok in SUSPICIOUS_TOKENS:
        suspicious = suspicious | url_low.contains(tok)
    df = df.withColumn("has_suspicious_params", suspicious.cast("int"))

    _quality_report_spark(df)

    _clean_output_dir(CLEAN_DIR)
    (df.write.mode("overwrite").parquet(str(CLEAN_DIR)))
    print(f"[ingest] Clean logs written to {CLEAN_DIR}")


def _validate_columns(cols) -> None:
    missing = [c for c in REQUIRED_COLUMNS if c not in cols]
    if missing:
        raise ValueError(f"Schema validation failed - missing columns: {missing}")
    print(f"[ingest] Schema OK - {len(REQUIRED_COLUMNS)} required columns present.")


def _quality_report_spark(df) -> None:
    from pyspark.sql import functions as F

    total = df.count()
    null_counts = {
        c: df.filter(F.col(c).isNull()).count() for c in NON_NULL_COLUMNS
    }
    bot_count = df.filter(F.col("is_bot")).count()
    susp_count = df.filter(F.col("has_suspicious_params") == 1).count()
    bad_ts = df.filter(F.col("event_time").isNull()).count()

    _print_report(total, null_counts, bad_ts, bot_count, susp_count)


# --------------------------------------------------------------------------- #
# pandas fallback implementation
# --------------------------------------------------------------------------- #
def run_pandas() -> None:
    import pandas as pd

    if RAW_PARQUET.exists():
        df = pd.read_parquet(RAW_PARQUET)
    else:
        df = pd.read_csv(RAW_CSV)

    _validate_columns(df.columns.tolist())

    df["event_time"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["status_code"] = df["status_code"].astype("int64")
    df["response_bytes"] = df["response_bytes"].astype("int64")

    df["is_bot"] = df["user_agent"].map(is_bot_ua)
    df["browser_type"] = df["user_agent"].map(detect_browser)
    df["base_url"] = df["url"].map(base_path)
    df["has_suspicious_params"] = df["url"].map(has_suspicious_params).astype(int)

    null_counts = {c: int(df[c].isnull().sum()) if hasattr(df[c], "isnull")
                   else int(df[c].isna().sum()) for c in NON_NULL_COLUMNS}
    _print_report(
        total=len(df),
        null_counts=null_counts,
        bad_ts=int(df["event_time"].isna().sum()),
        bot_count=int(df["is_bot"].sum()),
        susp_count=int((df["has_suspicious_params"] == 1).sum()),
    )

    _clean_output_dir(CLEAN_DIR)
    out = CLEAN_DIR / "part-00000.parquet"
    df.to_parquet(out, index=False)
    print(f"[ingest] Clean logs written to {CLEAN_DIR}")


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _print_report(total, null_counts, bad_ts, bot_count, susp_count) -> None:
    print("\n" + "=" * 52)
    print(" DATA QUALITY REPORT")
    print("=" * 52)
    print(f" Total rows                 : {total:,}")
    print(" Null counts (must be zero):")
    for col, cnt in null_counts.items():
        flag = "OK" if cnt == 0 else "FAIL"
        print(f"   {col:<22}: {cnt:>6,}  [{flag}]")
    print(f" Unparseable timestamps     : {bad_ts:,}")
    print(f" Bot user-agents (is_bot)   : {bot_count:,}")
    print(f" Suspicious-param requests  : {susp_count:,}")
    print("=" * 52 + "\n")


def main() -> None:
    if not (RAW_PARQUET.exists() or RAW_CSV.exists()):
        raise SystemExit(
            "Raw log not found. Run `python data/generate_logs.py` first."
        )
    spark = get_spark("ingest_logs")
    if spark is not None:
        run_spark(spark)
        spark.stop()
    else:
        run_pandas()


if __name__ == "__main__":
    main()
