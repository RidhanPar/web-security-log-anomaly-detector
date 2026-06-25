"""
Stage 2 - Behavioural feature engineering.

Computes 10 per-IP behavioural features over time windows. The canonical
implementation uses **PySpark window functions** (``PARTITION BY ip_address
ORDER BY timestamp`` with ``RANGE BETWEEN INTERVAL ... PRECEDING AND CURRENT
ROW`` frames). A **pandas** fallback computes the identical features when Spark
is unavailable.

Features
--------
 1. requests_per_minute        - request count in the trailing 60s
 2. post_login_rate            - POST /login count in the trailing 5min
 3. error_rate_5min            - mean(status >= 400) in the trailing 5min
 4. unique_urls_per_hour       - distinct base URLs in the trailing 1h
 5. avg_response_bytes_ratio   - response size vs trailing-1h mean (spike)
 6. request_interval_variance  - variance of inter-request gaps per IP
 7. is_offhours                - 1 if hour < 7 or hour > 22
 8. sequential_url_score       - 1 if URL id increments from the prior request
 9. suspicious_param_rate      - mean(has_suspicious_params) in trailing 30min
10. new_session_flag           - 1 if session unseen for this IP in prior 24h

Run:
    python scripts/feature_engineering.py
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLEAN_DIR = ROOT / "data" / "processed" / "clean_logs"
FEATURES_DIR = ROOT / "data" / "processed" / "log_features"

FEATURE_COLUMNS = [
    "requests_per_minute", "post_login_rate", "error_rate_5min",
    "unique_urls_per_hour", "avg_response_bytes_ratio",
    "request_interval_variance", "is_offhours", "sequential_url_score",
    "suspicious_param_rate", "new_session_flag",
]


def get_spark(app_name: str):
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
    except Exception as exc:  # noqa: BLE001
        print(f"[features] PySpark unavailable ({type(exc).__name__}: {exc}).")
        print("[features] Falling back to the pandas implementation.")
        return None


def _clean_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# PySpark implementation
# --------------------------------------------------------------------------- #
def run_spark(spark) -> None:
    from pyspark.sql import Window
    from pyspark.sql import functions as F

    df = spark.read.parquet(str(CLEAN_DIR))

    # Numeric seconds-since-epoch ordering key (keeps sub-second precision for
    # the interval-variance feature).
    df = df.withColumn("ts_double", F.col("event_time").cast("double"))

    w_ip = Window.partitionBy("ip_address").orderBy("ts_double")
    w_1m = w_ip.rangeBetween(-60, 0)
    w_5m = w_ip.rangeBetween(-300, 0)
    w_30m = w_ip.rangeBetween(-1800, 0)
    w_1h = w_ip.rangeBetween(-3600, 0)
    w_ip_full = Window.partitionBy("ip_address")
    w_sess = Window.partitionBy("ip_address", "session_id").orderBy("ts_double")

    post_login = F.when(
        (F.col("base_url") == "/login") & (F.col("method") == "POST"), 1
    ).otherwise(0)
    error_flag = F.when(F.col("status_code") >= 400, 1.0).otherwise(0.0)

    # 1-5, 9: windowed aggregates
    df = (
        df
        .withColumn("requests_per_minute", F.count(F.lit(1)).over(w_1m))
        .withColumn("post_login_rate", F.sum(post_login).over(w_5m))
        .withColumn("error_rate_5min", F.avg(error_flag).over(w_5m))
        .withColumn("unique_urls_per_hour",
                    F.size(F.collect_set("base_url").over(w_1h)))
        .withColumn("hourly_avg_bytes", F.avg("response_bytes").over(w_1h))
        .withColumn("suspicious_param_rate",
                    F.avg(F.col("has_suspicious_params").cast("double")).over(w_30m))
    )
    df = df.withColumn(
        "avg_response_bytes_ratio",
        F.when(F.col("hourly_avg_bytes") > 0,
               F.col("response_bytes") / F.col("hourly_avg_bytes")).otherwise(1.0),
    )

    # 6: inter-request interval variance per IP
    prev_ts = F.lag("ts_double").over(w_ip)
    df = df.withColumn("interval_sec", F.col("ts_double") - prev_ts)
    df = df.withColumn(
        "request_interval_variance",
        F.coalesce(F.var_samp("interval_sec").over(w_ip_full), F.lit(0.0)),
    )

    # 7: off-hours flag
    df = df.withColumn(
        "is_offhours",
        ((F.hour("event_time") < 7) | (F.hour("event_time") > 22)).cast("int"),
    )

    # 8: sequential URL score (id increments by 1 vs previous request)
    url_num = F.regexp_extract(F.col("base_url"), r"/(\d+)$", 1)
    df = df.withColumn(
        "url_num",
        F.when(url_num != "", url_num.cast("long")).otherwise(F.lit(None)),
    )
    prev_num = F.lag("url_num").over(w_ip)
    df = df.withColumn(
        "sequential_url_score",
        F.when(
            F.col("url_num").isNotNull() & prev_num.isNotNull()
            & (F.col("url_num") == prev_num + 1), 1.0,
        ).otherwise(0.0),
    )

    # 10: new-session flag (session unseen for this IP in prior 24h)
    prev_sess_ts = F.lag("ts_double").over(w_sess)
    df = df.withColumn(
        "new_session_flag",
        F.when(prev_sess_ts.isNull()
               | ((F.col("ts_double") - prev_sess_ts) > 86400), 1).otherwise(0),
    )

    df = df.drop("ts_double", "hourly_avg_bytes", "interval_sec", "url_num")

    _clean_output_dir(FEATURES_DIR)
    df.write.mode("overwrite").parquet(str(FEATURES_DIR))
    _summary_spark(df)
    print(f"[features] Feature dataset written to {FEATURES_DIR}")


def _summary_spark(df) -> None:
    from pyspark.sql import functions as F

    print("\n[features] Feature summary (mean by attack_type):")
    cols = [F.round(F.avg(c), 3).alias(c) for c in
            ["requests_per_minute", "error_rate_5min",
             "avg_response_bytes_ratio", "suspicious_param_rate"]]
    df.groupBy("attack_type").agg(*cols).orderBy("attack_type").show(truncate=False)


# --------------------------------------------------------------------------- #
# pandas fallback implementation
# --------------------------------------------------------------------------- #
def run_pandas() -> None:
    import numpy as np
    import pandas as pd

    df = pd.read_parquet(CLEAN_DIR)
    df = df.sort_values(["ip_address", "event_time"]).reset_index(drop=True)

    df["post_login_flag"] = (
        (df["base_url"] == "/login") & (df["method"] == "POST")
    ).astype(int)
    df["error_flag"] = (df["status_code"] >= 400).astype(float)
    df["one"] = 1
    df["hour"] = df["event_time"].dt.hour
    df["url_num"] = df["base_url"].map(_trailing_num)

    parts = []
    for _, grp in df.groupby("ip_address", sort=False):
        parts.append(_features_for_ip(grp.copy(), np, pd))
    out = pd.concat(parts, ignore_index=True)

    out["is_offhours"] = ((out["hour"] < 7) | (out["hour"] > 22)).astype(int)
    out = out.sort_values("event_time").reset_index(drop=True)

    drop_cols = ["post_login_flag", "error_flag", "one", "hour", "url_num"]
    out = out.drop(columns=[c for c in drop_cols if c in out.columns])

    _clean_output_dir(FEATURES_DIR)
    out.to_parquet(FEATURES_DIR / "part-00000.parquet", index=False)
    _summary_pandas(out)
    print(f"[features] Feature dataset written to {FEATURES_DIR}")


def _trailing_num(url: str):
    import numpy as np
    m = re.search(r"/(\d+)$", url or "")
    return float(m.group(1)) if m else np.nan


def _features_for_ip(grp, np, pd):
    """Compute all per-IP windowed features for a single IP's rows."""
    grp = grp.sort_values("event_time")
    g = grp.set_index("event_time")

    grp["requests_per_minute"] = g["one"].rolling("60s").count().to_numpy()
    grp["post_login_rate"] = g["post_login_flag"].rolling("300s").sum().to_numpy()
    grp["error_rate_5min"] = g["error_flag"].rolling("300s").mean().to_numpy()
    grp["suspicious_param_rate"] = (
        g["has_suspicious_params"].astype(float).rolling("1800s").mean().to_numpy()
    )

    # unique base URLs in the trailing hour (rolling distinct via integer codes)
    codes = pd.Series(pd.factorize(g["base_url"])[0].astype(float), index=g.index)
    grp["unique_urls_per_hour"] = (
        codes.rolling("3600s").apply(lambda a: len(np.unique(a)), raw=True).to_numpy()
    )

    # response-size spike vs trailing-1h mean
    hourly_avg = g["response_bytes"].rolling("3600s").mean().to_numpy()
    rbytes = grp["response_bytes"].to_numpy()
    ratio = np.divide(rbytes, hourly_avg, out=np.ones_like(rbytes, dtype=float),
                      where=hourly_avg > 0)
    grp["avg_response_bytes_ratio"] = ratio

    # inter-request interval variance (single value per IP)
    ts = g.index.view("int64") / 1e9
    diffs = np.diff(ts)
    grp["request_interval_variance"] = (
        float(np.var(diffs, ddof=1)) if len(diffs) > 1 else 0.0
    )

    # sequential URL score (id == previous id + 1)
    nums = grp["url_num"].to_numpy()
    prev = np.empty_like(nums)
    prev[0] = np.nan
    prev[1:] = nums[:-1]
    grp["sequential_url_score"] = (
        (~np.isnan(nums)) & (~np.isnan(prev)) & (nums == prev + 1)
    ).astype(float)

    # new-session flag (session unseen for this IP in prior 24h)
    sess_prev = grp.groupby("session_id")["event_time"].shift(1)
    delta = (grp["event_time"] - sess_prev).dt.total_seconds()
    grp["new_session_flag"] = (
        sess_prev.isna() | (delta > 86400)
    ).astype(int).to_numpy()

    return grp


def _summary_pandas(out) -> None:
    cols = ["requests_per_minute", "error_rate_5min",
            "avg_response_bytes_ratio", "suspicious_param_rate"]
    print("\n[features] Feature summary (mean by attack_type):")
    summary = out.groupby("attack_type")[cols].mean().round(3)
    print(summary.to_string())
    print()


def main() -> None:
    if not CLEAN_DIR.exists():
        raise SystemExit("Clean logs not found. Run `python scripts/ingest_logs.py` first.")
    spark = get_spark("feature_engineering")
    if spark is not None:
        run_spark(spark)
        spark.stop()
    else:
        run_pandas()


if __name__ == "__main__":
    main()
