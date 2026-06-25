"""
Stage 5 - Real-time streaming detection (Spark Structured Streaming + Kafka).

Consumes the ``web_access_logs`` Kafka topic, applies lightweight real-time
detectors (bot user-agent, suspicious query parameters, and a z-score on
response size against a rolling 5-minute baseline), and appends flagged events
to ``output/streaming_security_alerts/`` every 30 seconds.

Start the producer first (writes one event every 0.2s):
    python data/generate_logs.py --stream

Then run this consumer (needs the Spark Kafka connector, provided via
spark.jars.packages):
    python scripts/streaming_consumer.py
    spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
        scripts/streaming_consumer.py
"""
from __future__ import annotations

import math
import os
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output" / "streaming_security_alerts"
CHECKPOINT_DIR = ROOT / "output" / "_checkpoints" / "streaming"

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "web_access_logs")
SPARK_KAFKA_PKG = "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1"

BOT_TOKENS = ["python-requests", "curl", "wget", "scrapy", "bot", "crawler"]
SUSPICIOUS_TOKENS = [
    "1=1", "or 1=1", "union select", "drop table", "information_schema",
    "xp_cmdshell", "sleep(", "--", "';", "' or '",
]

# Rolling 5-minute baseline for response size: with a 30s trigger, 10 batches
# ~= 5 minutes. Each entry is (count, sum, sum_of_squares).
_BASELINE = deque(maxlen=10)


def build_spark():
    from pyspark.sql import SparkSession

    return (
        SparkSession.builder
        .appName("streaming_consumer")
        .config("spark.jars.packages", SPARK_KAFKA_PKG)
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )


def event_schema():
    from pyspark.sql.types import (IntegerType, LongType, StringType,
                                   StructField, StructType)
    return StructType([
        StructField("timestamp", StringType()),
        StructField("ip_address", StringType()),
        StructField("method", StringType()),
        StructField("url", StringType()),
        StructField("status_code", IntegerType()),
        StructField("response_bytes", LongType()),
        StructField("user_agent", StringType()),
        StructField("referrer", StringType()),
        StructField("session_id", StringType()),
        StructField("attack_type", StringType()),
    ])


def _rolling_stats():
    """Mean/std of response_bytes across the buffered (5-minute) window."""
    total_n = sum(n for n, _, _ in _BASELINE)
    if total_n < 2:
        return 0.0, 0.0
    total_sum = sum(s for _, s, _ in _BASELINE)
    total_sq = sum(sq for _, _, sq in _BASELINE)
    mean = total_sum / total_n
    var = max(total_sq / total_n - mean * mean, 0.0)
    return mean, math.sqrt(var)


def process_batch(batch_df, batch_id: int) -> None:
    from pyspark.sql import functions as F

    if batch_df.rdd.isEmpty():
        print(f"Batch {batch_id}: processed 0 events, 0 alerts")
        return

    ua_low = F.lower(F.coalesce(F.col("user_agent"), F.lit("")))
    is_bot = F.lit(False)
    for tok in BOT_TOKENS:
        is_bot = is_bot | ua_low.contains(tok)

    url_low = F.lower(F.coalesce(F.col("url"), F.lit("")))
    suspicious = F.lit(False)
    for tok in SUSPICIOUS_TOKENS:
        suspicious = suspicious | url_low.contains(tok)

    enriched = (
        batch_df
        .withColumn("is_bot", is_bot)
        .withColumn("has_suspicious_params", suspicious.cast("int"))
    )

    # z-score of response size vs the rolling 5-minute baseline.
    mean, std = _rolling_stats()
    if std > 0:
        zexpr = (F.col("response_bytes") - F.lit(mean)) / F.lit(std)
    else:
        zexpr = F.lit(0.0)
    enriched = enriched.withColumn("resp_zscore", zexpr)
    enriched = enriched.withColumn("zscore_flag", F.abs(F.col("resp_zscore")) > 3.0)

    # Composite real-time threat score.
    enriched = enriched.withColumn(
        "threat_score",
        F.col("is_bot").cast("int") * 25
        + F.col("has_suspicious_params") * 25
        + F.col("zscore_flag").cast("int") * 30,
    )
    enriched = enriched.withColumn(
        "severity",
        F.when(F.col("threat_score") >= 75, "CRITICAL")
        .when(F.col("threat_score") >= 50, "HIGH")
        .when(F.col("threat_score") >= 25, "MEDIUM")
        .otherwise("NORMAL"),
    )

    alerts = enriched.filter(F.col("threat_score") >= 25).cache()

    total = enriched.count()
    by_sev = {r["severity"]: r["count"] for r in
              alerts.groupBy("severity").count().collect()}
    n_alerts = alerts.count()

    if n_alerts > 0:
        (alerts.select(
            "timestamp", "ip_address", "url", "status_code", "response_bytes",
            "is_bot", "has_suspicious_params", "zscore_flag",
            "threat_score", "severity", "attack_type")
         .write.mode("append").parquet(str(OUTPUT_DIR)))

    print(f"Batch {batch_id}: processed {total} events, {n_alerts} alerts "
          f"(CRITICAL: {by_sev.get('CRITICAL', 0)}, "
          f"HIGH: {by_sev.get('HIGH', 0)}, "
          f"MEDIUM: {by_sev.get('MEDIUM', 0)})")

    # Update the rolling baseline with this batch's response sizes.
    stats = enriched.select(
        F.count("response_bytes").alias("n"),
        F.sum("response_bytes").alias("s"),
        F.sum(F.col("response_bytes") * F.col("response_bytes")).alias("sq"),
    ).collect()[0]
    if stats["n"]:
        _BASELINE.append((stats["n"], float(stats["s"] or 0), float(stats["sq"] or 0)))
    alerts.unpersist()


def main() -> None:
    from pyspark.sql import functions as F

    spark = build_spark()
    spark.sparkContext.setLogLevel("WARN")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    raw = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "latest")
        .load()
    )
    parsed = (
        raw.select(
            F.from_json(F.col("value").cast("string"), event_schema()).alias("d"))
        .select("d.*")
        .filter(F.col("ip_address").isNotNull())
    )

    query = (
        parsed.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", str(CHECKPOINT_DIR))
        .trigger(processingTime="30 seconds")
        .start()
    )
    print(f"Streaming from topic '{TOPIC}' at {KAFKA_BOOTSTRAP} "
          f"(30s micro-batches). Alerts -> {OUTPUT_DIR}")
    query.awaitTermination()


if __name__ == "__main__":
    main()
