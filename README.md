# Web Application Security Log Anomaly Detector

A security-analytics pipeline that ingests web application access logs, engineers
10 behavioural features using PySpark window functions, and applies three
anomaly-detection methods — **Isolation Forest**, **Local Outlier Factor**, and a
**z-score statistical baseline** — to classify threats as CRITICAL, HIGH, or
MEDIUM severity. It runs as a batch pipeline over historical logs with results
stored on AWS S3 and queryable via Athena SQL, and as a real-time Kafka
streaming layer for continuous monitoring. It detects five attack patterns:
brute-force login, SQL-injection probes, bot/scraper activity, account-takeover
attempts, and data-exfiltration patterns.

> Built to mirror the day-to-day work of a security data-science / threat-detection
> team: ingest logs → engineer behavioural features → detect anomalies with ML →
> deliver real-time, severity-ranked alerts.

---

## Architecture

```
                Synthetic Nginx Logs (50,000 rows, labelled)
                                 |
                                 v
        ingest_logs.py  ──  PySpark + data-quality validation
                                 |
                                 v
   feature_engineering.py  ──  10 behavioural features (window functions)
                                 |
                                 v
   anomaly_detection.py  ──  Isolation Forest + LOF + z-score  →  threat score
                                 |
                                 v
   export_alerts.py  ──────────────────────────────►  S3  +  Athena SQL
                                                          |
                                                          v
                                            Lambda (alert triage on new file)

   ── PARALLEL real-time path ────────────────────────────────────────────────
   generate_logs.py --stream  ──►  Kafka topic `web_access_logs`
                                       |
                                       v
        streaming_consumer.py  ──  Spark Structured Streaming (30s micro-batch)
                                       |
                                       v
                          output/streaming_security_alerts/
```

All stages feed a **4-tab Streamlit dashboard** (`app.py`).

---

## Detection results (measured on the bundled dataset)

50,000 rows · 90% benign · 10% attacks (2% per type) · `contamination = 0.1`

| Attack pattern        | Detection rate (MEDIUM+) |
|-----------------------|--------------------------|
| Brute-force login     | **100.0%** |
| SQL-injection probes  | **100.0%** |
| Bot / scraper         | **100.0%** |
| Account takeover      | 77.1% |
| Data exfiltration     | 77.1% |
| **Overall (attacks)** | **90.8%** |
| False-positive rate (benign flagged) | 10.2% |

The composite score combines all three detectors, so volumetric attacks
(brute-force, scraping) and signature-like probes (SQLi) are caught with high
recall, while the subtler behavioural attacks (takeover, exfiltration) are
surfaced through sequential-access and session features. The ~10% false-positive
rate tracks the configured contamination and is the precision/recall lever for
a SOC to tune.

Reproduce with `python scripts/anomaly_detection.py`.

---

## Behavioural features (per IP, time-windowed)

Computed with `PARTITION BY ip_address ORDER BY timestamp` and
`RANGE BETWEEN INTERVAL … PRECEDING AND CURRENT ROW` frames:

| # | Feature | What it catches |
|---|---------|-----------------|
| 1 | `requests_per_minute` | volumetric floods, scraping |
| 2 | `post_login_rate` | brute-force login bursts |
| 3 | `error_rate_5min` | auth failures, probing |
| 4 | `unique_urls_per_hour` | enumeration / crawling |
| 5 | `avg_response_bytes_ratio` | data-exfiltration spikes |
| 6 | `request_interval_variance` | bot uniformity (low variance) |
| 7 | `is_offhours` | activity outside 07:00–22:00 |
| 8 | `sequential_url_score` | `/user/1 → /user/2 …` walking |
| 9 | `suspicious_param_rate` | SQLi / injection payloads |
| 10 | `new_session_flag` | session reuse from new context |

---

## Detection methods

- **Isolation Forest** — isolates anomalies by randomly partitioning the feature
  space; outliers require fewer splits.
- **Local Outlier Factor** — flags points whose local density is much lower than
  that of their k nearest neighbours.
- **Z-score baseline** — flags any of the 5 strongest features that exceed 3
  standard deviations from the population mean.

**Composite threat score (0–100):**

```
score = isolation_forest_flag*35 + lof_flag*35 + zscore_flag*20
        + is_bot*5 + (suspicious_param_rate > 0.5)*5
```

`CRITICAL ≥ 75 · HIGH ≥ 50 · MEDIUM ≥ 25 · NORMAL < 25`

---

## Repository structure

```
web-security-log-anomaly-detector/
├── data/
│   └── generate_logs.py         # synthetic log generator (+ Kafka producer)
├── scripts/
│   ├── ingest_logs.py           # parse + validate + data-quality report
│   ├── feature_engineering.py   # 10 behavioural features (window functions)
│   ├── anomaly_detection.py     # Isolation Forest + LOF + z-score + scoring
│   ├── export_alerts.py         # alert summary → S3 + Athena SQL
│   └── streaming_consumer.py    # Kafka → Spark Structured Streaming
├── aws/
│   ├── s3_handler.py            # S3 upload/list (LocalStack)
│   ├── athena_handler.py        # external table + analytical SQL
│   ├── lambda_handler.py        # S3-triggered alert triage
│   └── setup_lambda.py          # provision Lambda + S3 notification
├── app.py                       # 4-tab Streamlit threat dashboard
├── docker-compose.yml           # Kafka + Zookeeper + Kafka-UI + LocalStack
├── docker-compose.localstack.yml
└── requirements.txt
```

---

## Quickstart — batch pipeline (no infrastructure required)

The ingest and feature stages are **PySpark-first with a transparent pandas
fallback**, so the full batch pipeline runs on a plain Python environment (no JVM
or cluster needed). Install Spark + a JDK to exercise the PySpark path.

```bash
pip install -r requirements.txt

python data/generate_logs.py          # -> data/access_logs.{csv,parquet}
python scripts/ingest_logs.py         # -> data/processed/clean_logs/
python scripts/feature_engineering.py # -> data/processed/log_features/
python scripts/anomaly_detection.py   # -> data/output/security_alerts/ (+ eval)
python scripts/export_alerts.py       # alert summary + analytics
```

Then launch the dashboard:

```bash
streamlit run app.py
```

The repo ships with pre-computed outputs (`data/output/`), so the dashboard
renders immediately after cloning.

---

## Full stack — Kafka streaming + AWS (LocalStack)

```bash
docker compose up -d        # Kafka :9092 · Kafka-UI :8090 · LocalStack :4566

# Real-time path
python data/generate_logs.py --stream      # producer: 1 event / 0.2s
python scripts/streaming_consumer.py       # Spark Structured Streaming consumer

# AWS path
export AWS_ENDPOINT_URL=http://localhost:4566
python aws/s3_handler.py                    # create buckets
python scripts/export_alerts.py             # upload alerts + raw logs to S3
python aws/setup_lambda.py                  # deploy S3-triggered triage Lambda
```

The streaming consumer needs the Spark Kafka connector; it is requested
automatically via `spark.jars.packages`, or run with
`spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1`.

> **LocalStack note:** Athena is a LocalStack Pro feature, so `export_alerts.py`
> falls back to computing the same three queries with pandas on the community
> edition. The Lambda Parquet read requires `pyarrow` (ship it as a layer in
> real AWS).

---

## Dashboard

| Tab | Contents |
|-----|----------|
| **Log Overview** | volume KPIs, requests-over-time, status-code mix, top talkers |
| **Threat Alerts** | severity-filtered alert queue, attack breakdown, detection rates vs ground truth |
| **ML Model Comparison** | per-detector detections / false-positives / recall, IF-vs-LOF scatter |
| **Real-Time Stream** | live streaming-alert counter, last 20 alerts, events/sec |

---

## Tech stack

PySpark (batch + Structured Streaming) · scikit-learn (Isolation Forest, LOF) ·
Kafka (Confluent 7.6) · AWS S3 / Athena / Lambda via LocalStack · pandas ·
Streamlit + Plotly · Docker Compose.
