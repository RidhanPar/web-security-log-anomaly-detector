"""
Web Application Security Log Anomaly Detector - Streamlit threat dashboard.

Four tabs:
  1. Log Overview        - traffic volume, status mix, top talkers
  2. Threat Alerts       - severity-filtered alert queue + detection rates
  3. ML Model Comparison - Isolation Forest vs LOF vs Z-score vs Composite
  4. Real-Time Stream    - live view of the Kafka streaming alerts

Run:
    streamlit run app.py
"""
from __future__ import annotations

import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent
SCORED_DIR = ROOT / "data" / "output" / "scored_logs"
ALERTS_DIR = ROOT / "data" / "output" / "security_alerts"
STREAM_DIR = ROOT / "output" / "streaming_security_alerts"

ATTACK_TYPES = [
    "brute_force", "sql_injection", "bot_scraper",
    "account_takeover", "data_exfiltration",
]
SEVERITY_COLORS = {
    "CRITICAL": "#b00020", "HIGH": "#e65100",
    "MEDIUM": "#f9a825", "NORMAL": "#2e7d32",
}

st.set_page_config(page_title="Security Log Anomaly Detector",
                   page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #
@st.cache_data(show_spinner=False)
def load_parquet_dir(path: str) -> pd.DataFrame | None:
    p = Path(path)
    if not p.exists() or not any(p.glob("*.parquet")):
        return None
    df = pd.read_parquet(p)
    if "event_time" in df.columns:
        df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    elif "timestamp" in df.columns:
        df["event_time"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def load_stream() -> pd.DataFrame | None:
    # Not cached: this view is meant to update as new micro-batches land.
    if not STREAM_DIR.exists() or not any(STREAM_DIR.glob("**/*.parquet")):
        return None
    return pd.read_parquet(STREAM_DIR)


# --------------------------------------------------------------------------- #
# Tab 1 - Log Overview
# --------------------------------------------------------------------------- #
def tab_overview(scored: pd.DataFrame) -> None:
    total = len(scored)
    flagged = int((scored["threat_score"] >= 25).sum())
    anomaly_rate = flagged / total * 100 if total else 0
    detected_types = scored.loc[scored["threat_score"] >= 25, "attack_type"]
    n_types = detected_types[detected_types != "normal"].nunique()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total logs processed", f"{total:,}")
    c2.metric("Anomaly rate", f"{anomaly_rate:.1f}%")
    c3.metric("Unique IPs", f"{scored['ip_address'].nunique():,}")
    c4.metric("Attack types detected", f"{n_types} / {len(ATTACK_TYPES)}")

    st.divider()
    left, right = st.columns([2, 1])

    with left:
        st.subheader("Requests over time")
        ts = scored.dropna(subset=["event_time"]).copy()
        ts["hour"] = ts["event_time"].dt.floor("h")
        series = ts.groupby("hour").size().reset_index(name="requests")
        fig = px.line(series, x="hour", y="requests")
        fig.update_layout(height=320, margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("HTTP status codes")
        status = scored["status_code"].value_counts().reset_index()
        status.columns = ["status_code", "count"]
        status["status_code"] = status["status_code"].astype(str)
        fig = px.pie(status, names="status_code", values="count", hole=0.45)
        fig.update_layout(height=320, margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top 10 IPs by request count")
    top_ips = (scored["ip_address"].value_counts().head(10)
               .reset_index())
    top_ips.columns = ["ip_address", "requests"]
    fig = px.bar(top_ips, x="requests", y="ip_address", orientation="h")
    fig.update_layout(height=360, yaxis=dict(autorange="reversed"),
                      margin=dict(t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)


# --------------------------------------------------------------------------- #
# Tab 2 - Threat Alerts
# --------------------------------------------------------------------------- #
def _style_severity(row):
    color = SEVERITY_COLORS.get(row["severity"], "#444")
    return [f"background-color: {color}; color: white"
            if col == "severity" else "" for col in row.index]


def tab_alerts(scored: pd.DataFrame, alerts: pd.DataFrame) -> None:
    choice = st.selectbox("Severity filter",
                          ["ALL", "CRITICAL", "HIGH", "MEDIUM"])
    view = alerts if choice == "ALL" else alerts[alerts["severity"] == choice]

    st.caption(f"{len(view):,} alerts")
    cols = ["ip_address", "threat_score", "severity", "top_flag", "timestamp"]
    cols = [c for c in cols if c in view.columns]
    table = view.sort_values("threat_score", ascending=False)[cols].head(500)
    st.dataframe(table.style.apply(_style_severity, axis=1),
                 use_container_width=True, height=360)

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by attack type")
        breakdown = (view["attack_type"].value_counts().reset_index())
        breakdown.columns = ["attack_type", "count"]
        fig = px.bar(breakdown, x="attack_type", y="count", color="attack_type")
        fig.update_layout(height=340, showlegend=False, margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Detection rate vs ground truth")
        flagged = scored["threat_score"] >= 25
        rows = []
        for atk in ATTACK_TYPES:
            sub = scored[scored["attack_type"] == atk]
            if len(sub):
                rows.append({"attack_type": atk,
                             "detection_rate": flagged[sub.index].mean() * 100})
        rate_df = pd.DataFrame(rows)
        fig = px.bar(rate_df, x="detection_rate", y="attack_type",
                     orientation="h", range_x=[0, 100],
                     text=rate_df["detection_rate"].round(1))
        fig.update_layout(height=340, yaxis=dict(autorange="reversed"),
                          margin=dict(t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)


# --------------------------------------------------------------------------- #
# Tab 3 - ML Model Comparison
# --------------------------------------------------------------------------- #
def tab_models(scored: pd.DataFrame) -> None:
    is_attack = scored["attack_type"] != "normal"
    n_attacks = int(is_attack.sum())

    def stats(flag: pd.Series) -> dict:
        detections = int(flag.sum())
        false_pos = int((flag & ~is_attack).sum())
        true_pos = int((flag & is_attack).sum())
        rate = true_pos / n_attacks * 100 if n_attacks else 0
        return {"Detections": detections, "False Positives": false_pos,
                "Detection Rate": f"{rate:.1f}%"}

    table = pd.DataFrame({
        "Isolation Forest": stats(scored["isolation_forest_flag"]),
        "Local Outlier Factor": stats(scored["lof_flag"]),
        "Z-Score Baseline": stats(scored["zscore_flag"]),
        "Composite (Combined)": stats(scored["threat_score"] >= 25),
    }).T
    st.subheader("Detector comparison")
    st.dataframe(table, use_container_width=True)

    st.subheader("Isolation Forest vs LOF score")
    sample = scored.sample(min(6000, len(scored)), random_state=1)
    fig = px.scatter(
        sample, x="isolation_forest_score", y="lof_score",
        color="attack_type", opacity=0.6,
        labels={"isolation_forest_score": "Isolation Forest score (lower = anomalous)",
                "lof_score": "LOF score (lower = anomalous)"},
    )
    fig.update_layout(height=420, margin=dict(t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)

    st.info("**Isolation Forest:** isolates anomalies by randomly partitioning "
            "data - outliers require fewer splits.")
    st.info("**Local Outlier Factor:** flags points whose local density is much "
            "lower than their neighbours.")
    st.info("**Z-Score:** flags values more than 3 standard deviations from the "
            "population mean.")


# --------------------------------------------------------------------------- #
# Tab 4 - Real-Time Stream
# --------------------------------------------------------------------------- #
def tab_stream() -> None:
    auto = st.checkbox("Auto-refresh every 5s", value=False)
    placeholder = st.empty()

    with placeholder.container():
        stream = load_stream()
        if stream is None:
            st.warning(
                "No streaming alerts yet. Start the producer and consumer:\n\n"
                "```\npython data/generate_logs.py --stream\n"
                "python scripts/streaming_consumer.py\n```"
            )
            return

        if "event_time" not in stream.columns and "timestamp" in stream.columns:
            stream["event_time"] = pd.to_datetime(stream["timestamp"],
                                                  errors="coerce")

        c1, c2, c3 = st.columns(3)
        c1.metric("Streaming alerts", f"{len(stream):,}")
        crit = int((stream.get("severity") == "CRITICAL").sum())
        c2.metric("Critical", f"{crit:,}")
        span = 1.0
        if "event_time" in stream.columns and stream["event_time"].notna().any():
            span = max((stream["event_time"].max()
                        - stream["event_time"].min()).total_seconds(), 1.0)
        c3.metric("Alerts / sec", f"{len(stream) / span:.2f}")

        st.subheader("Last 20 streaming alerts")
        cols = [c for c in ["timestamp", "ip_address", "url", "threat_score",
                            "severity", "attack_type"] if c in stream.columns]
        st.dataframe(stream.tail(20)[cols].iloc[::-1],
                     use_container_width=True, height=360)

    if auto:
        time.sleep(5)
        st.rerun()


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    st.title("🛡️ Web Application Security Log Anomaly Detector")
    st.caption("Isolation Forest · Local Outlier Factor · Z-score baseline "
               "· real-time Kafka streaming")

    scored = load_parquet_dir(str(SCORED_DIR))
    alerts = load_parquet_dir(str(ALERTS_DIR))

    if scored is None:
        st.error(
            "No scored data found. Run the batch pipeline first:\n\n"
            "```\npython data/generate_logs.py\n"
            "python scripts/ingest_logs.py\n"
            "python scripts/feature_engineering.py\n"
            "python scripts/anomaly_detection.py\n```"
        )
        return
    if alerts is None:
        alerts = scored[scored["threat_score"] >= 25].copy()

    t1, t2, t3, t4 = st.tabs(
        ["Log Overview", "Threat Alerts", "ML Model Comparison", "Real-Time Stream"]
    )
    with t1:
        tab_overview(scored)
    with t2:
        tab_alerts(scored, alerts)
    with t3:
        tab_models(scored)
    with t4:
        tab_stream()


if __name__ == "__main__":
    main()
