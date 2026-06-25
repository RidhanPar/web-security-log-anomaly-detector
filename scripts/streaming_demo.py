"""
No-infrastructure streaming demo.

Simulates the real-time layer (``streaming_consumer.py``) without needing Kafka,
Spark or Java. It replays the detected alerts as live micro-batches, writing one
Parquet file per batch into ``output/streaming_security_alerts/`` with fresh
timestamps, so the dashboard's "Real-Time Stream" tab populates and updates.

Use this when you just want to see the streaming tab working locally. For the
genuine Kafka + Spark Structured Streaming path, use ``generate_logs.py --stream``
plus ``streaming_consumer.py`` instead.

Run (in a separate terminal from ``streamlit run app.py``):
    python scripts/streaming_demo.py                 # continuous, 3s batches
    python scripts/streaming_demo.py --interval 1.5  # faster
    python scripts/streaming_demo.py --reset         # clear previous demo data
"""
from __future__ import annotations

import argparse
import shutil
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
SCORED_DIR = ROOT / "data" / "output" / "scored_logs"
ALERTS_DIR = ROOT / "data" / "output" / "security_alerts"
STREAM_DIR = ROOT / "output" / "streaming_security_alerts"

STREAM_COLUMNS = [
    "timestamp", "ip_address", "url", "status_code", "response_bytes",
    "is_bot", "has_suspicious_params", "zscore_flag",
    "threat_score", "severity", "attack_type",
]


def load_alert_pool() -> pd.DataFrame:
    src = ALERTS_DIR if ALERTS_DIR.exists() else SCORED_DIR
    if not src.exists() or not any(src.glob("*.parquet")):
        raise SystemExit(
            "No alert data found. Run the batch pipeline first "
            "(python scripts/anomaly_detection.py)."
        )
    df = pd.read_parquet(src)
    df = df[df["threat_score"] >= 25].copy()
    keep = [c for c in STREAM_COLUMNS if c in df.columns]
    return df[keep].reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="No-infra streaming demo")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="seconds between micro-batches")
    parser.add_argument("--batch-size", type=int, default=8,
                        help="alerts emitted per batch")
    parser.add_argument("--batches", type=int, default=0,
                        help="number of batches (0 = run until Ctrl-C)")
    parser.add_argument("--reset", action="store_true",
                        help="clear previous demo output before starting")
    args = parser.parse_args()

    if args.reset and STREAM_DIR.exists():
        shutil.rmtree(STREAM_DIR)
    STREAM_DIR.mkdir(parents=True, exist_ok=True)

    pool = load_alert_pool()
    rng = np.random.default_rng()
    print(f"[demo] Replaying {len(pool):,} alerts as live micro-batches "
          f"-> {STREAM_DIR}")
    print("[demo] Open the dashboard's 'Real-Time Stream' tab "
          "(tick Auto-refresh). Ctrl-C to stop.\n")

    batch_id = 0
    try:
        while args.batches == 0 or batch_id < args.batches:
            chunk = pool.sample(min(args.batch_size, len(pool))).copy()
            chunk["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

            out = STREAM_DIR / f"batch_{batch_id:05d}.parquet"
            chunk.to_parquet(out, index=False)

            sev = chunk["severity"].value_counts()
            print(f"Batch {batch_id}: processed {len(chunk)} events, "
                  f"{len(chunk)} alerts "
                  f"(CRITICAL: {int(sev.get('CRITICAL', 0))}, "
                  f"HIGH: {int(sev.get('HIGH', 0))}, "
                  f"MEDIUM: {int(sev.get('MEDIUM', 0))})")

            batch_id += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[demo] Stopped after {batch_id} batches.")


if __name__ == "__main__":
    main()
