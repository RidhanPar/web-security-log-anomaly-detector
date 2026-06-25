"""
Stage 3 - Anomaly detection & threat scoring.

Applies three complementary detectors to the 10-feature behavioural matrix and
combines them into a single 0-100 threat score:

  * Isolation Forest  - tree-based isolation of multivariate outliers
  * Local Outlier Factor - local-density deviation vs. k nearest neighbours
  * Z-score baseline  - univariate 3-sigma rule on the 5 strongest features

The composite score is bucketed into CRITICAL / HIGH / MEDIUM / NORMAL. Results
are evaluated against the ``attack_type`` ground-truth column and alerts
(threat_score >= 25) are written to ``data/output/security_alerts/``.

Run:
    python scripts/anomaly_detection.py
"""
from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
FEATURES_DIR = ROOT / "data" / "processed" / "log_features"
ALERTS_DIR = ROOT / "data" / "output" / "security_alerts"
SCORED_DIR = ROOT / "data" / "output" / "scored_logs"

FEATURE_COLUMNS = [
    "requests_per_minute", "post_login_rate", "error_rate_5min",
    "unique_urls_per_hour", "avg_response_bytes_ratio",
    "request_interval_variance", "is_offhours", "sequential_url_score",
    "suspicious_param_rate", "new_session_flag",
]

# The five most discriminating features for the statistical baseline.
ZSCORE_FEATURES = [
    "requests_per_minute", "post_login_rate", "error_rate_5min",
    "avg_response_bytes_ratio", "suspicious_param_rate",
]

CONTAMINATION = 0.1
RANDOM_STATE = 42


def _clean_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def load_features() -> pd.DataFrame:
    if not FEATURES_DIR.exists():
        raise SystemExit(
            "Feature data not found. Run `python scripts/feature_engineering.py` first."
        )
    df = pd.read_parquet(FEATURES_DIR)
    # Guard against NaN/inf produced by ratio/variance features.
    df[FEATURE_COLUMNS] = (
        df[FEATURE_COLUMNS]
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
        .astype(float)
    )
    return df


def detect(df: pd.DataFrame) -> pd.DataFrame:
    X = df[FEATURE_COLUMNS].to_numpy()
    X_scaled = StandardScaler().fit_transform(X)

    # --- Method 1: Isolation Forest ------------------------------------ #
    print("[detect] Fitting Isolation Forest...")
    iso = IsolationForest(
        contamination=CONTAMINATION, random_state=RANDOM_STATE, n_jobs=-1
    )
    iso_pred = iso.fit_predict(X_scaled)
    df["isolation_forest_score"] = iso.decision_function(X_scaled)
    df["isolation_forest_flag"] = iso_pred == -1

    # --- Method 2: Local Outlier Factor -------------------------------- #
    print("[detect] Fitting Local Outlier Factor...")
    lof = LocalOutlierFactor(
        n_neighbors=20, contamination=CONTAMINATION, novelty=False, n_jobs=-1
    )
    lof_pred = lof.fit_predict(X_scaled)
    df["lof_flag"] = lof_pred == -1
    df["lof_score"] = lof.negative_outlier_factor_

    # --- Method 3: Z-score statistical baseline ------------------------ #
    print("[detect] Computing z-score baseline...")
    zscores = pd.DataFrame(index=df.index)
    for col in ZSCORE_FEATURES:
        mean, std = df[col].mean(), df[col].std(ddof=0)
        zscores[col] = 0.0 if std == 0 else (df[col] - mean) / std
    abs_z = zscores.abs()
    df["max_zscore"] = abs_z.max(axis=1)
    df["zscore_flag"] = (abs_z > 3.0).any(axis=1)
    # Most anomalous single dimension (useful as an analyst-facing reason).
    df["top_flag"] = abs_z.idxmax(axis=1).where(df["zscore_flag"], "ml_pattern")

    # --- Composite threat score (0-100) -------------------------------- #
    is_bot = df["is_bot"].astype(int)
    susp_gt_half = (df["suspicious_param_rate"] > 0.5).astype(int)
    df["threat_score"] = (
        df["isolation_forest_flag"].astype(int) * 35
        + df["lof_flag"].astype(int) * 35
        + df["zscore_flag"].astype(int) * 20
        + is_bot * 5
        + susp_gt_half * 5
    )

    df["severity"] = pd.cut(
        df["threat_score"],
        bins=[-1, 24, 49, 74, 100],
        labels=["NORMAL", "MEDIUM", "HIGH", "CRITICAL"],
    ).astype(str)
    return df


def evaluate(df: pd.DataFrame) -> None:
    """Detection rate per attack type and the overall false-positive rate."""
    flagged = df["threat_score"] >= 25  # MEDIUM or above

    print("\n" + "=" * 60)
    print(" DETECTION EVALUATION (vs. ground truth)")
    print("=" * 60)
    print(f" {'attack_type':<20}{'rows':>8}{'flagged':>10}{'detect %':>11}")
    print(" " + "-" * 57)
    for attack in sorted(df["attack_type"].unique()):
        if attack == "normal":
            continue
        sub = df[df["attack_type"] == attack]
        rate = flagged[sub.index].mean() * 100
        print(f" {attack:<20}{len(sub):>8,}{int(flagged[sub.index].sum()):>10,}"
              f"{rate:>10.1f}%")

    normal = df[df["attack_type"] == "normal"]
    fp_rate = flagged[normal.index].mean() * 100
    overall = flagged[df["attack_type"] != "normal"]
    print(" " + "-" * 57)
    print(f" {'ATTACK (overall)':<20}{len(overall):>8,}"
          f"{int(overall.sum()):>10,}{overall.mean() * 100:>10.1f}%")
    print(f" {'FALSE POSITIVES':<20}{len(normal):>8,}"
          f"{int(flagged[normal.index].sum()):>10,}{fp_rate:>10.1f}%")
    print("=" * 60)

    # Per-method contribution.
    print("\n Per-method flags (count):")
    for name, col in [("Isolation Forest", "isolation_forest_flag"),
                      ("Local Outlier Factor", "lof_flag"),
                      ("Z-Score Baseline", "zscore_flag")]:
        print(f"   {name:<22}: {int(df[col].sum()):>6,}")

    print("\n Severity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "NORMAL"]:
        print(f"   {sev:<10}: {int((df['severity'] == sev).sum()):>6,}")
    print()


def write_outputs(df: pd.DataFrame) -> None:
    # Full scored dataset (used by the dashboard's overview & model tabs).
    _clean_output_dir(SCORED_DIR)
    df.to_parquet(SCORED_DIR / "part-00000.parquet", index=False)

    # Alert subset (threat_score >= 25).
    alerts = df[df["threat_score"] >= 25].copy()
    alerts = alerts.sort_values("threat_score", ascending=False)
    _clean_output_dir(ALERTS_DIR)
    alerts.to_parquet(ALERTS_DIR / "part-00000.parquet", index=False)

    print(f"[detect] Scored dataset ({len(df):,} rows) -> {SCORED_DIR}")
    print(f"[detect] Alerts ({len(alerts):,} rows, threat_score>=25) -> {ALERTS_DIR}")


def main() -> None:
    df = load_features()
    print(f"[detect] Loaded {len(df):,} feature rows.")
    df = detect(df)
    evaluate(df)
    write_outputs(df)


if __name__ == "__main__":
    main()
