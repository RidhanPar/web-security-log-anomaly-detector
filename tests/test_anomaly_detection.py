"""Tests for the anomaly-detection / threat-scoring stage.

``detect`` fits Isolation Forest + LOF + a z-score baseline and combines them
into a 0-100 composite score. The model internals are random, so these tests
assert the *contract* that holds regardless of the fitted models: the additive
score formula, the score bounds, and the severity bucketing.
"""
import numpy as np
import pandas as pd
import pytest

from scripts import anomaly_detection as ad


@pytest.fixture
def scored():
    """A feature matrix with a dense normal cluster plus a few clear outliers."""
    rng = np.random.default_rng(7)
    n_normal, n_outlier = 80, 8

    normal = pd.DataFrame(
        {col: rng.normal(1.0, 0.1, n_normal) for col in ad.FEATURE_COLUMNS}
    )
    normal["is_offhours"] = 0
    normal["suspicious_param_rate"] = rng.uniform(0.0, 0.1, n_normal)
    normal["is_bot"] = 0
    normal["attack_type"] = "normal"

    outlier = pd.DataFrame(
        {col: rng.normal(20.0, 1.0, n_outlier) for col in ad.FEATURE_COLUMNS}
    )
    outlier["is_offhours"] = 1
    outlier["suspicious_param_rate"] = rng.uniform(0.8, 1.0, n_outlier)
    outlier["is_bot"] = 1
    outlier["attack_type"] = "brute_force"

    df = pd.concat([normal, outlier], ignore_index=True)
    return ad.detect(df)


def test_threat_score_matches_additive_formula(scored):
    expected = (
        scored["isolation_forest_flag"].astype(int) * 35
        + scored["lof_flag"].astype(int) * 35
        + scored["zscore_flag"].astype(int) * 20
        + scored["is_bot"].astype(int) * 5
        + (scored["suspicious_param_rate"] > 0.5).astype(int) * 5
    )
    pd.testing.assert_series_equal(
        scored["threat_score"], expected, check_names=False
    )


def test_threat_score_within_bounds(scored):
    assert scored["threat_score"].between(0, 100).all()


def test_severity_labels_are_valid(scored):
    assert set(scored["severity"]).issubset(
        {"NORMAL", "MEDIUM", "HIGH", "CRITICAL"}
    )


def test_severity_bucketing_follows_thresholds(scored):
    # Bins: [-1,24]=NORMAL, [25,49]=MEDIUM, [50,74]=HIGH, [75,100]=CRITICAL.
    for _, row in scored.iterrows():
        ts = row["threat_score"]
        if ts <= 24:
            assert row["severity"] == "NORMAL"
        elif ts <= 49:
            assert row["severity"] == "MEDIUM"
        elif ts <= 74:
            assert row["severity"] == "HIGH"
        else:
            assert row["severity"] == "CRITICAL"


def test_detector_flags_some_outliers(scored):
    # With an obvious outlier cluster, at least one row should reach MEDIUM+.
    assert (scored["threat_score"] >= 25).any()


def test_detect_adds_all_expected_columns(scored):
    for col in [
        "isolation_forest_flag", "lof_flag", "zscore_flag",
        "max_zscore", "threat_score", "severity",
    ]:
        assert col in scored.columns
