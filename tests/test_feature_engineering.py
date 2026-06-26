"""Tests for the pandas-fallback behavioural feature engineering.

``_features_for_ip`` computes the 10 per-IP windowed features that the PySpark
implementation produces. Using a single IP with hand-placed timestamps lets us
assert exact, deterministic values for each window function.
"""
import numpy as np
import pandas as pd
import pytest

from scripts import feature_engineering as fe


@pytest.mark.parametrize(
    "url,expected",
    [
        ("/products/123", 123.0),
        ("/42", 42.0),
        ("/login", None),
        ("/products/abc", None),
        ("", None),
        (None, None),
    ],
)
def test_trailing_num(url, expected):
    result = fe._trailing_num(url)
    if expected is None:
        assert np.isnan(result)
    else:
        assert result == expected


@pytest.fixture
def single_ip_frame():
    """Four requests from one IP at +0s, +30s, +45s, +120s.

    Columns mirror what ``run_pandas`` prepares before calling
    ``_features_for_ip``.
    """
    base = pd.Timestamp("2026-01-01 10:00:00")
    times = [base, base + pd.Timedelta("30s"), base + pd.Timedelta("45s"),
             base + pd.Timedelta("120s")]
    df = pd.DataFrame(
        {
            "ip_address": ["10.0.0.1"] * 4,
            "event_time": times,
            "base_url": ["/login", "/login", "/products/5", "/products/6"],
            "method": ["POST", "POST", "GET", "GET"],
            "status_code": [200, 401, 200, 500],
            "response_bytes": [100, 100, 100, 400],
            "has_suspicious_params": [0, 0, 1, 1],
            "session_id": ["A", "A", "B", "A"],
        }
    )
    # Derived helper columns added by run_pandas prior to the per-IP call.
    df["post_login_flag"] = (
        (df["base_url"] == "/login") & (df["method"] == "POST")
    ).astype(int)
    df["error_flag"] = (df["status_code"] >= 400).astype(float)
    df["one"] = 1
    df["url_num"] = df["base_url"].map(fe._trailing_num)
    return df


@pytest.fixture
def features(single_ip_frame):
    return fe._features_for_ip(single_ip_frame.copy(), np, pd)


def test_requests_per_minute_trailing_window(features):
    # +0s:1, +30s:2 (r0,r1), +45s:3 (r0,r1,r2), +120s:1 (only r3 within 60s).
    assert features["requests_per_minute"].tolist() == [1, 2, 3, 1]


def test_post_login_rate_trailing_5min(features):
    # Two POST /login requests, both within the trailing 5-minute window.
    assert features["post_login_rate"].iloc[-1] == 2


def test_error_rate_5min(features):
    # error_flags = [0, 1, 0, 1] all inside the 5-minute window -> mean 0.5.
    assert features["error_rate_5min"].iloc[-1] == pytest.approx(0.5)


def test_unique_urls_per_hour(features):
    # Distinct base URLs accumulate: /login, /products/5, /products/6 -> 3.
    assert features["unique_urls_per_hour"].iloc[-1] == 3


def test_avg_response_bytes_ratio_detects_spike(features):
    # Last request is 400 bytes vs a trailing-hour mean of 175 -> ~2.29x.
    assert features["avg_response_bytes_ratio"].iloc[-1] == pytest.approx(400 / 175, rel=1e-6)


def test_sequential_url_score(features):
    # url ids 10? no -> here ids are 5,6 from /products; /login -> NaN.
    # Sequence: NaN, NaN(/login), 5, 6 -> only 6 follows 5 by +1.
    assert features["sequential_url_score"].tolist() == [0.0, 0.0, 0.0, 1.0]


def test_request_interval_variance(features):
    # Inter-request gaps = [30, 15, 75] seconds; sample variance = 975.
    assert features["request_interval_variance"].iloc[0] == pytest.approx(975.0)


def test_new_session_flag(features):
    # Sessions A,A,B,A: first sighting of A and B -> 1; repeats within 24h -> 0.
    assert features["new_session_flag"].tolist() == [1, 0, 1, 0]


def test_all_feature_columns_present(features):
    for col in fe.FEATURE_COLUMNS:
        if col == "is_offhours":
            continue  # added by run_pandas after the per-IP pass
        assert col in features.columns
