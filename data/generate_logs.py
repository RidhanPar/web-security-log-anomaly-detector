"""
Synthetic Nginx access-log generator for the Web Security Log Anomaly Detector.

Produces 50,000 web access-log rows: ~90% benign traffic plus five injected
attack patterns (brute force, SQL injection, bot/scraper, account takeover and
data exfiltration). Each row carries a ground-truth ``attack_type`` label so the
downstream anomaly-detection stage can be evaluated.

Output is written to ``data/access_logs.csv`` and ``data/access_logs.parquet``.
The module also exposes a small Kafka producer (``--stream``) used by the
real-time streaming layer.

Usage
-----
    python data/generate_logs.py                       # write CSV + Parquet
    python data/generate_logs.py --rows 100000         # custom volume
    python data/generate_logs.py --stream              # stream to Kafka
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
RANDOM_SEED = 42

HERE = Path(__file__).resolve().parent          # .../data
ROOT = HERE.parent                              # repo root
CSV_PATH = HERE / "access_logs.csv"
PARQUET_PATH = HERE / "access_logs.parquet"

TOTAL_ROWS = 50_000
ATTACK_FRACTION_EACH = 0.02                     # 2% per attack type -> 10% total

ATTACK_TYPES = [
    "brute_force",
    "sql_injection",
    "bot_scraper",
    "account_takeover",
    "data_exfiltration",
]

# 7-day observation window (fixed end date keeps the dataset reproducible).
WINDOW_DAYS = 7
END_DATE = datetime(2026, 6, 26, 0, 0, 0)
START_DATE = END_DATE - timedelta(days=WINDOW_DAYS)

COLUMNS = [
    "timestamp",
    "ip_address",
    "method",
    "url",
    "status_code",
    "response_bytes",
    "user_agent",
    "referrer",
    "session_id",
    "attack_type",
]

# --------------------------------------------------------------------------- #
# Reference pools
# --------------------------------------------------------------------------- #
# Realistic application paths for benign traffic.
URLS = [
    "/login", "/logout", "/dashboard", "/home", "/about", "/contact",
    "/pricing", "/help", "/support", "/faq", "/blog", "/blog/post",
    "/account", "/account/settings", "/favicon.ico", "/robots.txt",
    "/sitemap.xml", "/static/css/main.css", "/static/js/app.js",
    "/api/v1/user", "/api/v1/users", "/api/v1/user/profile",
    "/api/v1/user/settings", "/api/v1/orders", "/api/v1/order",
    "/api/v1/search", "/api/v1/products", "/api/v1/product",
    "/api/v1/cart", "/api/v1/checkout", "/api/v1/payment",
    "/api/v1/payment/methods", "/api/v1/notifications", "/api/v1/messages",
    "/api/v1/auth/refresh", "/api/v1/auth/token", "/api/v1/reports",
    "/api/v1/analytics", "/api/v1/export", "/api/v1/download",
    "/api/v1/upload", "/api/v1/admin", "/api/v1/admin/users",
    "/api/v1/health", "/api/v1/status", "/api/v1/metrics",
    "/api/v1/config", "/api/v1/feedback", "/api/v1/subscribe",
    "/api/v1/unsubscribe",
]

# 20 genuine browser user-agent strings.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

# Automated-client user agents (used by the bot/scraper pattern + bot detection).
BOT_USER_AGENTS = [
    "python-requests/2.28.0",
    "curl/7.68.0",
    "Wget/1.20.3 (linux-gnu)",
    "Scrapy/2.8.0 (+https://scrapy.org)",
    "Go-http-client/2.0",
]

# Tooling/odd user agents that accompany SQL-injection probes.
SUSPICIOUS_USER_AGENTS = [
    "sqlmap/1.6.12#stable (https://sqlmap.org)",
    "Mozilla/5.0 zgrab/0.x",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "-",
]

REFERRERS = [
    "https://www.google.com/",
    "https://example.com/home",
    "https://example.com/dashboard",
    "https://example.com/login",
    "https://t.co/shortlink",
    "https://www.bing.com/",
    "-",
]

# SQL-injection URL payloads (kept human-readable so the suspicious-param
# detector can match on the canonical tokens).
INJECTION_PAYLOADS = [
    "/api/v1/user?id=1 OR 1=1",
    "/api/v1/product?id=1' OR '1'='1",
    "/api/v1/search?q=1 UNION SELECT username,password FROM users",
    "/api/v1/orders?id=1; DROP TABLE users",
    "/api/v1/user?id=1 UNION SELECT NULL,NULL,version()",
    "/login?user=admin'--",
    "/api/v1/product?id=1 AND SLEEP(5)",
    "/api/v1/search?q='; EXEC xp_cmdshell('whoami')--",
    "/api/v1/user?id=-1 UNION SELECT table_name FROM information_schema.tables",
    "/api/v1/order?id=1 OR 1=1 LIMIT 1",
]

# Five specific attacker IPs for the brute-force pattern (look like Tor/bad ranges).
ATTACKER_IPS = [
    "45.131.66.12",
    "185.220.101.7",
    "193.32.162.45",
    "91.219.236.18",
    "23.129.64.99",
]

# Dedicated bot/scraper source IPs.
BOT_IPS = [
    "104.244.78.231",
    "159.203.45.180",
    "167.71.13.196",
    "138.197.92.44",
    "165.227.103.55",
]


def _make_ip_pool(n: int, rng: np.random.Generator) -> list[str]:
    """Build a pool of ``n`` unique pseudo-random IPv4 addresses."""
    ips: set[str] = set()
    while len(ips) < n:
        octets = rng.integers(1, 254, size=4)
        ips.add(".".join(map(str, octets)))
    return sorted(ips)


def _hour_weights() -> np.ndarray:
    """Daily traffic curve weighted toward business hours (09:00-18:00)."""
    weights = np.full(24, 0.25)
    weights[7:9] = 0.6
    weights[9:18] = 1.0
    weights[18:22] = 0.6
    return weights / weights.sum()


HOUR_WEIGHTS = _hour_weights()


def _random_timestamp(rng: np.random.Generator) -> datetime:
    """Sample a timestamp in the 7-day window with a business-hours peak."""
    day = int(rng.integers(0, WINDOW_DAYS))
    hour = int(rng.choice(24, p=HOUR_WEIGHTS))
    return START_DATE + timedelta(
        days=day,
        hours=hour,
        minutes=int(rng.integers(0, 60)),
        seconds=int(rng.integers(0, 60)),
        microseconds=int(rng.integers(0, 1_000_000)),
    )


def _ts(dt: datetime) -> str:
    """Render a timestamp as an ISO-style string with microseconds."""
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def _row(dt, ip, method, url, status, rbytes, ua, referrer, session, attack):
    return {
        "timestamp": _ts(dt),
        "ip_address": ip,
        "method": method,
        "url": url,
        "status_code": int(status),
        "response_bytes": int(max(rbytes, 0)),
        "user_agent": ua,
        "referrer": referrer,
        "session_id": session,
        "attack_type": attack,
    }


def _session_id(rng: np.random.Generator) -> str:
    return "sess_" + "".join(rng.choice(list("0123456789abcdef"), size=16))


# --------------------------------------------------------------------------- #
# Traffic generators
# --------------------------------------------------------------------------- #
def gen_normal(n, rng, ip_pool, session_pool):
    methods = np.array(["GET", "POST", "DELETE"])
    method_p = [0.70, 0.25, 0.05]
    statuses = np.array([200, 201, 302, 404])
    status_p = [0.75, 0.10, 0.10, 0.05]

    rows = []
    for _ in range(n):
        status = int(rng.choice(statuses, p=status_p))
        rbytes = int(rng.normal(5000, 2000))
        rows.append(
            _row(
                _random_timestamp(rng),
                rng.choice(ip_pool),
                rng.choice(methods, p=method_p),
                rng.choice(URLS),
                status,
                max(rbytes, 100),
                rng.choice(USER_AGENTS),
                rng.choice(REFERRERS),
                rng.choice(session_pool),
                "normal",
            )
        )
    return rows


def gen_brute_force(n, rng, session_pool):
    """Single attacker IP firing 50+ POST /login attempts inside 5 minutes."""
    rows = []
    while len(rows) < n:
        ip = rng.choice(ATTACKER_IPS)
        start = _random_timestamp(rng)
        burst = int(rng.integers(50, 90))
        session = _session_id(rng)
        for _ in range(burst):
            if len(rows) >= n:
                break
            ts = start + timedelta(seconds=float(rng.uniform(0, 300)))
            rows.append(
                _row(
                    ts, ip, "POST", "/login",
                    rng.choice([401, 401, 403, 401, 403]),
                    int(rng.integers(150, 600)),
                    rng.choice(USER_AGENTS),
                    "-",                       # direct request, no referrer
                    session, "brute_force",
                )
            )
    return rows


def gen_sql_injection(n, rng, ip_pool, session_pool):
    """Injection probes from varied IPs with tooling/odd user agents."""
    suspicious_pool = list(ATTACKER_IPS) + list(rng.choice(ip_pool, size=15))
    rows = []
    while len(rows) < n:
        ip = rng.choice(suspicious_pool)
        ua = rng.choice(SUSPICIOUS_USER_AGENTS)
        start = _random_timestamp(rng)
        burst = int(rng.integers(3, 10))
        session = _session_id(rng)
        for _ in range(burst):
            if len(rows) >= n:
                break
            ts = start + timedelta(seconds=float(rng.uniform(0, 120)))
            rows.append(
                _row(
                    ts, ip,
                    rng.choice(["GET", "POST"], p=[0.7, 0.3]),
                    rng.choice(INJECTION_PAYLOADS),
                    rng.choice([400, 500, 400, 403]),
                    int(rng.integers(200, 1500)),
                    ua, "-", session, "sql_injection",
                )
            )
    return rows


def gen_bot_scraper(n, rng, session_pool):
    """Single IP walking sequential resource IDs at a uniform high rate."""
    rows = []
    while len(rows) < n:
        ip = rng.choice(BOT_IPS)
        ua = rng.choice(BOT_USER_AGENTS[:3])      # python-requests / curl / wget
        base = rng.choice(["/api/v1/user/", "/api/v1/product/", "/api/v1/orders/"])
        start = _random_timestamp(rng)
        interval = float(rng.choice([0.25, 0.30, 0.35]))   # ~170-240 req/min
        burst = int(rng.integers(200, 320))
        session = _session_id(rng)
        for i in range(burst):
            if len(rows) >= n:
                break
            ts = start + timedelta(seconds=i * interval)
            rows.append(
                _row(
                    ts, ip, "GET", f"{base}{i + 1}",
                    200, int(rng.normal(4000, 500)),
                    ua, "-", session, "bot_scraper",
                )
            )
    return rows


def gen_account_takeover(n, rng, ip_pool, known_sessions):
    """Hijacked session: successful login from a new IP, then rapid data access."""
    seq = [
        ("POST", "/login", 200),
        ("GET", "/api/v1/user/profile", 200),
        ("GET", "/api/v1/payment/methods", 200),
        ("GET", "/api/v1/user/settings", 200),
        ("GET", "/api/v1/orders", 200),
    ]
    rows = []
    while len(rows) < n:
        session = rng.choice(known_sessions)        # legitimate, stolen session
        new_ip = rng.choice(ip_pool)                # geographically new source
        start = _random_timestamp(rng)
        offset = 0.0
        for method, url, status in seq:
            if len(rows) >= n:
                break
            offset += float(rng.uniform(1, 4))
            ts = start + timedelta(seconds=offset)
            rows.append(
                _row(
                    ts, new_ip, method, url, status,
                    int(rng.normal(6000, 1500)),
                    rng.choice(USER_AGENTS),
                    rng.choice(REFERRERS),
                    session, "account_takeover",
                )
            )
    return rows


def gen_data_exfiltration(n, rng, ip_pool, known_sessions):
    """Authenticated session pulling sequential exports at ~100x normal size."""
    rows = []
    while len(rows) < n:
        session = rng.choice(known_sessions)
        ip = rng.choice(ip_pool)
        base = rng.choice(["/api/v1/export/", "/api/v1/download/"])
        start = _random_timestamp(rng)
        burst = int(rng.integers(10, 25))
        for i in range(burst):
            if len(rows) >= n:
                break
            ts = start + timedelta(seconds=i * float(rng.uniform(0.5, 2.0)))
            rbytes = int(rng.normal(500_000, 100_000))
            rows.append(
                _row(
                    ts, ip, "GET", f"{base}{i + 1}",
                    200, max(rbytes, 50_000),
                    rng.choice(USER_AGENTS),
                    rng.choice(REFERRERS),
                    session, "data_exfiltration",
                )
            )
    return rows


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #
def build_dataframe(total_rows: int = TOTAL_ROWS) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_SEED)

    ip_pool = _make_ip_pool(500, rng)
    session_pool = [_session_id(rng) for _ in range(2000)]
    known_sessions = list(rng.choice(session_pool, size=200))

    attack_each = int(total_rows * ATTACK_FRACTION_EACH)
    normal_rows = total_rows - attack_each * len(ATTACK_TYPES)

    print(f"Generating {total_rows:,} rows "
          f"({normal_rows:,} normal, {attack_each:,} per attack type)...")

    rows: list[dict] = []
    rows += gen_normal(normal_rows, rng, ip_pool, session_pool)
    rows += gen_brute_force(attack_each, rng, session_pool)
    rows += gen_sql_injection(attack_each, rng, ip_pool, session_pool)
    rows += gen_bot_scraper(attack_each, rng, session_pool)
    rows += gen_account_takeover(attack_each, rng, ip_pool, known_sessions)
    rows += gen_data_exfiltration(attack_each, rng, ip_pool, known_sessions)

    df = pd.DataFrame(rows, columns=COLUMNS)
    # Sort chronologically so the file reads like a real append-only access log.
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def write_outputs(df: pd.DataFrame) -> None:
    df.to_csv(CSV_PATH, index=False)
    try:
        df.to_parquet(PARQUET_PATH, index=False)
        parquet_status = f"{PARQUET_PATH} ({PARQUET_PATH.stat().st_size / 1e6:.1f} MB)"
    except Exception as exc:                          # pragma: no cover
        parquet_status = f"SKIPPED ({exc}); install pyarrow to enable Parquet"

    print("\n=== Generation complete ===")
    print(f"Rows           : {len(df):,}")
    print(f"Date range     : {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
    print(f"Unique IPs     : {df['ip_address'].nunique():,}")
    print(f"Unique sessions: {df['session_id'].nunique():,}")
    print("\nAttack-type breakdown:")
    counts = df["attack_type"].value_counts()
    for name, cnt in counts.items():
        print(f"  {name:<18}{cnt:>7,}  ({cnt / len(df) * 100:4.1f}%)")
    print(f"\nCSV     : {CSV_PATH} ({CSV_PATH.stat().st_size / 1e6:.1f} MB)")
    print(f"Parquet : {parquet_status}")


# --------------------------------------------------------------------------- #
# Kafka producer (real-time streaming layer)
# --------------------------------------------------------------------------- #
def stream_to_kafka(topic="web_access_logs", rate=0.2,
                    bootstrap="localhost:9092", limit=None):
    """Replay generated rows to a Kafka topic, one JSON event per ``rate`` s."""
    try:
        from kafka import KafkaProducer
    except ImportError as exc:                        # pragma: no cover
        raise SystemExit(
            "kafka-python is required for --stream "
            "(pip install kafka-python)"
        ) from exc

    if PARQUET_PATH.exists():
        df = pd.read_parquet(PARQUET_PATH)
    elif CSV_PATH.exists():
        df = pd.read_csv(CSV_PATH)
    else:
        df = build_dataframe()

    producer = KafkaProducer(
        bootstrap_servers=bootstrap,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    print(f"Streaming to topic '{topic}' at {1 / rate:.0f} events/s "
          f"(Ctrl-C to stop)...")

    sent = 0
    records = df.to_dict("records")
    rng = np.random.default_rng()
    try:
        while True:
            # Shuffle each pass so the live stream looks continuous.
            for idx in rng.permutation(len(records)):
                producer.send(topic, records[int(idx)])
                sent += 1
                if sent % 25 == 0:
                    producer.flush()
                    print(f"  sent {sent:,} events")
                if limit and sent >= limit:
                    producer.flush()
                    print(f"Done: {sent:,} events sent.")
                    return
                time.sleep(rate)
    except KeyboardInterrupt:
        producer.flush()
        print(f"\nStopped after {sent:,} events.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic access-log generator")
    parser.add_argument("--rows", type=int, default=TOTAL_ROWS,
                        help="total number of rows to generate")
    parser.add_argument("--stream", action="store_true",
                        help="stream generated rows to Kafka instead of writing files")
    parser.add_argument("--rate", type=float, default=0.2,
                        help="seconds between events in --stream mode")
    parser.add_argument("--bootstrap", default="localhost:9092",
                        help="Kafka bootstrap servers for --stream mode")
    parser.add_argument("--topic", default="web_access_logs",
                        help="Kafka topic for --stream mode")
    parser.add_argument("--limit", type=int, default=None,
                        help="max events to send in --stream mode")
    args = parser.parse_args()

    if args.stream:
        stream_to_kafka(topic=args.topic, rate=args.rate,
                        bootstrap=args.bootstrap, limit=args.limit)
    else:
        df = build_dataframe(args.rows)
        write_outputs(df)


if __name__ == "__main__":
    main()
