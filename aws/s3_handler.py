"""
S3 handler (LocalStack-compatible).

A thin boto3 wrapper for the object-storage layer of the pipeline. All calls
target the endpoint in ``AWS_ENDPOINT_URL`` (defaults to LocalStack at
``http://localhost:4566``) so the same code runs against LocalStack in
development and real AWS in production (just unset the endpoint override).

boto3 is imported lazily so modules that only need the constants (or the local
fallbacks elsewhere in the pipeline) work even when boto3 is not installed.

Run directly to provision the project buckets:
    python aws/s3_handler.py
"""
from __future__ import annotations

import os
from pathlib import Path

ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
BUCKET = os.environ.get("S3_BUCKET", "security-logs-pipeline")

ALERTS_PREFIX = "alerts/"
RAW_LOGS_PREFIX = "raw-logs/"


def _config():
    from botocore.config import Config
    # Short timeouts so a missing LocalStack fails fast instead of hanging.
    return Config(
        region_name=REGION,
        connect_timeout=3,
        read_timeout=5,
        retries={"max_attempts": 1},
    )


def get_client(service: str = "s3"):
    """Return a boto3 client wired to the configured endpoint."""
    import boto3
    return boto3.client(
        service,
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
        config=_config(),
    )


def is_available() -> bool:
    """True if the S3 endpoint is reachable (used to gate optional AWS steps)."""
    try:
        get_client().list_buckets()
        return True
    except Exception:  # noqa: BLE001 - ImportError, connection, or client errors
        return False


def ensure_bucket(bucket: str = BUCKET) -> None:
    from botocore.exceptions import ClientError

    s3 = get_client()
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        # us-east-1 must not pass a LocationConstraint.
        if REGION == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        print(f"[s3] Created bucket s3://{bucket}")


def upload_file(local_path, bucket: str, key: str) -> str:
    s3 = get_client()
    s3.upload_file(str(local_path), bucket, key)
    uri = f"s3://{bucket}/{key}"
    print(f"[s3] Uploaded {Path(local_path).name} -> {uri}")
    return uri


def upload_dir(local_dir, bucket: str, prefix: str, pattern: str = "*.parquet") -> int:
    """Upload every file matching ``pattern`` under ``local_dir`` to ``prefix``."""
    local_dir = Path(local_dir)
    count = 0
    for path in sorted(local_dir.glob(pattern)):
        key = prefix.rstrip("/") + "/" + path.name
        upload_file(path, bucket, key)
        count += 1
    if count == 0:
        print(f"[s3] No files matching {pattern} under {local_dir}")
    return count


def list_objects(bucket: str = BUCKET, prefix: str = "") -> list[str]:
    s3 = get_client()
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [obj["Key"] for obj in resp.get("Contents", [])]


def download_bytes(bucket: str, key: str) -> bytes:
    s3 = get_client()
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def main() -> None:
    if not is_available():
        raise SystemExit(
            f"S3 endpoint {ENDPOINT_URL} is not reachable. "
            "Start LocalStack: docker compose -f docker-compose.localstack.yml up -d"
        )
    ensure_bucket(BUCKET)
    print(f"[s3] Bucket ready: s3://{BUCKET}")
    print(f"[s3] Prefixes: {ALERTS_PREFIX}, {RAW_LOGS_PREFIX}")


if __name__ == "__main__":
    main()
