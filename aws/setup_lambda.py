"""
Provision the alert-triage Lambda on LocalStack.

Creates the IAM role, packages ``lambda_handler.py``, deploys the function,
wires an S3 ``ObjectCreated`` notification on the ``alerts/`` prefix, and runs a
test invocation.

Run (LocalStack must be up):
    docker compose -f docker-compose.localstack.yml up -d
    python aws/setup_lambda.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aws import s3_handler  # noqa: E402

ROLE_NAME = "security-lambda-role"
FUNCTION_NAME = "security-alert-lambda"
HANDLER = "lambda_handler.handler"
RUNTIME = "python3.11"
HANDLER_FILE = Path(__file__).resolve().parent / "lambda_handler.py"

# Endpoint the Lambda *container* uses to reach LocalStack's S3 API.
LAMBDA_ENDPOINT = os.environ.get("LAMBDA_AWS_ENDPOINT", "http://localstack:4566")

ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def create_role() -> str:
    from botocore.exceptions import ClientError

    iam = s3_handler.get_client("iam")
    try:
        resp = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(ASSUME_ROLE_POLICY),
        )
        arn = resp["Role"]["Arn"]
        iam.attach_role_policy(
            RoleName=ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        )
        print(f"[lambda] Created IAM role {ROLE_NAME}")
    except ClientError:
        arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
        print(f"[lambda] IAM role {ROLE_NAME} already exists")
    return arn


def build_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_handler.py", HANDLER_FILE.read_text(encoding="utf-8"))
    return buf.getvalue()


def deploy_function(role_arn: str, zip_bytes: bytes) -> str:
    from botocore.exceptions import ClientError

    lam = s3_handler.get_client("lambda")
    env = {"Variables": {
        "AWS_ENDPOINT_URL": LAMBDA_ENDPOINT,
        "S3_BUCKET": s3_handler.BUCKET,
    }}
    try:
        resp = lam.create_function(
            FunctionName=FUNCTION_NAME,
            Runtime=RUNTIME,
            Role=role_arn,
            Handler=HANDLER,
            Code={"ZipFile": zip_bytes},
            Timeout=60,
            MemorySize=256,
            Environment=env,
        )
        arn = resp["FunctionArn"]
        print(f"[lambda] Created function {FUNCTION_NAME}")
    except ClientError:
        lam.update_function_code(FunctionName=FUNCTION_NAME, ZipFile=zip_bytes)
        arn = lam.get_function(FunctionName=FUNCTION_NAME)[
            "Configuration"]["FunctionArn"]
        print(f"[lambda] Updated existing function {FUNCTION_NAME}")

    # Wait until the function is active before wiring/invoking.
    for _ in range(30):
        state = lam.get_function(FunctionName=FUNCTION_NAME)[
            "Configuration"].get("State", "Active")
        if state == "Active":
            break
        time.sleep(1)
    return arn


def add_s3_trigger(function_arn: str) -> None:
    lam = s3_handler.get_client("lambda")
    s3 = s3_handler.get_client("s3")

    try:
        lam.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId="s3-invoke",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn=f"arn:aws:s3:::{s3_handler.BUCKET}",
        )
    except Exception:  # noqa: BLE001 - permission may already exist
        pass

    s3.put_bucket_notification_configuration(
        Bucket=s3_handler.BUCKET,
        NotificationConfiguration={
            "LambdaFunctionConfigurations": [{
                "LambdaFunctionArn": function_arn,
                "Events": ["s3:ObjectCreated:*"],
                "Filter": {"Key": {"FilterRules": [
                    {"Name": "prefix", "Value": s3_handler.ALERTS_PREFIX}]}},
            }]
        },
    )
    print(f"[lambda] S3 notification configured on "
          f"s3://{s3_handler.BUCKET}/{s3_handler.ALERTS_PREFIX}")


def test_invoke() -> None:
    lam = s3_handler.get_client("lambda")
    event = {
        "Records": [{
            "s3": {
                "bucket": {"name": s3_handler.BUCKET},
                "object": {"key": f"{s3_handler.ALERTS_PREFIX}part-00000.parquet"},
            }
        }]
    }
    print("[lambda] Test-invoking function...")
    resp = lam.invoke(
        FunctionName=FUNCTION_NAME,
        Payload=json.dumps(event).encode("utf-8"),
    )
    payload = resp["Payload"].read().decode("utf-8")
    print(f"[lambda] Response: {payload}")


def main() -> None:
    if not s3_handler.is_available():
        raise SystemExit(
            f"AWS endpoint {s3_handler.ENDPOINT_URL} unreachable. "
            "Start LocalStack: docker compose -f docker-compose.localstack.yml up -d"
        )
    s3_handler.ensure_bucket(s3_handler.BUCKET)
    role_arn = create_role()
    time.sleep(2)  # let IAM role propagate
    fn_arn = deploy_function(role_arn, build_zip())
    add_s3_trigger(fn_arn)
    test_invoke()
    print(f"\nLambda trigger configured. Watching "
          f"s3://{s3_handler.BUCKET}/{s3_handler.ALERTS_PREFIX} for new alert files.")


if __name__ == "__main__":
    main()
