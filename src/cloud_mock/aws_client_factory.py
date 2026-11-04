import os
import boto3

# Use 127.0.0.1 to avoid Windows IPv6 localhost resolution delay
MOTO_ENDPOINT = os.getenv("MOTO_ENDPOINT", "http://127.0.0.1:5000")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

DUMMY_CREDENTIALS = {
    "aws_access_key_id": os.getenv("AWS_ACCESS_KEY_ID", "test_key"),
    "aws_secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY", "test_secret"),
    "region_name": AWS_REGION,
    "endpoint_url": MOTO_ENDPOINT,
}


def get_organizations_client():
    return boto3.client("organizations", **DUMMY_CREDENTIALS)


def get_iam_client():
    return boto3.client("iam", **DUMMY_CREDENTIALS)


def get_sts_client():
    return boto3.client("sts", **DUMMY_CREDENTIALS)


def get_cloudtrail_client():
    return boto3.client("cloudtrail", **DUMMY_CREDENTIALS)


def get_s3_client():
    return boto3.client("s3", **DUMMY_CREDENTIALS)
