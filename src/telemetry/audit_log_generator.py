"""
audit_log_generator.py
----------------------
Simulates batch CloudTrail audit logs in time-window chunks for the
Paper Baseline (AC-SCP) sense phase.

Captures key features:
1. Unusual / high-risk API actions (e.g. s3:DeleteBucket, ec2:TerminateInstances, iam:*)
2. Off-hours execution (e.g. 23:00 - 05:00 UTC)
3. Anomalous region / IP execution (e.g. non-standard regions)
4. Privilege escalation attempts count
"""

import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

# Normal vs High-Risk AWS API actions
BENIGN_ACTIONS = [
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("s3.amazonaws.com", "GetObject"),
    ("s3.amazonaws.com", "PutObject"),
    ("sts.amazonaws.com", "GetCallerIdentity"),
    ("organizations.amazonaws.com", "DescribeOrganization"),
]

PRIVILEGE_ESCALATION_ACTIONS = [
    ("iam.amazonaws.com", "CreateUser"),
    ("iam.amazonaws.com", "AttachUserPolicy"),
    ("iam.amazonaws.com", "PutUserPolicy"),
    ("iam.amazonaws.com", "CreateAccessKey"),
    ("iam.amazonaws.com", "AttachRolePolicy"),
]

DESTRUCTIVE_ACTIONS = [
    ("s3.amazonaws.com", "DeleteBucket"),
    ("ec2.amazonaws.com", "TerminateInstances"),
    ("rds.amazonaws.com", "DeleteDBInstance"),
    ("cloudtrail.amazonaws.com", "StopLogging"),
]

STANDARD_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
ANOMALOUS_REGIONS = ["ap-southeast-1", "me-south-1", "af-south-1", "sa-east-1"]

CORP_IP_PREFIXES = ["10.0.", "172.16.", "192.168.1."]
ANOMALOUS_IP_PREFIXES = ["198.51.100.", "203.0.113.", "185.220.101."]


def generate_single_event(
    user_id: str,
    account_id: str = "111122223331",
    is_anomalous: bool = False,
    timestamp: datetime = None,
) -> Dict[str, Any]:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    if is_anomalous:
        # High risk action or privilege escalation
        if random.random() < 0.6:
            source, action = random.choice(PRIVILEGE_ESCALATION_ACTIONS)
            category = "privilege_escalation"
        else:
            source, action = random.choice(DESTRUCTIVE_ACTIONS)
            category = "destructive"

        region = random.choice(ANOMALOUS_REGIONS if random.random() < 0.7 else STANDARD_REGIONS)
        ip = f"{random.choice(ANOMALOUS_IP_PREFIXES)}{random.randint(1, 254)}"
        # Off-hours: set hour to late night (01:00-04:00)
        hour = random.choice([1, 2, 3, 4, 23])
        event_time = timestamp.replace(hour=hour, minute=random.randint(0, 59))
        error_code = "AccessDenied" if random.random() < 0.4 else None
    else:
        source, action = random.choice(BENIGN_ACTIONS)
        category = "benign"
        region = random.choice(STANDARD_REGIONS)
        ip = f"{random.choice(CORP_IP_PREFIXES)}{random.randint(1, 254)}"
        # Normal business hours: (09:00 - 18:00)
        hour = random.choice(range(9, 18))
        event_time = timestamp.replace(hour=hour, minute=random.randint(0, 59))
        error_code = None

    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{user_id.upper()[:8]}",
            "arn": f"arn:aws:iam::{account_id}:user/{user_id}",
            "accountId": account_id,
            "userName": user_id,
        },
        "eventTime": event_time.isoformat(),
        "eventSource": source,
        "eventName": action,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11",
        "errorCode": error_code,
        "category": category,
        "is_off_hours": hour < 6 or hour > 21,
        "is_anomalous_region": region in ANOMALOUS_REGIONS,
    }


def generate_batch_audit_logs(
    users: List[str],
    total_events: int = 100,
    anomaly_probability: float = 0.15,
    output_file: str = None,
) -> List[Dict[str, Any]]:
    """Generates a batch chunk of CloudTrail audit logs."""
    now = datetime.now(timezone.utc)
    events = []

    for _ in range(total_events):
        user = random.choice(users)
        is_anom = random.random() < anomaly_probability
        # Spread events across recent minutes
        ts = now - timedelta(seconds=random.randint(0, 360))
        event = generate_single_event(user_id=user, is_anomalous=is_anom, timestamp=ts)
        events.append(event)

    # Sort by eventTime ascending
    events.sort(key=lambda e: e["eventTime"])

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2)

    return events


def extract_user_feature_vector(user_events: List[Dict[str, Any]]) -> np.ndarray:
    """
    Extracts the feature vector x_u(t) for Logistic Regression:
    x_u(t) = [
      f1: unusual_api_ratio (destructive actions ratio)
      f2: off_hours_ratio (events happening between 22:00 - 06:00)
      f3: anomalous_region_ratio (actions outside standard regions)
      f4: privilege_escalation_rate (IAM privilege mutation actions ratio)
      f5: error_rate (AccessDenied frequency)
    ]
    """
    n = len(user_events)
    if n == 0:
        return np.zeros(5)

    destructive_count = sum(1 for e in user_events if e.get("category") == "destructive")
    off_hours_count = sum(1 for e in user_events if e.get("is_off_hours"))
    anom_region_count = sum(1 for e in user_events if e.get("is_anomalous_region"))
    priv_esc_count = sum(1 for e in user_events if e.get("category") == "privilege_escalation")
    error_count = sum(1 for e in user_events if e.get("errorCode") is not None)

    return np.array([
        destructive_count / n,
        off_hours_count / n,
        anom_region_count / n,
        priv_esc_count / n,
        error_count / n,
    ], dtype=float)


if __name__ == "__main__":
    test_users = ["alice_dev", "bob_contractor", "mallory_attacker"]
    batch = generate_batch_audit_logs(test_users, total_events=50, anomaly_probability=0.2)
    print(f"[*] Generated batch of {len(batch)} CloudTrail events.")

    for user in test_users:
        user_ev = [e for e in batch if e["userIdentity"]["userName"] == user]
        vec = extract_user_feature_vector(user_ev)
        print(f"  User {user:<18} ({len(user_ev)} events) -> Feature Vector x_u(t): {np.round(vec, 3)}")

