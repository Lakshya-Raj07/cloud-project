"""
risk_api.py
-----------
FastAPI microservice running on :8000.
Exposes real-time risk tag evaluation for Keycloak IdP and STS Session Tagging:
- GET /identity/risk-tag?user_id={id} -> {"RiskLevel": "High" | "Low", "risk_score": float}
- POST /identity/telemetry -> Receives live sensor feeds from native_sensor.py
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Query
from pydantic import BaseModel

# Ensure project paths
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
if str(project_root / "src") not in sys.path:
    sys.path.insert(0, str(project_root / "src"))

from ml_engine.risk_scorer import risk_engine

app = FastAPI(
    title="Adaptive Cloud Governance - ML Decision Engine",
    description="Microservice providing real-time in-memory risk scoring for Keycloak SAML/OIDC PrincipalTags",
    version="1.0.0",
)

# In-memory user telemetry cache for sub-millisecond lookups
user_telemetry_cache: Dict[str, Dict[str, Any]] = {
    "alice_dev": {"risk_score": 0.05, "RiskLevel": "Low", "last_updated": time.time()},
    "bob_contractor": {"risk_score": 0.25, "RiskLevel": "Low", "last_updated": time.time()},
    "mallory_attacker": {"risk_score": 0.92, "RiskLevel": "High", "last_updated": time.time()},
}


class LiveTelemetryEvent(BaseModel):
    user_id: str
    anomaly_detected: bool
    trigger_type: str
    source_process: Optional[str] = None
    target_path: Optional[str] = None
    feature_weights: Optional[List[float]] = None


@app.get("/health")
def health():
    return {"status": "ok", "service": "ml_decision_engine", "port": 8000}


@app.get("/identity/risk-tag")
def get_risk_tag(user_id: str = Query(..., description="Principal/User ID")):
    """
    Sub-millisecond risk evaluation query called by Keycloak Token Mapper / STS AssumeRole.
    Returns: {"user_id": user_id, "RiskLevel": "High" | "Low", "risk_score": float, "eval_latency_ms": float}
    """
    t0 = time.perf_counter()

    if user_id in user_telemetry_cache:
        cached = user_telemetry_cache[user_id]
        risk_score = cached["risk_score"]
        risk_level = cached["RiskLevel"]
    else:
        # Default low risk for unknown new sessions
        risk_score = 0.08
        risk_level = "Low"

    eval_latency_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "user_id": user_id,
        "RiskLevel": risk_level,
        "risk_score": risk_score,
        "eval_latency_ms": round(eval_latency_ms, 4),
        "saml_attribute_name": "https://aws.amazon.com/SAML/Attributes/PrincipalTag:RiskLevel",
    }


@app.post("/identity/telemetry")
def ingest_live_telemetry(event: LiveTelemetryEvent):
    """
    Called by native_sensor.py to instantly elevate risk upon local OS anomaly detection.
    """
    t0 = time.perf_counter()
    if event.anomaly_detected:
        risk_score = 0.96
        risk_level = "High"
    else:
        risk_score = 0.10
        risk_level = "Low"

    user_telemetry_cache[event.user_id] = {
        "risk_score": risk_score,
        "RiskLevel": risk_level,
        "last_updated": time.time(),
        "last_trigger": event.trigger_type,
    }
    processing_time_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "status": "updated",
        "user_id": event.user_id,
        "RiskLevel": risk_level,
        "processing_time_ms": round(processing_time_ms, 4),
    }


@app.get("/identity/all-users")
def get_all_users():
    return user_telemetry_cache

