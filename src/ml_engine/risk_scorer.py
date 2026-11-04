"""
risk_scorer.py
--------------
Implements the Research Paper ML Risk Engine:
Regularized Logistic Regression model:
    rho_u(t) = sigma(w_u^T x_u(t)) = 1 / (1 + e^(-(w_0 + w^T x_u(t))))

Outputs continuous score rho_u(t) in [0, 1] and discrete tag {"RiskLevel": "Low" | "Medium" | "High"}
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Paths
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
model_path = project_root / "config" / "risk_model.joblib"

# Include project paths for inter-module imports
if str(project_root / "src") not in sys.path:
    sys.path.insert(0, str(project_root / "src"))

from telemetry.audit_log_generator import extract_user_feature_vector


class MLRiskEngine:
    def __init__(self, high_risk_threshold: float = 0.65, medium_risk_threshold: float = 0.35):
        self.high_risk_threshold = high_risk_threshold
        self.medium_risk_threshold = medium_risk_threshold
        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        """Loads saved model or trains a regularized Logistic Regression baseline."""
        if model_path.exists():
            try:
                self.model = joblib.load(model_path)
                return
            except Exception:
                pass

        # Train a regularized L2 Logistic Regression on synthetic reference data
        self._train_calibrated_baseline()

    def _train_calibrated_baseline(self):
        """
        Calibrates regularized logistic regression:
        Features: [destructive, off_hours, anom_region, priv_esc, error_rate]
        """
        np.random.seed(42)
        n_samples = 1000

        # 0: Benign
        X_benign = np.random.beta(a=0.5, b=8.0, size=(n_samples // 2, 5))
        y_benign = np.zeros(n_samples // 2)

        # 1: Anomalous / Malicious
        X_malicious = np.random.beta(a=3.0, b=2.0, size=(n_samples // 2, 5))
        y_malicious = np.ones(n_samples // 2)

        X = np.vstack([X_benign, X_malicious])
        y = np.concatenate([y_benign, y_malicious])

        clf = LogisticRegression(C=1.0, solver="lbfgs")
        clf.fit(X, y)
        self.model = clf

        # Save to config
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, model_path)

    def calculate_risk_score(self, feature_vector: np.ndarray) -> float:
        """
        Computes continuous risk score rho_u(t) in [0, 1] using logistic sigmoid.
        """
        X = np.array(feature_vector).reshape(1, -1)
        prob = self.model.predict_proba(X)[0][1]
        return float(np.clip(prob, 0.0, 1.0))

    def get_risk_tag(self, risk_score: float) -> str:
        """Categorizes continuous score into PrincipalTag:RiskLevel."""
        if risk_score >= self.high_risk_threshold:
            return "High"
        elif risk_score >= self.medium_risk_threshold:
            return "Medium"
        return "Low"

    def evaluate_user_telemetry(self, user_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        End-to-end evaluation: raw telemetry events -> x_u(t) -> rho_u(t) -> Tag
        """
        feature_vector = extract_user_feature_vector(user_events)
        risk_score = self.calculate_risk_score(feature_vector)
        risk_tag = self.get_risk_tag(risk_score)

        return {
            "feature_vector": feature_vector.tolist(),
            "risk_score": round(risk_score, 4),
            "risk_tag": risk_tag,
            "event_count": len(user_events),
        }


# Global singleton instance for high-throughput in-memory evaluation (<1 ms)
risk_engine = MLRiskEngine()


if __name__ == "__main__":
    print("[*] Testing ML Risk Scorer (Regularized Logistic Regression)...")
    # Benign telemetry vector
    benign_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0])
    benign_score = risk_engine.calculate_risk_score(benign_vec)
    print(f"Benign User x_u(t)={benign_vec} -> rho_u(t) = {benign_score:.4f} | Tag: {risk_engine.get_risk_tag(benign_score)}")

    # Compromised / High-risk telemetry vector
    compromised_vec = np.array([0.45, 0.70, 0.50, 0.40, 0.35])
    comp_score = risk_engine.calculate_risk_score(compromised_vec)
    print(f"Compromised User x_u(t)={compromised_vec} -> rho_u(t) = {comp_score:.4f} | Tag: {risk_engine.get_risk_tag(comp_score)}")
