"""
optimizer.py
------------
Implements the Research Paper Parameterized SCP Compiler & Optimizer:
Dynamic cost function:
    J(θ) = α V(θ) + β O(θ) - γ A(θ)

Where:
- V(θ): Vulnerability / Violation Risk Cost (damage from allowing risky actions under risk)
- O(θ): Operational Overhead / False Alarm Cost (impeding legitimate business operations)
- A(θ): Availability / Productivity Benefit
- θ: Policy threshold & denial action set
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Potential actions to restrict in dynamic SCP
CANDIDATE_RESTRICTED_ACTIONS = [
    "s3:DeleteBucket",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "ec2:TerminateInstances",
    "rds:DeleteDBInstance",
    "iam:PutUserPolicy",
    "cloudtrail:StopLogging",
]

DEFAULT_ALLOWED_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


class PolicyOptimizer:
    def __init__(self, alpha: float = 1.5, beta: float = 0.8, gamma: float = 0.5):
        """
        Weights for the cost function:
        alpha: Penalty weight for security risk V(theta)
        beta: Penalty weight for operational disruption O(theta)
        gamma: Reward weight for legitimate availability A(theta)
        """
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

    def calculate_cost(self, theta_actions: List[str], max_user_risk: float) -> float:
        """
        Calculates J(theta) = alpha * V(theta) + beta * O(theta) - gamma * A(theta)
        """
        num_denied = len(theta_actions)
        total_candidates = len(CANDIDATE_RESTRICTED_ACTIONS)

        # 1. Vulnerability Risk V(theta): High if high user risk is NOT covered by restrictions
        uncovered_risk_ratio = (total_candidates - num_denied) / total_candidates
        V_theta = max_user_risk * uncovered_risk_ratio

        # 2. Operational Overhead O(theta): Friction from restricting too many actions for normal work
        O_theta = (num_denied / total_candidates) * (1.0 - max_user_risk)

        # 3. Availability Benefit A(theta): Productivity enabled by permitted actions
        A_theta = (total_candidates - num_denied) / total_candidates

        cost = self.alpha * V_theta + self.beta * O_theta - self.gamma * A_theta
        return float(cost)

    def optimize_policy_parameters(self, max_user_risk: float) -> Dict[str, Any]:
        """
        Selects optimal parameter theta* minimizing J(theta).
        """
        best_cost = float("inf")
        best_actions = []

        # Iterate through tiered action restrictions
        action_tiers = [
            [],  # Tier 0: No extra restrictions
            ["s3:DeleteBucket", "cloudtrail:StopLogging"],  # Tier 1: Destructive storage & logs
            ["s3:DeleteBucket", "cloudtrail:StopLogging", "ec2:TerminateInstances", "rds:DeleteDBInstance"],  # Tier 2: Compute & DB
            CANDIDATE_RESTRICTED_ACTIONS,  # Tier 3: Full lockdown (IAM + Infrastructure)
        ]

        for tier in action_tiers:
            cost = self.calculate_cost(tier, max_user_risk)
            if cost < best_cost:
                best_cost = cost
                best_actions = tier

        return {
            "optimal_actions": best_actions,
            "min_cost_J": round(best_cost, 4),
            "max_user_risk": max_user_risk,
        }

    def compile_scp_json(self, optimal_actions: List[str], allowed_regions: List[str] = None) -> Dict[str, Any]:
        """
        Compiles concrete SCP JSON document P(theta*) to push to AWS Organizations.
        """
        if allowed_regions is None:
            allowed_regions = DEFAULT_ALLOWED_REGIONS

        statements = []
        if optimal_actions:
            statements.append({
                "Sid": "DynamicallyRestrictedActions",
                "Effect": "Deny",
                "Action": optimal_actions,
                "Resource": "*",
            })

        statements.append({
            "Sid": "DenyUnapprovedRegions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": allowed_regions
                }
            }
        })

        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }


policy_optimizer = PolicyOptimizer()


if __name__ == "__main__":
    print("[*] Testing Policy Optimizer and Parameterized SCP Compiler...")
    # Scenario 1: Low risk (e.g. max_user_risk = 0.1)
    res_low = policy_optimizer.optimize_policy_parameters(max_user_risk=0.1)
    print(f"Low Risk (0.1) -> Optimal Actions: {res_low['optimal_actions']} | Cost J: {res_low['min_cost_J']}")

    # Scenario 2: High risk (e.g. max_user_risk = 0.95)
    res_high = policy_optimizer.optimize_policy_parameters(max_user_risk=0.95)
    print(f"High Risk (0.95) -> Optimal Actions: {res_high['optimal_actions']} | Cost J: {res_high['min_cost_J']}")

    scp_doc = policy_optimizer.compile_scp_json(res_high["optimal_actions"])
    print("\nCompiled Concrete SCP JSON P(theta*):")
    print(json.dumps(scp_doc, indent=2))

