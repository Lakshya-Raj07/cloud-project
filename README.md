# Adaptive Cloud Governance: Research Paper Baseline vs Advance System

This repository implements and benchmarks two cloud governance paradigms:
1. **Paper Baseline (AC-SCP Model)**: Reactive CloudTrail batch log ingestion, dynamic cost function optimization $J(\theta)$, and control-plane policy updates via AWS Organizations (`boto3.update_policy`).
2. **Advance System (Keycloak Dynamic Tagging + Sub-second Telemetry)**: Zero-API-Churn static guardrail conditioned on `aws:PrincipalTag/RiskLevel == "High"`, dynamic session tag injection (< 1 ms), and instant native sensor anomaly containment (< 1 sec) with Keycloak backchannel token revocation.

---

## 🏗️ Architecture & Component Overview

```
                                [ Fast Telemetry Stream ]
                     (Native Process & File Sensor: psutil / watchdog)
                                            │
                                            ▼ (Sub-second anomaly trigger)
┌──────────────────────┐        ┌────────────────────────────────────┐
│ Keycloak IdP Server  │        │       ML & Decision Engine         │
│  (Standalone :8080)  │◄──────►│   (FastAPI + Scikit-Learn :8000)   │
│ - Issue JWT/STS Tag  │  REST  │ - Risk Scoring: ρu(t) = σ(wᵀx)     │
│ - Backchannel Logout │        │ - Cost Optimization: J(θ)          │
└──────────┬───────────┘        └─────────────────┬──────────────────┘
           │ STS Session Tag                      │ Policy Update
           │ (Advance Mode: <1 ms)                │ (Paper Baseline: ~247 ms)
           ▼                                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 Mock Cloud Governance (Moto Server)                 │
│                          (Standalone :5000)                         │
│ - Multi-Account Hierarchy: Single Root -> OUs (Dev, Stage, Prod)    │
│ - Baseline Path: Dynamic SCP JSON update (Paper model)              │
│ - Advance Path: Static Guardrail checking aws:PrincipalTag/RiskLevel│
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
adaptive-cloud-governance/
├── venv/                       # Python Virtual Environment
├── config/
│   ├── org_hierarchy.json      # OUs (Dev, Stage, Prod, Regulated) & accounts
│   ├── scp_templates.json      # Baseline parameterized template P(θ)
│   ├── static_guardrail_scp.json # Advance static SCP (PrincipalTag-based)
│   ├── runtime_state.json      # Discovered Root ID, OUs, and Policy IDs
│   ├── baseline_benchmark.json # Baseline benchmark metrics
│   └── advance_benchmark.json  # Advance benchmark metrics
├── src/
│   ├── cloud_mock/
│   │   ├── aws_client_factory.py # Reusable boto3 factory targeting Moto (:5000)
│   │   ├── bootstrap_org.py    # Auto-provisions OUs, accounts, and attaches SCPs
│   │   └── iam_sts_client.py   # AssumeRole with Keycloak STS session tags
│   ├── telemetry/
│   │   ├── audit_log_generator.py # CloudTrail batch logs simulator & feature extraction
│   │   └── native_sensor.py       # psutil / watchdog sub-second listener
│   ├── ml_engine/
│   │   ├── risk_scorer.py      # Logistic regression risk scoring ρu(t)
│   │   └── optimizer.py        # Cost function J(θ) minimization & SCP compiler
│   ├── identity/
│   │   ├── keycloak_client.py  # Keycloak Admin REST API & backchannel logout
│   │   └── risk_api.py         # FastAPI microservice (:8000)
│   └── benchmark/
│       ├── run_paper_baseline.py # Benchmarks 247 ms latency & 6.5 min exposure
│       └── run_advance_system.py # Benchmarks <1 ms evaluation & <1s containment
├── dashboard/
│   └── app.py                  # Streamlit comparative monitoring dashboard
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Demos

### 1. Live "Attacker vs Defender" Cyber Attack Simulation
Run this to see the end-to-end attack containment drama in real time:
```powershell
.\venv\Scripts\python.exe demo_attack_flow.py
```

### 2. Multi-Scenario Benchmark & Live GUI Pop-up Window
Run this to execute 20 test runs across 4 threat scenarios and automatically launch the interactive Matplotlib comparison window:
```powershell
.\venv\Scripts\python.exe run_demo.py
```

### 3. Keycloak Standalone Server (Port 8080)
To start Keycloak Standalone with CloudGovRealm Admin Console (`http://localhost:8080`):
```powershell
.\venv\Scripts\python.exe src\identity\keycloak_server.py
# Or on Windows using batch script:
.\keycloak\bin\kc.bat
```

---

## 🚀 Benchmark Comparison Results

| Metric | Paper Baseline (AC-SCP) | Advance Proposed System | Improvement |
| :--- | :--- | :--- | :--- |
| **Policy Evaluation Latency** | **247.4 ± 58.6 ms** (Control-Plane API) | **0.0012 ms** (In-Memory STS Tag) | **~200,000x faster** |
| **Cloud Control-Plane Updates** | High Churn (API update per threat) | **0 Calls** (Static Guardrail) | **Zero-API-Churn** |
| **Anomaly Containment Window** | **~6.5 minutes (390s)** (CloudTrail log lag) | **0.0635 seconds (63 ms)** (Native Sensor) | **~6,139x faster** |
| **Simulated Policy Violations** | 45 violations | **2 violations** | **95.5% reduction** |

---

## 🛠️ How to Run

### 1. Start Moto Mock Cloud Server (Port 5000)
```powershell
.\venv\Scripts\moto_server.exe -p 5000
```

### 2. Initialize Multi-Account Hierarchy & SCPs
```powershell
.\venv\Scripts\python.exe src\cloud_mock\bootstrap_org.py
```

### 3. Run Benchmarks & Generate Plots
```powershell
# Run Paper Baseline (measures 247ms latency & 6.5m exposure)
.\venv\Scripts\python.exe src\benchmark\run_paper_baseline.py

# Run Advance System (measures <1ms latency & <1s containment)
.\venv\Scripts\python.exe src\benchmark\run_advance_system.py

# Run Statistical Multi-Scenario Benchmark (20 runs - replicates Fig 7)
.\venv\Scripts\python.exe src\benchmark\statistical_benchmark.py

# Generate High-Resolution Publication Comparison Plots (saved to benchmark_plots/)
.\venv\Scripts\python.exe src\benchmark\generate_paper_comparison_plots.py
```

### 4. Start Decision Engine Microservice (Port 8000)
```powershell
.\venv\Scripts\uvicorn.exe src.identity.risk_api:app --host 127.0.0.1 --port 8000 --reload
```

### 5. Launch Live Streamlit Comparison Dashboard
```powershell
.\venv\Scripts\streamlit.exe run dashboard\app.py
```
Access the dashboard in your browser at `http://localhost:8501`.
