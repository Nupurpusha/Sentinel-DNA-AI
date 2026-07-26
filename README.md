<div align="center">

# 🧬 SentinelDNA

### AI-Powered Behavioral Anomaly Detection for Cybersecurity

<p>
  <strong>Learn the behavioral DNA. Detect the deviation. Investigate what matters.</strong>
</p>

<p>
  SentinelDNA builds behavioral baselines for users, service accounts, and edge devices,
  then combines event-level ML, sequence-aware detection, temporal analysis,
  explainability, and risk-based SOC prioritization to surface suspicious activity.
</p>

<p>
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1000&color=E31B23&center=true&vCenter=true&width=850&lines=Behavioral+DNA+for+Every+Digital+Identity;Isolation+Forest+%2B+GRU+Sequence+Detection;Label-Independent+Anomaly+Scoring;Explainable+Top-1%25+SOC+Alert+Prioritization" alt="SentinelDNA typing animation" />
</p>

<p>
  <img src="https://img.shields.io/badge/Python-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-3178C6?style=for-the-badge&logo=react&logoColor=white" />
  <img src="https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white" />
  <img src="https://img.shields.io/badge/ML-Isolation%20Forest-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Sequence%20Model-GRU-purple?style=for-the-badge" />
</p>

</div>

---

## 🛡️ What is SentinelDNA?

Traditional security systems often evaluate events in isolation.

SentinelDNA takes an **identity-centric behavioral approach**.

Every user, service account, and edge device develops a behavioral baseline — its **Behavioral DNA** — describing expected:

- authentication patterns
- devices
- locations
- IP ranges
- accessed resources
- working hours
- session behavior

SentinelDNA detects deviations from this baseline using multiple complementary detection mechanisms and converts them into **explainable, risk-ranked alerts for SOC analysts**.

The system is designed around a critical principle:

> **Ground-truth attack labels are never used for model training, anomaly scoring, behavioral scoring, or operational alert ranking.**

Labels are used only after predictions for offline evaluation.

---

# 🚀 Core Capabilities

| Capability | Implementation |
|---|---|
| 🧬 Behavioral Profiling | Per-identity behavioral baselines |
| 🌲 Event-Level Detection | Isolation Forest |
| 🔁 Sequence Detection | GRU next-event sequence predictor |
| 📈 Temporal Analysis | Multi-window temporal drift detection |
| 🧊 Cold-Start Handling | Reliability gating for identities with insufficient history |
| 🧠 Behavioral Evidence | Weighted behavioral deviation engine |
| 🎯 Risk Ranking | Explainable final risk scoring |
| 🚨 SOC Prioritization | Top-1% analyst alert budget |
| 🏷️ Attack Classification | Deterministic anomaly-type classification |
| 🔍 Explainability | Expected vs Observed behavioral comparison |
| 👩‍💻 Investigation | Analyst-facing SOC investigation workflow |
| 🔐 Leakage Validation | Deterministic label-independence testing |

---

# 🏗️ Detection Architecture

```text
                    ┌─────────────────────┐
                    │ Security Telemetry  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Per-Identity        │
                    │ Behavioral Baseline │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Feature Engineering │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
                 ▼                           ▼
       ┌──────────────────┐        ┌──────────────────┐
       │ Isolation Forest │        │ GRU Sequence     │
       │ Event Detection  │        │ Detection        │
       └────────┬─────────┘        └────────┬─────────┘
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
                  ┌──────────────────────┐
                  │ Behavioral Evidence │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Risk Prioritization  │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Anomaly             │
                  │ Classification       │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ SOC Investigation    │
                  └──────────────────────┘
```

> **Important:** Isolation Forest and GRU operate as parallel anomaly signals.  
> The GRU score is exposed as complementary sequence-aware evidence and is **not score-fused into the validated Step-3 final risk ranking**, preserving reproducibility of the operational alert metrics.

---

# 📊 Verified Results

The current deterministic synthetic dataset contains:

<div align="center">

| Metric | Result |
|---|---:|
| Security Events | **51,209** |
| Digital Identities | **300** |
| Ground-Truth Attack Events | **412** |
| Isolation Forest ROC-AUC | **0.971** |
| Raw Isolation Forest Recall | **85.2%** |
| Top-0.5% Precision | **89.5%** |
| Top-1% Alert Count | **512** |
| Top-1% Precision | **49.8%** |
| Top-1% Attack Coverage | **61.9%** |
| Overall Attack Classification Accuracy | **64.1%** |
| Top-1% Classification Accuracy | **89.0%** |
| GRU Sequence ROC-AUC | **0.9769** |
| Label-Leakage Validation | **PASS** |

</div>

---

## 🎯 Why the Top-1% Alert Budget Matters

A raw unsupervised anomaly detector can generate too many alerts for realistic analyst workflows.

SentinelDNA separates **model anomaly detection** from **operational alert selection**.

Events are ranked by final risk score and the SOC can operate under a fixed analyst budget.

| Alert Budget | Alerts | Precision | Recall |
|---|---:|---:|---:|
| Top 0.5% | 256 | **89.5%** | 55.6% |
| Top 1% | 512 | **49.8%** | **61.9%** |
| Top 2% | 1,024 | 34.0% | 84.5% |
| Top 5% | 2,560 | 13.8% | 85.7% |

The **Top-1% mode** is the primary SOC operating point used by the prototype.

---

# 🧬 Behavioral DNA

Each synthetic identity receives a behavioral profile representing its expected behavior.

| Profile Attribute | Behavioral Meaning |
|---|---|
| `normal_hours` | Typical access hours |
| `primary_location` | Expected authentication location |
| `known_devices` | Trusted device fingerprints |
| `common_resources` | Frequently accessed resources |
| `preferred_auth` | Normal authentication mechanism |
| `session_dur_min/max` | Expected session duration |
| `ip_prefix` | Typical network range |
| `typical_commands` | Expected command/activity patterns |

Incoming events are compared against these baselines to identify meaningful deviations.

---

# 🌲 Event-Level Anomaly Detection

SentinelDNA uses an **Isolation Forest** as its primary event-level unsupervised detector.

### Configuration

```text
n_estimators = 200
contamination = 0.05
random_state = 42
```

### Behavioral Features

The detector uses 12 behavioral features:

```text
hour_of_day
is_outside_normal_hours
session_duration
session_zscore
auth_failed
auth_method_unfamiliar
device_unknown
resource_unfamiliar
location_unfamiliar
ip_unfamiliar
recent_failure_rate
n_anomaly_signals
```

The ground-truth `label` column is explicitly excluded.

---

# 🔁 Sequence-Aware GRU Detection

Event-level anomaly detection cannot fully capture suspicious behavior that emerges only across a **sequence of actions**.

SentinelDNA therefore includes a genuine sequence-aware GRU detector.

### Architecture

```text
Model              Lightweight GRU Next-Event Predictor
Sequence Length    12 chronological events
Input Features     12 behavioral features
Hidden Units       16
Training Epochs    3
Seed               20260726
Training           Unsupervised / label-independent
```

The GRU learns to predict the next normalized behavioral feature vector from an identity's recent sequence.

### Sequence Anomaly Score

```text
Recent Behavioral Sequence
          ↓
        GRU
          ↓
Predicted Next Event Features
          ↓
Prediction Error (MSE)
          ↓
Calibration against training error distribution
          ↓
Sequence Anomaly Score [0–100]
```

Higher prediction error indicates behavior that is less consistent with the learned sequence dynamics.

Current offline evaluation:

```text
ROC-AUC ≈ 0.9769
Recall @ score threshold 50 = 1.00
Precision @ score threshold 50 ≈ 0.036
```

The high ROC-AUC indicates strong ranking ability, while the low fixed-threshold precision reinforces why SentinelDNA uses analyst-budget prioritization rather than treating every anomaly score as an alert.

---

# 🧠 Behavioral Deviation Engine

SentinelDNA independently evaluates explicit deviations from each identity's baseline.

Examples include:

- failed authentication
- unknown device
- unfamiliar location
- unusual IP range
- off-hours activity
- unfamiliar resource
- unfamiliar authentication method
- abnormal session duration
- elevated recent authentication failure rate

These signals produce:

```text
Behavioral Deviation Score: 0–100
Evidence Count:             Number of distinct triggered signals
Behavioral Reasons:         Human-readable explanations
```

---

# 🎯 Final Risk Scoring

The validated operational risk score combines event-level ML and explicit behavioral deviation evidence:

```text
combined =
    0.55 × ML anomaly score
  + 0.45 × behavioral deviation score
```

When both independent signals are strongly elevated:

```text
if ML score >= 70
and behavioral deviation >= 60:

    combined = combined × 1.15
```

Final score:

```text
final_risk_score = min(100, round(combined))
```

### Risk Bands

| Risk Level | Score |
|---|---:|
| 🔴 Critical | ≥ 80 |
| 🟠 High | ≥ 65 |
| 🟡 Medium | ≥ 45 |
| 🟢 Low | < 45 |

The GRU remains a **parallel sequence-aware evidence signal** and does not modify this validated ranking formula.

---

# 📈 Temporal Drift Detection

Behavior is not static.

SentinelDNA tracks gradual behavioral changes using rolling windows of:

```text
10 events
25 events
50 events
```

Signals include:

- resource expansion
- repeated access to newly introduced resources
- sustained activity-frequency changes
- behavioral deviation accumulation
- authentication-failure persistence
- session-duration deviation
- device/location diversity growth

Temporal state is classified as:

| Score | Status |
|---|---|
| `< 35` | Stable |
| `35–64` | Elevated |
| `≥ 65` | High Drift |

This allows SentinelDNA to distinguish isolated anomalies from longer-term behavioral evolution.

---

# 🧊 Cold-Start Protection

Behavioral models should not claim confidence when insufficient history exists.

SentinelDNA therefore applies:

```text
Minimum behavioral history = 50 events
```

For identities with fewer than 50 events:

```text
baseline_status = "Cold Start"
temporal_scoring_reliable = false
temporal_drift_score = 0
```

The UI explicitly communicates that the score is **unreliable due to insufficient history**, rather than presenting zero as evidence of safety.

> The current generated dataset contains established identities with at least 50 events, so the cold-start branch is implementation-validated but is not naturally triggered by the present 300-identity dataset.

---

# 🏷️ Anomaly-Type Classification

After detection, SentinelDNA provides an interpretable anomaly-type prediction.

Supported categories include:

```text
brute_force
credential_stuffing
insider_drift
impossible_travel
device_spoofing
low_slow_exfiltration
lateral_movement
unknown_anomaly
```

Current evaluation:

```text
Overall classification accuracy     64.1%
Top-1% classification accuracy      89.0%
```

Strong classes include brute force, credential stuffing, and device spoofing.

Stealthier patterns such as lateral movement remain more difficult because their observable behavioral features overlap with legitimate deviations.

This limitation is intentionally reported rather than hidden or label-tuned.

---

# 🔍 Explainability

SentinelDNA does not present analysts with only a numerical anomaly score.

Every investigated alert can include:

### Why SentinelDNA Flagged This

Human-readable behavioral reasons derived from the detection evidence.

### Expected vs Observed

Example:

```text
Expected Location     → Bengaluru
Observed Location     → London

Expected Device       → Known Device
Observed Device       → Unknown Fingerprint

Expected Access Time  → 09:00–18:00
Observed Access Time  → 02:14
```

Only genuine deviations from the identity's baseline are highlighted.

Ground-truth attack labels are never used to generate these explanations.

---

# 🚨 SOC Investigation Workflow

SentinelDNA provides a dedicated analyst-facing SOC interface.

Analysts can inspect:

- Top-1% priority alerts
- entity ID and type
- timestamp
- final risk score
- risk level
- ML anomaly score
- behavioral deviation score
- evidence count
- resource
- location
- device
- authentication result
- predicted anomaly type
- behavioral explanations
- Expected vs Observed behavior

Demo analyst dispositions include:

```text
Investigate
Escalate
Benign
```

These dispositions do not retrain the model or alter the validated ranking.

---

# 🔐 Label Independence

One of SentinelDNA's core design requirements is preventing **ground-truth leakage**.

Attack labels are used only for post-hoc evaluation.

They are never used for:

```text
❌ Isolation Forest training
❌ GRU training
❌ Feature engineering
❌ Behavioral deviation scoring
❌ Temporal drift scoring
❌ Final risk scoring
❌ SOC alert ranking
```

Deterministic leakage tests verify that changing/shuffling labels leaves:

```text
Isolation Forest anomaly scores
Behavioral deviation scores
Evidence counts
GRU sequence scores
Final risk scores
Event ranking
```

unchanged.

### Result

> ✅ **LABEL-INDEPENDENCE TEST: PASSED**

---

# 🧪 Synthetic Cybersecurity Dataset

SentinelDNA includes its own synthetic telemetry generator.

Current dataset:

```text
51,209 access events
300 digital identities
3 identity classes
7 attack categories
```

Identity types:

```text
Users
Service Accounts
Edge Devices
```

Attack scenarios:

| Attack | Simulated Behavior |
|---|---|
| Brute Force | Rapid repeated authentication failures |
| Credential Stuffing | External IP attempts authentication across multiple identities |
| Impossible Travel | Geographically impossible authentication transition |
| Device Spoofing | Authentication from unknown device fingerprint |
| Lateral Movement | Unusual cross-resource/system access |
| Low-Slow Exfiltration | Gradual anomalous access over time |
| Insider Drift | Slowly evolving behavior away from historical baseline |

The `label` field exists solely to enable offline evaluation.

---

# 🖥️ Dashboard

The frontend contains four primary analyst views.

### 📊 Data Foundation

Explore the synthetic dataset, identity distribution, anomaly breakdown, filters, search, CSV export, and dataset regeneration.

### 🧬 Identity Inspector

Inspect an identity's:

- Behavioral DNA
- baseline status
- event history
- detected anomalies
- temporal drift
- GRU sequence anomaly score
- sequence reliability

### 🚨 SOC Overview

Operational analyst view containing:

- Top-1% alert queue
- priority alerts
- risk levels
- attack coverage
- analyst investigation workflow

### 📈 Model Performance

Evaluation view containing:

- Isolation Forest metrics
- ROC-AUC
- alert-budget analysis
- attack coverage
- classification performance
- label-leakage validation
- GRU sequence evaluation
- pipeline architecture
- streaming-readiness design

---

# 🗂️ Project Structure

```text
Sentinel-DNA-AI/
│
├── backend/
│   ├── main.py
│   ├── generator.py
│   ├── database.py
│   ├── detector.py
│   ├── detection_routes.py
│   ├── temporal.py
│   ├── baseline.py
│   ├── sequence_detector.py
│   ├── test_sequence_detector.py
│   ├── requirements.txt
│   └── sentinel.db
│
├── artifacts/
│   └── sentinel-web/
│       └── src/
│           ├── components/
│           │   └── AlertInvestigationDialog.tsx
│           │
│           ├── pages/
│           │   ├── DataFoundation.tsx
│           │   ├── IdentityInspector.tsx
│           │   ├── SocOverview.tsx
│           │   └── ModelPerformance.tsx
│           │
│           ├── types/
│           │   └── index.ts
│           │
│           ├── App.tsx
│           └── index.css
│
└── README.md
```

---

# ⚙️ Running SentinelDNA

## 1. Clone the Repository

```bash
git clone https://github.com/Nupurpusha/Sentinel-DNA-AI.git
cd Sentinel-DNA-AI
```

---

## 2. Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

Start FastAPI:

```bash
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

The backend exposes the SentinelDNA REST API under:

```text
/sentinel-api/
```

---

## 3. Frontend Setup

From the repository root, install the JavaScript dependencies:

```bash
pnpm install
```

Then start the SentinelDNA frontend:

```bash
pnpm --filter @workspace/sentinel-web run dev
```

Open the local URL shown by the development server.

---

# 🔌 Key API Endpoints

### Data Foundation

```text
GET  /sentinel-api/summary
GET  /sentinel-api/events
GET  /sentinel-api/identities
GET  /sentinel-api/identities/{entity_id}
POST /sentinel-api/regenerate
GET  /sentinel-api/export/csv
```

### Detection

```text
GET /sentinel-api/detection/status
GET /sentinel-api/detection/summary
GET /sentinel-api/detection/metrics
GET /sentinel-api/detection/high-risk
GET /sentinel-api/detection/priority-alerts
GET /sentinel-api/detection/top-identities
GET /sentinel-api/detection/risk-trend
GET /sentinel-api/detection/top1-metrics
GET /sentinel-api/detection/alert-budget
GET /sentinel-api/detection/attack-coverage
GET /sentinel-api/detection/classification-metrics
```

### Behavioral / Sequence Analysis

```text
GET /sentinel-api/detection/temporal/{entity_id}
GET /sentinel-api/detection/sequence/{entity_id}
GET /sentinel-api/detection/sequence/evaluation
```

---

# ⚡ Streaming Readiness

The current prototype operates on locally generated telemetry and SQLite.

The architecture is intentionally modular so the ingestion layer can later be replaced with a real-time stream:

```text
Current
Synthetic Generator
        ↓
     SQLite
        ↓
 SentinelDNA API


Production Path
Kafka / Kinesis / Pub/Sub
        ↓
Stream Processing
        ↓
Feature / Profile Store
        ↓
SentinelDNA Detection Services
        ↓
SOC / SIEM Integration
```

The current project demonstrates the detection and investigation architecture; it does **not** claim that the prototype is already deployed as a production streaming system.

---

# ⚠️ Known Limitations

SentinelDNA intentionally reports limitations rather than hiding them.

- The dataset is synthetic and does not represent the full diversity of enterprise telemetry.
- Stealthy attacks such as lateral movement remain difficult to classify from the available behavioral features.
- GRU weights currently operate within the application runtime rather than as a production model-serving infrastructure.
- Current identities have sufficient generated history, so cold-start behavior is validated primarily through implementation/testing.
- Temporal drift results depend on the behavioral diversity present in the generated dataset.
- The current system is a batch/local prototype; real-time streaming architecture is a future deployment path.
- Analyst dispositions are demo-local and do not currently feed an online learning loop.

---

# 🔬 Research Foundation

SentinelDNA draws inspiration from research and established cybersecurity frameworks:

### Isolation Forest / Behavioral Anomaly Detection
**Detecting Anomalous User Behavior Using an Extended Isolation Forest Algorithm: An Enterprise Case Study**

https://arxiv.org/abs/1609.06676

### Sequence-Aware Cyber Anomaly Detection
**Recurrent Neural Network Language Models for Open Vocabulary Event-Level Cyber Anomaly Detection**

https://arxiv.org/abs/1712.00557

### Sequence-Based Network Anomaly Detection
**Sequence Aggregation Rules for Anomaly Detection in Computer Network Traffic**

https://arxiv.org/abs/1805.03735

### Zero Trust Architecture
**NIST SP 800-207**

https://csrc.nist.gov/pubs/sp/800/207/final

### Adversary Behavior Taxonomy
**MITRE ATT&CK — Enterprise**

https://attack.mitre.org/tactics/enterprise/

---

# 🗺️ Future Roadmap

```text
☑ Synthetic behavioral telemetry
☑ Per-identity Behavioral DNA
☑ Isolation Forest event detection
☑ Behavioral evidence scoring
☑ SOC risk prioritization
☑ Explainable investigation
☑ Temporal drift detection
☑ Cold-start safeguards
☑ Anomaly-type classification
☑ GRU sequence-aware detection

☐ Persistent sequence-model artifacts
☐ Real enterprise telemetry connectors
☐ Kafka/Kinesis/Pub-Sub streaming ingestion
☐ SIEM/SOAR integration
☐ Analyst-feedback learning loop
☐ Production model monitoring
```

---

# 🎯 Design Philosophy

SentinelDNA is built around four principles:

### 🧬 Identity First
Model what is normal for each digital identity rather than relying only on global rules.

### 🔐 Label Independent
Never use ground-truth attack labels to manufacture better anomaly scores.

### 🔍 Explainable by Design
Every high-risk alert should tell the analyst **why** it was considered suspicious.

### 🎯 Analyst Budget Aware
Detection quality is not enough — alerts must be prioritized within a realistic SOC workload.

---

<div align="center">

## 🧬 SentinelDNA

### Behavioral Intelligence for Modern Cyber Defense

**Detect deviations. Prioritize risk. Explain every alert.**

<br/>

Built for AI-powered behavioral anomaly detection in cybersecurity.

<br/>

[![GitHub](https://img.shields.io/badge/GitHub-Sentinel--DNA--AI-181717?style=for-the-badge&logo=github)](https://github.com/Nupurpusha/Sentinel-DNA-AI)

</div>
