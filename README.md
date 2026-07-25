# SentinelDNA — Step 1: Data Foundation

SentinelDNA is an AI-powered behavioral anomaly detection platform for cybersecurity. This README covers what was built in **Step 1** — the project foundation and synthetic data generation system. No machine learning has been implemented yet.

---

## What Was Built in Step 1

- A **Python FastAPI backend** that generates and serves synthetic cybersecurity access logs
- A **SQLite database** that stores 52,000+ realistic access events across 300+ synthetic identities
- A **React + TypeScript frontend** with two views:
  - **Data Foundation** — dataset statistics and a searchable, filterable event table
  - **Identity Profile Inspector** — view the hidden behavioral profile for any identity and their event history

---

## Project Folder Structure

```
sentineldna/
├── backend/                  # Python FastAPI backend
│   ├── main.py               # FastAPI app and all API endpoints
│   ├── generator.py          # Synthetic data generator
│   ├── database.py           # SQLite connection and table setup
│   ├── requirements.txt      # Python dependencies
│   └── sentinel.db           # SQLite database (created on first run)
│
├── artifacts/
│   └── sentinel-web/         # React + TypeScript + Tailwind frontend
│       └── src/
│           ├── App.tsx        # Router and layout
│           ├── pages/
│           │   ├── DataFoundation.tsx      # Main dataset view
│           │   └── IdentityInspector.tsx   # Identity profile view
│           └── index.css      # Global styles and theme
│
└── README.md                 # This file
```

---

## How the Synthetic Generator Works

The generator creates **300 synthetic identities** and then generates events for each one based on that identity's hidden behavioral profile.

### Step 1 — Create Identities and Profiles

Each identity gets a randomly generated **behavioral profile** that stays constant. This profile controls what "normal" looks like for that person or system:

| Profile Field            | What It Controls |
|--------------------------|------------------|
| `normal_hours`           | Which hours of the day this identity typically logs in |
| `primary_location`       | The city they usually authenticate from |
| `known_devices`          | 1–3 trusted device fingerprints |
| `common_resources`       | The files/APIs they usually access |
| `preferred_auth`         | Their usual authentication method (MFA, SSO, password, etc.) |
| `session_dur_min/max`    | How long their sessions typically last (seconds) |
| `ip_prefix`              | The network subnet their traffic usually comes from |
| `typical_commands`       | The command sequences they typically run |

### Step 2 — Generate Normal Events

For each identity, the generator produces events that closely follow their profile:
- Timestamps fall within their normal working hours
- Location is near their primary city (with small GPS drift for realism)
- Device is chosen from their known devices (95% of the time)
- Auth method matches their preference (90% of the time)
- Session duration is drawn from their normal range

### Step 3 — Inject Anomalies

About 1–2% of events are anomalous. Anomalies are injected as realistic attack patterns:

| Attack Type | How It's Simulated |
|---|---|
| `brute_force` | 15–40 rapid failed login attempts from one IP address |
| `impossible_travel` | Same identity authenticates from two cities thousands of miles apart within minutes |
| `credential_stuffing` | One external IP tries to authenticate against 20–40 different identities, mostly failing |
| `lateral_movement` | Identity suddenly accesses resources far outside its normal department, running unusual commands |
| `device_spoofing` | Identity authenticates using a device fingerprint not in their known-devices list |
| `low_slow_exfiltration` | Identity gradually accesses off-hours resources over many days, with increasing session duration |
| `insider_drift` | Behavioral patterns slowly shift — login hours drift later, resources accessed become unusual |

**Important**: The `label` column records the ground truth for future ML model evaluation. The detection system must never use this column to compute risk scores — it must infer anomalies from behavior patterns only.

---

## What Each Column Means

| Column | Description |
|---|---|
| `event_id` | Unique ID for this event |
| `entity_id` | Who performed the action (e.g. `USER_001`, `SVC_003`, `EDGE_012`) |
| `entity_type` | `user`, `service_account`, or `edge_device` |
| `timestamp` | ISO 8601 timestamp of the event |
| `source_ip` | IP address the request came from |
| `geo_location` | City name of the source location |
| `latitude` / `longitude` | Coordinates of the source location |
| `resource_accessed` | The file, API, or system that was accessed |
| `auth_method` | Authentication method used (`mfa`, `sso`, `password`, `certificate`, `api_key`, `biometric`) |
| `auth_success` | Whether authentication succeeded (`true`/`false`) |
| `session_duration` | How long the session lasted in seconds |
| `command_sequence` | List of commands/actions performed during the session |
| `device_fingerprint` | Identifier for the device used |
| `department` | Department of the user (`Engineering`, `Finance`, `HR`, `Sales`, `Operations`, `IT`) — null for service accounts and edge devices |
| `label` | Ground truth label: `normal` or one of the 7 attack types (for ML evaluation only) |

---

## How to Run the Application

### Start the Python Backend

```bash
cd backend
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The first time it runs, it will generate the synthetic dataset automatically (this takes about 30–60 seconds).

### Start the React Frontend

```bash
pnpm --filter @workspace/sentinel-web run dev
```

### API Endpoints Available

| Method | Path | Description |
|---|---|---|
| `GET` | `/sentinel-api/summary` | Dataset statistics (totals, percentages, breakdowns) |
| `GET` | `/sentinel-api/events` | Paginated events with optional filters |
| `GET` | `/sentinel-api/identities` | List all identities |
| `GET` | `/sentinel-api/identities/{entity_id}` | Get one identity's profile and full event history |
| `POST` | `/sentinel-api/regenerate` | Drop and regenerate the entire dataset |
| `GET` | `/sentinel-api/export/csv` | Download events as CSV |

---

## What's Next (Step 2+)

Step 1 is complete. Step 2 will introduce:
- ML-based anomaly detection (Isolation Forest or similar)
- Behavioral profile learning per identity
- Risk scoring without using the `label` column
- SOC analyst dashboard with real-time anomaly alerts
