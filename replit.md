# SentinelDNA

An AI-powered behavioral anomaly detection platform for cybersecurity. Generates and analyzes synthetic access logs to identify anomalous identity behavior using machine learning.

## Stack

- **Backend**: Python 3.12 · FastAPI · SQLite · scikit-learn (Isolation Forest)
- **Frontend**: React + TypeScript · Vite · Tailwind CSS · Recharts · Wouter
- **Workspace**: pnpm monorepo

## How to Run

### Backend (Python FastAPI)
The `SentinelDNA Python API` workflow runs automatically:
```bash
cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
On first run, generates ~52,000 synthetic access events into `backend/sentinel.db` (takes 30–60 s). Subsequent starts skip generation if data already exists.

### Frontend (React)
The `artifacts/sentinel-web: web` workflow runs automatically:
```bash
pnpm --filter @workspace/sentinel-web run dev
```
Vite proxies `/sentinel-api/*` → `http://localhost:8000` so the frontend talks to the Python backend.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sentinel-api/summary` | Dataset statistics |
| GET | `/sentinel-api/events` | Paginated events with filters |
| GET | `/sentinel-api/identities` | List all identities |
| GET | `/sentinel-api/identities/{entity_id}` | Identity profile + event history |
| GET | `/sentinel-api/detections` | ML anomaly detection results |
| POST | `/sentinel-api/regenerate` | Regenerate the entire dataset |
| GET | `/sentinel-api/export/csv` | Download events as CSV |

## Project Structure

```
sentineldna/
├── backend/
│   ├── main.py              # FastAPI app + all API routes
│   ├── generator.py         # Synthetic data generator (300 identities, ~52K events)
│   ├── database.py          # SQLite setup
│   ├── detector.py          # ML anomaly detection (Isolation Forest)
│   ├── detection_routes.py  # Detection API routes
│   ├── baseline.py          # Behavioral baseline computation
│   ├── classifier.py        # Event classification
│   ├── temporal.py          # Temporal pattern analysis
│   ├── requirements.txt     # Python dependencies
│   └── sentinel.db          # SQLite database (auto-created)
│
└── artifacts/sentinel-web/  # React + TypeScript frontend
    └── src/
        ├── App.tsx
        ├── pages/
        │   ├── DataFoundation.tsx
        │   ├── IdentityInspector.tsx
        │   ├── SOCOverview.tsx
        │   └── ModelPerformance.tsx
        └── index.css
```

## User Preferences

- Do not redesign, refactor, or change SentinelDNA functionality, ML logic, risk scoring, dataset generation, or existing features unless explicitly asked.
- Fix only environment/workflow/startup configuration issues when asked to "get it running."
