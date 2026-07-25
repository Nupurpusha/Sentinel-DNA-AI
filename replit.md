# SentinelDNA

An AI-powered behavioral anomaly detection platform for cybersecurity. Generates synthetic access logs, trains an Isolation Forest ML model, and surfaces anomalies through a SOC analyst dashboard.

## Run & Operate

- **Python API** — managed by the `SentinelDNA Python API` workflow: `cd backend && python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload`
- **React frontend** — managed by the `artifacts/sentinel-web: web` workflow: `pnpm --filter @workspace/sentinel-web run dev`

The first time the backend runs, it generates ~51K synthetic events (30–60 seconds) and trains the ML model. Subsequent restarts skip generation if data already exists.

## Stack

- **Backend:** Python 3.11, FastAPI, SQLite (via `backend/sentinel.db`), pandas, numpy, scikit-learn (Isolation Forest)
- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, TanStack Query, Recharts, Wouter
- **Monorepo:** pnpm workspaces

## Where things live

- `backend/main.py` — FastAPI app and all API routes
- `backend/generator.py` — Synthetic data generation (300 identities, 7 attack types)
- `backend/detector.py` — Isolation Forest ML model training and anomaly scoring
- `backend/detection_routes.py` — Detection/SOC API routes
- `backend/database.py` — SQLite schema and connection
- `backend/sentinel.db` — Pre-generated SQLite database (~25MB, committed)
- `artifacts/sentinel-web/src/pages/` — DataFoundation, IdentityInspector, SocOverview, ModelPerformance
- `artifacts/sentinel-web/src/App.tsx` — Router and layout

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/sentinel-api/summary` | Dataset statistics |
| GET | `/sentinel-api/events` | Paginated events with filters |
| GET | `/sentinel-api/identities` | All identities |
| GET | `/sentinel-api/identities/{id}` | One identity's profile and event history |
| POST | `/sentinel-api/regenerate` | Drop and regenerate the dataset |
| GET | `/sentinel-api/export/csv` | Download events as CSV |

## Architecture decisions

- SQLite is used instead of Postgres — appropriate for a local/demo dataset (51K rows, pre-generated). No external DB dependency.
- The ML model is trained at startup and cached in `model_cache.pkl`; training is skipped if the cache exists.
- The Vite dev server proxies `/sentinel-api` → `localhost:8000` so the frontend and backend can run on separate ports without CORS issues.
- Python packages are installed system-wide via `pip` (not uv/poetry) because Replit's NixOS environment uses Python 3.11.

## Gotchas

- Python packages must be installed with `python3 -m pip install ...` (not `pip3` or uv) in this environment.
- If the backend fails to start, check that Python packages are installed: `python3 -m pip list | grep fastapi`.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._
