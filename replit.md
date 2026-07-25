# SentinelDNA

An AI-powered behavioral anomaly detection platform for cybersecurity. Generates 51,000+ synthetic access events across 300 identities and uses machine learning (Isolation Forest) to detect behavioral anomalies without relying on ground-truth labels.

## Architecture

- **Backend**: Python FastAPI (`backend/`) — serves the API and holds the SQLite database (`backend/sentinel.db`)
- **Frontend**: React + TypeScript + Tailwind (`artifacts/sentinel-web/`) — dashboard with four views

## How to Run

Both services start automatically via the configured workflows.

### Backend (Python FastAPI)
```
cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Workflow: **SentinelDNA Python API** (port 8000)

On first run, the backend generates ~51,000 synthetic access events and trains the anomaly detection model (30–60 seconds). Subsequent starts skip generation if data already exists.

### Frontend (React + Vite)
```
pnpm --filter @workspace/sentinel-web run dev
```
Workflow: **artifacts/sentinel-web: web** (port 20692, previewed at `/`)

The frontend proxies `/sentinel-api/*` to the backend at `localhost:8000`.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sentinel-api/summary` | Dataset statistics |
| GET | `/sentinel-api/events` | Paginated events with filters |
| GET | `/sentinel-api/identities` | All identities |
| GET | `/sentinel-api/identities/{id}` | Identity profile + event history |
| POST | `/sentinel-api/regenerate` | Regenerate the full dataset |
| GET | `/sentinel-api/export/csv` | Download events as CSV |

## Key Files

- `backend/main.py` — FastAPI app and all API routes
- `backend/generator.py` — Synthetic data generator (300 identities, 7 attack types)
- `backend/detector.py` — Isolation Forest anomaly detection
- `backend/database.py` — SQLite schema and connection
- `artifacts/sentinel-web/src/` — React frontend source
- `artifacts/sentinel-web/vite.config.ts` — Vite config (proxy, port from `PORT` env var)

## User Preferences

- Keep the project's existing structure (Python backend + React frontend monorepo)
- Do not restructure or migrate the stack without asking
