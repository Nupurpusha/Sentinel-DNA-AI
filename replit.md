# SentinelDNA

AI-powered behavioral anomaly detection platform for cybersecurity. Generates and analyzes synthetic access logs to identify anomalous behavior using ML models.

## How to Run

**Backend (FastAPI + ML):**
Workflow: `SentinelDNA Python API`
```
cd backend && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Starts on port 8000. On first run, generates ~52K synthetic events into `backend/sentinel.db`. Subsequent runs skip generation if data already exists.

**Frontend (React + TypeScript):**
Workflow: `artifacts/sentinel-web: web`
```
pnpm --filter @workspace/sentinel-web run dev
```
Proxies `/sentinel-api/*` to `localhost:8000`.

## Stack

- **Backend:** Python 3.12, FastAPI, SQLite, scikit-learn (Isolation Forest + classifier)
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS, shadcn/ui
- **Package manager:** pnpm (workspace monorepo)

## Project Structure

```
backend/           # FastAPI app, ML models, SQLite DB
artifacts/
  sentinel-web/    # React + TypeScript frontend
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/sentinel-api/summary` | Dataset statistics |
| GET | `/sentinel-api/events` | Paginated events with filters |
| GET | `/sentinel-api/identities` | All identities |
| GET | `/sentinel-api/identities/{id}` | Identity profile + event history |
| POST | `/sentinel-api/regenerate` | Drop and regenerate dataset |
| GET | `/sentinel-api/export/csv` | Download events as CSV |

## User Preferences

- Do not modify application logic, ML models, metrics, or UI unless explicitly asked.
