# CYBER_SENTINEL.AI — AI Cyber Threat Intelligence Dashboard

Full-stack project that **collects** cyber threat data from network sources, **classifies** threats with AI (phishing, malware, ransomware), shows **real-time charts**, and **generates PDF reports** for security decision-making.

The UI follows a neon cyber-ops aesthetic: threat definition cards, KPI tiles, log analyzer terminal, distribution donut, and severity density charts.

**Works fully offline** after the first dependency install — no cloud APIs, no CDN fonts, no external threat feeds at runtime.

## Features

| Requirement | Implementation |
|---|---|
| Data Collection | Multi-source network collection + manual ingest API |
| AI Classification | Hybrid ML (TF-IDF + Logistic Regression) + explainable rule indicators |
| Real-time Visualization | Live dashboard with timeline, pie, and severity charts |
| Reporting | Executive summary + downloadable PDF decision report |
| Offline mode | Local fonts, local AI model, local SQLite, bundled UI + docs |

## Project structure

```
backend/          FastAPI API, AI classifier, collector, PDF reports
frontend/         React (Vite) dashboard UI + local fonts
frontend/dist/    Prebuilt offline UI (served by FastAPI)
start-offline.sh  One-command offline launcher (Linux/macOS)
start-offline.bat One-command offline launcher (Windows)
data/             SQLite DB + generated PDF reports (created at runtime)
```

## Offline quick start (recommended)

### Linux / macOS

```bash
chmod +x start-offline.sh
./start-offline.sh
```

### Windows

```bat
start-offline.bat
```

If an old failed install left a broken environment, delete `backend\.venv` first, then run `start-offline.bat` again.

Then open:

- **Dashboard:** http://127.0.0.1:8000
- **API docs:** http://127.0.0.1:8000/docs

No internet is required while the app is running. Internet is only needed the **first time** you install Python/Node packages (or if `frontend/dist` is missing and must be rebuilt).

### Windows manual install (if needed)

```bat
cd backend
rmdir /s /q .venv
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python run.py
```

## Development mode (two terminals)

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py --reload
```

API: **http://127.0.0.1:8000**

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard (dev): **http://127.0.0.1:5173**

## What makes it offline

- Threat collection is local/simulated multi-source telemetry (no live internet feeds)
- AI model trains and runs entirely on-device with scikit-learn
- SQLite database stored under `data/`
- Fonts are bundled in `frontend/public/fonts` (no Google Fonts CDN)
- Swagger UI assets are bundled in `backend/static/swagger` (no jsDelivr CDN)
- Built React app is served by FastAPI from `frontend/dist`

## Main API endpoints

- `POST /api/collect` — collect & classify threats from network sources
- `POST /api/ingest` — ingest a single network event
- `POST /api/classify` — classify arbitrary threat text
- `GET /api/threats` — list threat events
- `GET /api/stats` — real-time statistics for charts
- `GET /api/reports/summary` — decision-support summary
- `GET /api/reports/pdf` — download PDF report

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, scikit-learn, ReportLab
- **Frontend:** React, Vite, Recharts, Lucide icons
- **Storage:** SQLite (`data/threats.db`)

## Rebuild offline UI after frontend changes

```bash
cd frontend
npm run build
```

Then restart `./start-offline.sh` (or `python backend/run.py`).
