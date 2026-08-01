# Aegis Intel — AI Cyber Threat Intelligence Dashboard

Full-stack project that **collects** cyber threat data from network sources, **classifies** threats with AI (phishing, malware, ransomware), shows **real-time charts**, and **generates PDF reports** for security decision-making.

## Features

| Requirement | Implementation |
|---|---|
| Data Collection | Multi-source network collection + manual ingest API |
| AI Classification | Hybrid ML (TF-IDF + Logistic Regression) + explainable rule indicators |
| Real-time Visualization | Live dashboard with timeline, pie, and severity charts |
| Reporting | Executive summary + downloadable PDF decision report |

## Project structure

```
backend/          FastAPI API, AI classifier, collector, PDF reports
frontend/         React (Vite) dashboard UI
data/             SQLite DB + generated PDF reports (created at runtime)
```

## Quick start

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

API runs at **http://127.0.0.1:8000**  
Docs: **http://127.0.0.1:8000/docs**

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard: **http://127.0.0.1:5173**

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

## Notes

- Network collection uses realistic multi-source simulated telemetry suitable for demos and academic projects.
- The classifier is trained on curated phishing / malware / ransomware / benign samples and persists to `backend/models/threat_classifier.joblib`.
- Frontend auto-refreshes every 12 seconds for near real-time stats.
