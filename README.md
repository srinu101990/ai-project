# CYBER_SENTINEL.AI — AI Cyber Threat Intelligence Dashboard

Full-stack project that **detects threats on your network**, **classifies** them with AI across a virus/malware catalog (virus, worm, trojan, ransomware, spyware, adware, rootkit, botnet, keylogger, RAT, downloader, backdoor, fileless, cryptominer) plus phishing / DDoS / brute-force / social engineering, shows **real-time charts**, and **generates PDF reports** for security decision-making.

The UI follows a neon cyber-ops aesthetic: threat definition cards, KPI tiles, log analyzer terminal, distribution donut, and severity density charts.

**No cloud APIs required** after the first dependency install — AI, fonts, SQLite, and the UI all run locally. Threat collection scans your LAN (hosts, risky ports, local connections).

## Features

| Requirement | Implementation |
|---|---|
| Data Collection | 6 live sources in parallel (Network IDS, Endpoint, Firewall, DNS, Email, Auth) + ingest API |
| AI Classification | Hybrid ML (TF-IDF + Logistic Regression) + explainable rule indicators |
| Real-time Visualization | Live dashboard with source cards, pie, and severity charts |
| Reporting | Executive summary + downloadable PDF decision report |
| Network access | Server binds to `0.0.0.0` so other devices on the LAN can open the dashboard |

## Project structure

```
backend/          FastAPI API, AI classifier, live network scanner, PDF reports
frontend/         React (Vite) dashboard UI + local fonts
frontend/dist/    Prebuilt UI (served by FastAPI)
start-offline.sh  One-command launcher (Linux/macOS)
start-offline.bat One-command launcher (Windows)
data/             SQLite DB + generated PDF reports (created at runtime)
```

## Quick start

### Linux / macOS

```bash
chmod +x start-offline.sh
./start-offline.sh
```

### Windows

```bat
start-offline.bat
```

If an old failed install left a broken environment, delete `backend\.venv` first, then run the launcher again.

Then open:

- **This PC:** http://127.0.0.1:8000
- **Other devices on your LAN:** http://\<your-lan-ip\>:8000
- **API docs:** http://127.0.0.1:8000/docs

Continuous monitoring starts automatically when the server boots. The dashboard
refreshes on its own — you do **not** need to keep clicking scan. Use **Pause
Monitoring** / **Resume Monitoring** if you want to stop the loop, or **Scan Now**
for an immediate extra pass.

### Optional environment variables

| Variable | Default | Meaning |
|---|---|---|
| `COLLECTION_MODE` | `network` | `network` = live LAN scan, `simulated` = demo payloads |
| `SCAN_SUBNET` | auto `/24` | Force a CIDR, e.g. `192.168.1.0/24` |
| `BIND_HOST` | `0.0.0.0` | HTTP bind address (LAN-reachable by default) |
| `BIND_PORT` | `8000` | HTTP port |
| `ALLOW_SIMULATED_FALLBACK` | `false` | If a live scan finds nothing, optionally seed demo events |
| `MONITOR_AUTO_START` | `true` | Begin continuous LAN monitoring on startup |
| `MONITOR_INTERVAL_SECONDS` | `45` | Seconds between automatic scans |
| `MONITOR_BATCH_SIZE` | `12` | Max findings stored per monitor cycle |

Example (simulated demo only, localhost bind):

```bash
COLLECTION_MODE=simulated BIND_HOST=127.0.0.1 ./start-offline.sh
```

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

API: **http://127.0.0.1:8000** (also on your LAN IP when bound to `0.0.0.0`)

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Dashboard (dev): **http://127.0.0.1:5173**

## Step 1 — phishing mail on THIS laptop

The old Email Gateway card does **not** read Gmail/Outlook. Use the new **My Mail** tab.

1. Start the app and open **My Mail**
2. Click **Load sample phishing** then **Check this email** — you should see **PHISHING DETECTED**
3. For a real mail: copy it from Gmail/Outlook and paste From / Subject / Body, or save as `.eml` and upload
4. Optional: connect IMAP with a Gmail/Outlook **app password** so new inbox mail is checked automatically

## How multi-source collection works

Every scan cycle runs **six collectors at the same time** on the presenter PC:

1. **Network IDS Sensor** — LAN host and risky-port scan (SMB, RDP, Telnet, databases)
2. **Endpoint Detection Agent** — local process / command-line inspection
3. **Firewall Flow Logs** — live socket table (listeners and suspicious outbound sessions)
4. **DNS Sinkhole** — DNS (port 53) sessions
5. **Email Gateway** — SMTP/IMAP/POP listeners and mail sessions
6. **Auth Gateway** — SSH/RDP/VNC login channels

Findings are classified with the on-device AI model and stored with the **source name** plus the **PC IP / hostname**. Duplicate findings in a time window are skipped.

For a **projected live demo**, open **Sources** (or the dashboard cards) and click:

- **Sweep All Sources Now** — real parallel collection
- **Projection Burst** — live sweep **plus** one classified event from every source at the same moment (so all six cards light up even on a quiet office LAN)

## Collect data from other PCs

The dashboard PC cannot read processes inside another computer just by sitting on WiFi or a cable. To collect **from other PCs**, run the remote agent on each machine you are allowed to monitor.

1. On the dashboard PC, start the app and note the LAN IP (also shown in **Connected PCs**)
2. Copy `agent/sentinel_agent.py` to the other PC (or download it from the dashboard)
3. On that PC run:

```bash
python sentinel_agent.py --server http://<dashboard-lan-ip>:8000
```

That PC appears under **Connected PCs** with its **hostname and IP**. It reports local processes and listening ports; the dashboard classifies them with the AI model.

Network IDS still probes other LAN IPs for **open ports** without an agent (ARP neighbors + TCP connect). That is exposure only, not an inside view of the remote PC.

## How network threat detection works

1. Auto-detects the local IPv4 address and `/24` subnet (or `SCAN_SUBNET`)
2. Continuously repeats scans in the background (default every 45 seconds)
3. Concurrently probes nearby hosts on common discovery ports
4. Deep-scans responsive hosts for risky services (SMB, RDP, Telnet, DB ports, etc.)
5. Inspects local listening sockets and suspicious outbound sessions (`psutil`)
6. Classifies each finding with the on-device AI model and stores it in SQLite
7. Skips duplicate findings so the feed does not flood
8. Dashboard marks events as **live** (network scan / ingest) or **simulated**

No root/pcap privileges are required. This is TCP connect scanning + host connection analysis — not full packet capture.

## Main API endpoints

- `POST /api/collect` — one-shot live multi-source scan & classify
- `GET /api/sources` — live collector status (6 sources)
- `POST /api/sources/sweep` — run all six collectors now
- `POST /api/sources/burst` — projector demo: live sweep + one event per source
- `GET /api/monitor` — continuous monitor status
- `POST /api/monitor/start` — start continuous monitoring
- `POST /api/monitor/stop` — pause continuous monitoring
- `POST /api/ingest` — ingest a single network event from an agent/sensor
- `GET /api/agents` — remote PCs running the agent
- `POST /api/agents/heartbeat` — agent report from another PC
- `GET /agent/sentinel_agent.py` — download the remote PC agent
- `POST /api/classify` — classify arbitrary threat text
- `GET /api/threats` — list threat events
- `GET /api/stats` — real-time statistics for charts
- `GET /api/health` — mode, local IP, scan subnet, monitor state
- `GET /api/reports/summary` — decision-support summary
- `GET /api/reports/pdf` — download PDF report

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy, scikit-learn, psutil, ReportLab
- **Frontend:** React, Vite, Recharts, Lucide icons
- **Storage:** SQLite (`data/threats.db`)

## Rebuild UI after frontend changes

```bash
cd frontend
npm run build
```

Then restart `./start-offline.sh` (or `python backend/run.py`).
