# CYBER_SENTINEL.AI — AI Cyber Threat Intelligence Dashboard

Full-stack project that **detects threats on your network**, **classifies** them with AI across a virus/malware catalog (virus, worm, trojan, ransomware, spyware, adware, rootkit, botnet, keylogger, RAT, downloader, backdoor, fileless, cryptominer) plus phishing / DDoS / brute-force / social engineering, shows **real-time charts**, and **generates PDF reports** for security decision-making.

The UI follows a neon cyber-ops aesthetic: threat definition cards, KPI tiles, log analyzer terminal, distribution donut, and severity density charts.

**No cloud APIs required** after the first dependency install — AI, fonts, SQLite, and the UI all run locally. Threat collection scans your LAN (hosts, risky ports, local connections).

## Features

| Requirement | Implementation |
|---|---|
| Data Collection | 6 live sources in parallel (Network IDS, Endpoint, Firewall, DNS, Email, Auth) + ingest API |
| Laptop mail | Watches Gmail/Outlook inbox (IMAP) and classifies phishing |
| Laptop files | Watches Downloads/Desktop/Documents for malware and ransomware |
| AI Classification | Hybrid ML (TF-IDF + Logistic Regression) + explainable rule indicators |
| Real-time Visualization | Live dashboard with source cards, pie, and severity charts |
| Reporting | Executive summary + downloadable PDF decision report |
| Network access | Server binds to `0.0.0.0` so a second laptop on the same Wi-Fi can send live findings |
| Second-laptop demo | `agent/sentinel_agent.py` reports phishing mail and every malware family to the main dashboard |

## Project structure

```
backend/          FastAPI API, AI classifier, live network scanner, PDF reports
frontend/         React (Vite) dashboard UI + local fonts
frontend/dist/    Prebuilt UI (served by FastAPI)
agent/            Remote PC agent (optional, other machines)
inbox_drop/       Optional folder for saved .eml files
file_drop/        Optional folder for malware/ransomware test files
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

**Chrome “127.0.0.1 refused to connect”** means the server is not running yet.

1. Extract the zip (do not run files from inside the zip).
2. Open the inner folder that contains `start-offline.bat`.
3. Double-click `start-offline.bat` and **leave that window open**.
4. Wait until it prints `READY`. Chrome opens by itself after that.
5. If the window closes or says Python was not found, install **Python 3.12** from https://www.python.org/downloads/ and tick **Add python.exe to PATH**. Then run the bat again.
6. If it still fails, open `start-offline.log` in the same folder and read the error.

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
| `FILE_WATCH_AUTO_START` | `true` | Watch Downloads/Desktop/Documents on startup |
| `FILE_WATCH_INTERVAL` | `8` | Seconds between folder scans |

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

## Download once and test

Use the **laptop phishing mail** copy of this project (the branch with My Mail + My Files), not the older zip.

1. Unzip, then run `start-offline.bat` (Windows) or `./start-offline.sh`
2. Open **http://127.0.0.1:8000**
3. On the dashboard, follow **Download-and-test checklist**

### Mail (phishing)

1. Open **My Mail**
2. Choose Gmail or Outlook
3. Enter your email and a Google/Microsoft **App Password** (not your normal password)
4. Click **Start watching my inbox**
5. Optional: **Load sample phishing** then **Check this email** to see a popup without waiting for real mail
6. For a live test, send yourself a phishing-style message; it is pulled about every 20 seconds

Gmail: enable IMAP, then create an App Password under Google Account → Security → 2-Step Verification → App passwords.

If the button stays on **Connecting…**, close the black window, use this latest zip, and try again. The dashboard now stops after about 12 seconds and shows the real reason (wrong password, IMAP off, or the network blocking port 993). A Gmail login in Chrome is not enough — only an App Password or classic Outlook on this PC works.

The connection is saved on this laptop (`data/mail_settings.json`) and resumes when you start the app again.

### Files and remaining malware families (this laptop)

Folder watch and laptop malware watch start with the app. Open **My Laptop**.

Live families (not Dummy Demo): virus, worm, trojan, ransomware, spyware, adware, rootkit, botnet, keylogger, RAT, downloader, backdoor, fileless, cryptominer.

They fire only when this PC actually shows an indicator, for example:

- a miner/RAT/keylogger **process** running
- **PowerShell -enc** / certutil / bitsadmin (fileless / downloader)
- classic **RAT/miner listen ports**
- **SMB spread** to many hosts (worm)
- **startup / Run-key** persistence
- **hosts-file** hijack (adware)
- a suspicious **file** in Downloads / Desktop / Documents

Click **Scan my laptop now** anytime. If nothing malicious is running, the family cards stay on “watching — no live hit”. That is correct.

Dummy Demo in the top bar injects fake catalog text and is optional. Do not use it if you want only live laptop detections.

Optional file check: **Drop test samples** writes harmless labeled files so you can see folder classification. Delete `CYBER_SENTINEL_TEST_*` afterward.

### Network and other PCs

- **Sources → Sweep All Sources Now** — real-time scan of six channels at once (Network IDS, Endpoint, Firewall, DNS, Email, Auth)
- **Projection Burst** — same sweep plus one classified event per source so every card lights up
- **Second laptop (final viva):** copy `agent/` to the other PC, run `start-agent.bat`, then inject phishing and each malware type. The main laptop pops up and the charts update.

## Final viva — two laptops

Keep the dashboard on the **main laptop**. The **second laptop** only runs the agent (Python 3, no extra packages).

1. Main laptop: `start-offline.bat`, leave the black window open. If Windows Firewall asks, click **Allow**.
2. Note the LAN URL on the dashboard **Second laptop — live demo** card (example `http://192.168.1.24:8000`).
3. Copy the `agent` folder to the second laptop (USB or download `sentinel_agent.py` + `start-agent.bat` from that card).
4. On the second laptop, same Wi-Fi, double-click `start-agent.bat` and paste the LAN URL.
5. When the card shows **LIVE**, choose **[1] Inject PHISHING mail**. The main laptop shows **PHISHING DETECTED**, the feed, and the charts.
6. Inject virus, worm, trojan, ransomware, … one by one (or **[A] Inject ALL**). Each type pops on the main dashboard.
7. Optional live mail: save a phishing `.eml` into `agent/inbox_drop` on the second laptop, or run the agent with `--mail` + App Password / `--outlook`.
8. On the main laptop click **Sweep All Sources Now** and say the same pipeline watches the LAN; the second PC is the inside-host sensor for that host.

You do **not** need to install real malware. `--inject` sends a labeled finding from that laptop’s hostname/IP. The AI module on the main laptop classifies it.

```bash
python sentinel_agent.py --server http://<main-laptop-lan-ip>:8000
python sentinel_agent.py --server http://<main-laptop-lan-ip>:8000 --inject phishing
python sentinel_agent.py --server http://<main-laptop-lan-ip>:8000 --inject-all --delay 8
```

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

That PC appears under **Second laptop — live demo** with its **hostname and IP**. It reports mail, files, processes, and ports; the dashboard AI classifies them. Use `--inject phishing` (and other types) so the popup is guaranteed during the viva.

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
- `GET /agent/start-agent.bat` — Windows menu launcher for the second laptop
- `POST /api/classify` — classify arbitrary threat text
- `GET /api/setup` — download-and-test checklist status
- `POST /api/mail/imap/connect` — start watching a Gmail/Outlook inbox
- `GET /api/mail/status` — inbox watch status
- `POST /api/files/start` — start watching laptop folders
- `POST /api/files/test-sample` — write harmless malware/ransomware test files
- `GET /api/files/status` — folder watch status
- `GET /api/endpoint/status` — live laptop malware-family watch
- `POST /api/endpoint/scan` — scan this laptop processes/ports/persistence now
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
