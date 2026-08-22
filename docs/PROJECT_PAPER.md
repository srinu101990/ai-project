# CYBER_SENTINEL.AI

## Project paper and step-by-step framework

**Title:** Offline AI Cyber Threat Intelligence Dashboard  
**Product name:** CYBER_SENTINEL.AI  
**Type:** Local FastAPI + React student project  
**AI used:** TF-IDF + Logistic Regression, plus regex rules  
**Not used:** ChatGPT, cloud antivirus, BERT, or a public 1-billion-row dataset

This paper is the framework of the project from the first idea to the live demo.
Read it in order. Each step is what the software actually does.

---

## 1. What problem this project solves

A college lab or small office has laptops on one Wi-Fi network. Staff open mail,
USB sticks, and downloads. They need a **single screen** that:

1. Collects suspicious text from the local PC, mail, files, USB, and a second laptop
2. Labels that text as a threat type (phishing, ransomware, virus, …)
3. Shows charts, a live table, and a PDF report

Commercial tools (CrowdStrike, Microsoft Defender for Endpoint, VirusTotal) need
cloud accounts and licenses. This project must run **offline on a laptop** after
Python packages are installed.

---

## 2. Project objectives

1. Build a local dashboard (no login cloud).
2. Classify 20 threat types from short event text.
3. Watch Gmail IMAP (App Password) for phishing-style mail.
4. Watch Downloads / Desktop / Documents / USB filenames for malware lures.
5. Accept live findings from a second laptop on the same Wi-Fi.
6. Store events in SQLite and export a filtered PDF.
7. Keep the viva honest: explain the model, the generated dataset, and the limits.

---

## 3. Scope (what it is / what it is not)

| It is | It is not |
|---|---|
| A local SOC-style dashboard | A replacement for real antivirus |
| Text classification of alerts and lures | Binary unpacking or sandbox detonation |
| Filename / mail-body heuristics | Full disk forensics |
| Generated training text for 20 labels | A downloaded 400,000-row public malware dump |
| Hybrid ML + regex | ChatGPT or a transformer |

---

## 4. Technology stack

| Layer | Choice | Why |
|---|---|---|
| Backend API | FastAPI (Python) | Simple REST, runs on Windows |
| Database | SQLite (`data/threats.db`) | One file, no server |
| AI model | scikit-learn TF-IDF + Logistic Regression | Fast, offline, explainable |
| Rules | Regular expressions | Stable demo labels + indicators |
| Frontend | React (Vite), served from `frontend/dist` | Single URL `http://127.0.0.1:8000` |
| Reports | ReportLab PDF | Offline PDF |
| Second PC | `agent/sentinel_agent.py` | HTTP POST to the main PC |

---

## 5. System architecture (big picture)

Read this as one pipeline:

```
 [Mail / Files / USB / LAN / Second laptop]
                    |
                    v
            raw text (payload)
                    |
                    v
     +-----------------------------+
     |  Hybrid classifier          |
     |  1. regex rules             |
     |  2. TF-IDF + Logistic Reg.  |
     +-----------------------------+
                    |
                    v
        threat_type, severity,
        confidence, indicators
                    |
                    v
           SQLite threat_events
                    |
          +---------+---------+
          |                   |
          v                   v
     React dashboard      PDF report
```

**Main PC** runs `start-offline.bat` → FastAPI on port **8000**.  
**Second PC** runs only the agent. It must call `http://<main-LAN-IP>:8000`, never `127.0.0.1`.

---

## 6. Threat taxonomy (20 classes)

The model and the UI use the same list from `backend/app/threat_types.py`.

**Network / social**

1. phishing  
2. ddos  
3. brute-force  
4. social  
5. benign  

**Catch-all**

6. malware  

**Malware catalog (Known Virus tab)**

7. virus  
8. worm  
9. trojan  
10. ransomware  
11. spyware  
12. adware  
13. rootkit  
14. botnet  
15. keylogger  
16. rat  
17. downloader  
18. backdoor  
19. fileless  
20. cryptominer  

Severity is fixed per type (example: ransomware = critical, phishing = medium, benign = low).

---

## 7. Step-by-step working of the project

### Step 1 — Start the system

On the main laptop:

```bat
start-offline.bat
```

The script creates a Python venv if needed, installs `backend/requirements.txt`,
and starts `backend/run.py`. Browser opens `http://127.0.0.1:8000`.

Leave the black window open. If it closes, the API is dead.

### Step 2 — Collect raw text

Every finding is just **text** plus a source name and IP. Sources:

| Source | Module | What is classified |
|---|---|---|
| LAN / ports | `network_scanner.py`, `monitor.py` | Host/port findings as text |
| Parallel sensors | `multi_source.py` | IDS / endpoint / firewall / DNS / email / auth style events |
| Gmail IMAP | `mail_guard.py` | Subject + body |
| Local folders | `file_guard.py` | Filename and small file text |
| USB | `file_guard.py` + agent `usb_drives` | Removable paths and lure names |
| Second laptop | `sentinel_agent.py` → `/api/agents/heartbeat` | Mail, files, USB, inject catalog |
| Dummy Demo | `demo_feed.py` | Fake catalog events (not a live scan) |
| AI Analyzer box | `/api/classify` | Whatever you paste |

### Step 3 — Classify

`backend/app/classifier.py` does this for every payload:

1. Run **regex rules** (example: `verify your account` → phishing, `wannacry` → worm).
2. Run the **v4 sklearn model** (`threat_classifier_v4.joblib`).
3. If a rule is strong (`confidence >= 0.75`), keep the rule label.
4. Else if the model probability is at least `0.45`, keep the ML label.
5. Else fall back to the rule (often `benign`).

Output:

- `threat_type`
- `severity`
- `confidence` (0–1)
- `indicators` (short phrases the rules hit)

### Step 4 — Store

`ThreatEvent` rows go into SQLite:

- source, source_ip, destination_ip, protocol
- raw_payload
- threat_type, severity, confidence, indicators
- status (`open` / later updated)
- created_at

### Step 5 — Show on the dashboard

The React app polls `/api/threats`, `/api/health`, mail, files, and agents.

Tabs (top bar):

1. **Dashboard** — KPIs and charts from the **visible** threat list  
2. **Threat Intelligence** — live table  
3. **Known Virus** — catalog cards (About / Behavior / Prevention)  
4. **AI Analyzer** — paste text, see label, see training-sample table  
5. **Reports** — newest events + PDF filters  
6. **Sources** — laptop live demo / connected PCs  
7. **My Mail** — IMAP connect and inbox check  
8. **Network Scan** — file/USB/folder watch  

**Dummy Demo** on the nav injects fake catalog events. Say that in viva. It is not a real infection.

### Step 6 — Report

`backend/app/report.py` filters events (date, severity, type, device, source)
and builds a PDF with ReportLab.

---

## 8. Module framework (paper chapter map)

Use these as report chapters.

### 8.1 Data collection layer

- `collector.py` — insert classified events, skip recent duplicates  
- `monitor.py` — background loop (default about every 12 seconds)  
- `multi_source.py` — named live sources for the Sources page  

### 8.2 Mail layer

- User enters Gmail address + **16-character App Password** (spaces allowed).  
- IMAP on port 993.  
- Newest inbox mail is classified as phishing or other types from the body.  
- Ordinary Gmail password will fail. That is expected.

### 8.3 File and USB layer

- Watches common user folders.  
- Heuristics on names such as `invoice.pdf.exe`, `virus.exe`, ransom notes.  
- Second-laptop USB list is merged on the main dashboard (`remote_agents.py`).  
- This is **not** a full AV engine. It is name/text matching plus the classifier.

### 8.4 Agent layer (second laptop)

```
Second PC:  sentinel_agent.py --server http://10.87.54.124:8000
Main PC:    FastAPI 0.0.0.0:8000
```

Replace `10.87.54.124` with the **main PC Wi-Fi IPv4**.  
Same Wi-Fi name is not enough if the IPv4 ranges differ.

### 8.5 AI layer

See section 9 and 10.

### 8.6 Presentation layer

React pages listed in Step 5. Charts use the current threat list, not a hidden second database.

### 8.7 Reporting layer

Filter modal → preview → PDF download.

---

## 9. Dataset framework (important for viva)

There is **no** downloaded 1,000,000,000-row public dataset for these 20 labels.

The trainer **generates** SOC-style sentences from templates in
`backend/app/training_data.py`. Hosts, IPs, users, and filenames are filled in
at random (seed 42).

| Name | Count | Where |
|---|---|---|
| Excel sample | **2,200** data rows (**2,201** lines with header) | `docs/dataset/threat_corpus_sample.csv` |
| Full train (in memory / full CSV) | **400,000** | 20,000 × 20 classes |
| Full holdout test | **50,000** | last 2 templates per class |
| Full CSV if you export it | **450,001** lines | `python -m scripts.export_full_corpus` |

So if you open the sample and see **2201**, that file is the sample.
The screenshots that say **400000** mean the trainer’s train size.

Holdout = last two wording templates per class. Those sentences are not used
in training. They still use the same family names (LockBit, Emotet, WannaCry),
so **100% holdout accuracy is not perfect real-world detection**.

Build the full CSV on the laptop:

```bat
cd %USERPROFILE%\Desktop\CYBER_SENTINEL\backend
py -3 -m scripts.export_full_corpus
find /c /v "" ..\docs\dataset\threat_corpus_full.csv
```

---

## 10. Training and classification framework

### 10.1 Why TF-IDF + Logistic Regression

Inputs are **short alert sentences**, not books.

- **TF-IDF (1–2 grams)** turns text into weighted word/phrase counts. Rare class
  words (`lockbit`, `xmrig`, `verify your account`) get high weight.
- **Logistic Regression** learns one weight vector per class and outputs
  probabilities (`predict_proba`).

Why not BERT / ChatGPT: they need large downloads or the internet, are harder
to explain, and would not be an honest “offline laptop AI.”

Why not regex only: new wording breaks. Why not ML only: the demo catalog
needs stable labels; rules supply readable indicators.

### 10.2 Train command

```bat
cd backend
py -3 -m scripts.train_threat_model 20000
```

Writes:

- `backend/models/threat_classifier_v4.joblib`
- `backend/models/threat_classifier_v4.metrics.json`

Recorded v4 numbers:

- Train 400,000 / test 50,000  
- Held-out accuracy **100%**, macro F1 **100%**  
- Algorithm: TF-IDF (1–2 grams) + Logistic Regression  

### 10.3 Inference (runtime)

Loaded once at API start. Every mail, file, agent, and paste box calls
`classifier.classify(text)`.

---

## 11. Dashboard walkthrough (what to click in viva)

1. Start main PC → Dashboard KPIs.  
2. **Known Virus** → click a family → About / Behavior / Prevention.  
3. **AI Analyzer** → paste a ransom note or phishing line → see the label.
   The training-sample table is below that.  
4. **My Mail** → App Password → Check inbox.  
5. **Network Scan / Files** → USB or a lure filename.  
6. **Sources** → second laptop appears only after the agent reports.  
7. **Reports** → filter → Download PDF.  
8. Optional: Dummy Demo — say it is injected catalog data.

---

## 12. Two-laptop demo framework

```
Laptop A (main)          Laptop B (agent)
DESKTOP-988C9GL          DESKTOP-SBJAOKO
start-offline.bat        py -3 -u sentinel_agent.py --server http://<A-Wi-Fi-IP>:8000
http://127.0.0.1:8000
```

Rules that fail the demo if ignored:

1. Agent must use laptop A’s **Wi-Fi IPv4**, not `127.0.0.1`.  
2. After agent/USB code changes, copy a **new** `sentinel_agent.py` to B.  
3. Firewall on A must allow TCP 8000 on private networks.  
4. Same SSID with different subnets (phone hotspot vs campus) will not connect.

---

## 13. Data flow example (one phishing mail)

1. IMAP reads: “Urgent action required: verify your account…”  
2. Rules hit `urgent action required` and `verify account`.  
3. TF-IDF also scores **phishing**.  
4. Strong rule wins → `threat_type=phishing`, `severity=medium`.  
5. Row stored. Dashboard table and charts update.  
6. PDF can include that row if filters match.

---

## 14. Folder map (for the paper “system design” figure)

```
CYBER_SENTINEL/
  start-offline.bat          main launcher
  backend/app/               API + AI + guards
    classifier.py            hybrid model
    training_data.py         generated corpus
    threat_types.py          20 labels
    mail_guard.py            IMAP
    file_guard.py            folders + USB
    remote_agents.py         second PC
    report.py                PDF
  backend/models/            v4 joblib + metrics
  backend/scripts/           train + export CSV
  frontend/src/              React tabs
  agent/sentinel_agent.py    second laptop
  docs/PROJECT_PAPER.md      this paper
  docs/dataset/              sample CSV
  docs/training-screenshots/ trainer stills
  data/threats.db            created at runtime
```

---

## 15. Limitations (write these in the paper)

1. Training text is **generated templates**, not VirusTotal or CIC-IDS2017 as-is.  
2. 100% holdout is on similar family-name sentences.  
3. File/USB detection is heuristic, not signature-complete.  
4. IMAP needs a Gmail App Password.  
5. Dummy Demo is synthetic.  
6. The system classifies **text**, not packed binaries.

---

## 16. Suggested report chapter order

1. Introduction and problem  
2. Objectives and scope  
3. Literature survey (SOC dashboards, TF-IDF text classification, phishing cues)  
4. System architecture (section 5 diagram)  
5. Requirement analysis (20 classes, offline, two laptops)  
6. Dataset generation and train/holdout split  
7. Model: TF-IDF + Logistic Regression + rules  
8. Implementation of modules (mail, files, agent, UI, PDF)  
9. Experimental result (400,000 / 50,000 / 100% holdout + honesty paragraph)  
10. Screenshots (dashboard, Known Virus, trainer stills, sample CSV)  
11. Conclusion and future work (real labeled mail, more file features)

---

## 17. One-page viva script

“This is CYBER_SENTINEL.AI, an offline laptop dashboard. Events come from mail,
files, USB, LAN, and a second PC. Each event is text. A hybrid classifier labels
it into 20 types. Rules give explainable words. TF-IDF and Logistic Regression
give the learned label. We generated 400,000 train sentences and held out 50,000
from unseen templates. The Excel file in the repo is a 2,200-row sample. The
dashboard stores results in SQLite and can print a PDF. It is not ChatGPT and
it is not commercial antivirus.”

---

## 18. Commands used in this project

```bat
rem start
start-offline.bat

rem train
cd backend
py -3 -m scripts.train_threat_model 20000

rem sample CSV (already in git, 2201 lines)
rem full CSV (400000 train + 50000 test)
py -3 -m scripts.export_full_corpus

rem second laptop
py -3 -u sentinel_agent.py --server http://10.87.54.124:8000
```

Replace the IP with the main PC Wi-Fi address.
