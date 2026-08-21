# ScamX — AI CyberShield Platform
### India's Real-Time Deepfake & Scam Detection System
**Team Falcon | Hackathon 2025**

---

## Quick Start in VS Code

### Step 1 — Open the project
```
File → Open Folder → select the ScamX folder
```

### Step 2 — Install Python dependencies
Open the VS Code terminal (`Ctrl+` ` `) and run:
```bash
cd backend
pip install -r requirements.txt
```

### Step 3 — Start the backend
```bash
python main.py
```
You should see:
```
[DB] Initialised → .../backend/cybershield.db
╔══════════════════════════════════════════════════════════╗
║  ScamX — AI CyberShield  v3.0  |  India Edition         ║
║  Database : cybershield.db  (SQLite)                     ║
║  API      : http://localhost:8000                         ║
║  Health   : http://localhost:8000/api/health              ║
╚══════════════════════════════════════════════════════════╝
```

### Step 4 — Open the frontend
Open `frontend/index.html` directly in your browser:
- **Windows:** Right-click → Open with → Chrome/Edge
- **Mac:** `open frontend/index.html`
- **VS Code:** Install the *Live Server* extension, then right-click `index.html` → *Open with Live Server*

The frontend auto-connects to the backend at `http://localhost:8000`.

---

## Project Structure

```
ScamX/
├── .vscode/
│   ├── launch.json          ← VS Code Run config (F5 to start backend)
│   └── settings.json
├── backend/
│   ├── main.py              ← Flask app entry point
│   ├── requirements.txt     ← Python dependencies
│   ├── cybershield.db       ← SQLite database (auto-created on first run)
│   ├── db/
│   │   ├── database.py      ← DB init, connection helper
│   │   └── crud.py          ← All read/write operations
│   └── routes/
│       ├── deepfake.py      ← POST /api/deepfake/analyze
│       ├── voice.py         ← POST /api/voice/analyze
│       ├── phishing.py      ← POST /api/phishing/analyze
│       ├── whatsapp.py      ← POST /api/whatsapp/analyze
│       ├── website.py       ← POST /api/website/detect
│       ├── detections.py    ← GET  /api/detections/*
│       ├── trends.py        ← GET  /api/trends/predict
│       └── assistant.py     ← POST /api/assistant/chat
└── frontend/
    └── index.html           ← Complete SPA (no build step needed)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/health` | Server health + DB status |
| GET  | `/api/cities` | 20 Indian cities with coordinates |
| POST | `/api/deepfake/analyze?city=Name` | Deepfake detection (file upload) |
| POST | `/api/voice/analyze?city=Name` | Voice scam detection (file upload) |
| POST | `/api/phishing/analyze` | Phishing message analysis (JSON) |
| POST | `/api/whatsapp/analyze` | WhatsApp scam analysis (JSON) |
| POST | `/api/website/detect?city=Name` | Website screenshot analysis (file upload) |
| POST | `/api/assistant/chat` | AI chatbot (JSON) |
| GET  | `/api/detections/` | Detection history (paginated) |
| GET  | `/api/detections/summary` | Dashboard KPIs |
| GET  | `/api/detections/map` | Map markers with coordinates |
| GET  | `/api/detections/heatmap` | State-level threat counts |
| GET  | `/api/detections/cities` | Per-city detection stats |
| GET  | `/api/trends/predict` | Scam trend predictions |

---

## Detection Modules

| Module | Type | Analysis Method |
|--------|------|----------------|
| **Deepfake Detector** | Video/Image | Byte entropy + histogram variance (EfficientNet-B4 upgrade path) |
| **Voice Scam Analyzer** | Audio | WAV PCM: ZCR, RMS energy, amplitude variance; MP3: byte-entropy fallback |
| **Phishing Analyzer** | Text | NLP keyword engine + URL domain reputation + India fraud corpus |
| **WhatsApp Scanner** | Text | UPI/KYC/OTP patterns + viral forward detection + emoji analysis |
| **Website Detector** | Image | PNG pixel decompression + brand impersonation + domain signals |
| **India Threat Map** | Visual | SVG map, 20 cities, state heatmap from real DB data |
| **SQLite Persistence** | Storage | Every detection stored with city, state, coordinates, reasons |
| **AI Chatbot** | Chat | Intent-matched responses for 10 India scam categories |
| **Trend Predictions** | Analytics | 7-day vs prior 7-day detection delta per state per type |

---

## Detection Rules

### Zero Mock Data Policy
- All analysis runs on actual uploaded/pasted content
- Dashboard populates only after real user detections
- No pre-seeded results or demo placeholders

### Persistence
- Every detection is stored in `cybershield.db` (SQLite)
- Survives backend restarts — historical data always available
- Frontend loads all stored detections on startup automatically

---

## Dependencies

```
flask>=3.0.0      — Web framework
numpy>=1.24.0     — Numeric operations
scipy>=1.10.0     — Signal processing
```
No external database, no ORM, no build tools needed.

---

## VS Code Tip
Press **F5** to launch the backend using the pre-configured debug profile.
Set breakpoints in any route file to inspect detection logic step by step.
