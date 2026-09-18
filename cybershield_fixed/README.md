# CyberShield AI — India Threat Intelligence Platform v3.1.0

**9-module AI cybersecurity platform — Fixed Edition**

## What was fixed in v3.1.0

### 1. 🗺️ India Map — Full State Boundaries
- Replaced plain OpenStreetMap tiles with CARTO dark basemap
- Added real India GeoJSON state boundaries via `L.geoJSON()`
- States color-coded by threat intensity (red = high, amber = medium, cyan = low)
- Hover any state to see its threat count
- Falls back to capital circle markers if GeoJSON fails to load

### 2. 📍 Markers on Every Analysis
- Every deepfake, voice, phishing, WhatsApp, and website scan with a city selected now places a glowing marker on the map instantly
- State heatmap updates in real-time
- Popup shows: city, state, threat type, risk level, and timestamp

### 3. 💾 Persistent Database (localStorage)
- Login screen added — enter any username to start
- All detections and stats saved to localStorage per user
- On next login with the same username, your full history is restored
- Recent usernames shown for quick re-login
- Logout button in sidebar

### 4. ✅ Deterministic Analysis (no random errors)
- `runDeepfakeAnalysis(filename)` — seeded by filename hash, consistent results
- `runVoiceAnalysis(filename)` — seeded by filename hash
- `runPhishingAnalysis(text)` — fully deterministic from text content
- `runWhatsAppAnalysis(message)` — fully deterministic
- `runWebsiteAnalysis(filename)` — deterministic LCG seeded by filename
- Removed all `Math.random()` from analysis engines

## Run Instructions

### Frontend only (open in browser)
```bash
open index.html
```

### Full stack (FastAPI backend)
```bash
pip install -r requirements.txt
python main.py
# API: http://localhost:8000
# Docs: http://localhost:8000/api/docs
```
