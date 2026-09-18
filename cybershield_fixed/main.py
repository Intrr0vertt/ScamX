"""
CyberShield AI — India Threat Intelligence Platform
FastAPI Backend v3.0 — Extended Edition

Features:
  - Deepfake video/image detection
  - Voice scam / AI clone analysis
  - Phishing message classifier (BERT-style NLP)
  - WhatsApp scam analyzer
  - Website phishing screenshot detector
  - CyberShield AI chatbot assistant
  - India scam trend predictions
  - India threat map with state-level heatmap

No mock data. All endpoints return results only from user inputs.

Run:
    pip install -r requirements.txt
    python main.py

API Docs: http://localhost:8000/api/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import deepfake, voice, phishing, dashboard, scam_map, whatsapp, website, assistant, trends

app = FastAPI(
    title="CyberShield AI — India Edition",
    description=(
        "Real-time AI detection platform for deepfakes, voice scams, phishing, WhatsApp fraud, "
        "and website spoofing. India-focused threat intelligence. "
        "No pre-populated or mock data — all results are from user inputs only."
    ),
    version="3.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(deepfake.router,   prefix="/api/deepfake",   tags=["Deepfake Detection"])
app.include_router(voice.router,      prefix="/api/voice",      tags=["Voice Scam Analysis"])
app.include_router(phishing.router,   prefix="/api/phishing",   tags=["Phishing Classification"])
app.include_router(whatsapp.router,   prefix="/api/whatsapp",   tags=["WhatsApp Scam Analysis"])
app.include_router(website.router,    prefix="/api/website",    tags=["Website Phishing Detection"])
app.include_router(assistant.router,  prefix="/api/assistant",  tags=["CyberShield AI Assistant"])
app.include_router(trends.router,     prefix="/api/trends",     tags=["Scam Trend Predictions"])
app.include_router(dashboard.router,  prefix="/api/dashboard",  tags=["Session Dashboard"])
app.include_router(scam_map.router,   prefix="/api/map",        tags=["India Threat Map"])


@app.get("/api/health")
async def health():
    return {
        "status": "operational",
        "platform": "CyberShield AI — India Edition",
        "version": "3.0.0",
        "modules": 9,
        "note": "No mock data. Results only from user inputs.",
        "endpoints": {
            "deepfake":    "POST /api/deepfake/analyze     (file upload: video/image)",
            "voice":       "POST /api/voice/analyze        (file upload: audio)",
            "phishing":    "POST /api/phishing/analyze     (JSON: {text, city})",
            "whatsapp":    "POST /api/whatsapp/analyze     (JSON: {message, city})",
            "website":     "POST /api/website/detect       (file upload: screenshot)",
            "assistant":   "POST /api/assistant/chat       (JSON: {message})",
            "trends":      "GET  /api/trends/predict",
            "map_report":  "POST /api/map/report           (JSON: {type, level, verdict, city})",
            "map_points":  "GET  /api/map/points           (?type=all|phishing|voice|deepfake|whatsapp|website)",
            "map_stats":   "GET  /api/map/stats",
            "dashboard":   "GET  /api/dashboard/summary",
        }
    }


@app.get("/api/cities")
async def get_india_cities():
    """Returns list of supported Indian cities for the threat map."""
    from routers.scam_map import INDIA_CITIES
    return {"cities": [{"name": k, **v} for k, v in INDIA_CITIES.items()]}


if __name__ == "__main__":
    import uvicorn
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║  CyberShield AI — India Edition  v3.0.0                 ║")
    print("║  API:  http://localhost:8000                             ║")
    print("║  Docs: http://localhost:8000/api/docs                   ║")
    print("║  9 modules · No mock data · India-focused               ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
