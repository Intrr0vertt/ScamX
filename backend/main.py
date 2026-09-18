"""
ScamX — AI CyberShield Platform
Flask Backend v3.0 | India Edition

Run:
    cd backend
    pip install -r requirements.txt
    python main.py

API: http://localhost:8000
Docs: http://localhost:8000/api/health
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify
from flask import Response

# ── DB init ───────────────────────────────────────────────────────────────────
from db.database import init_db
init_db()

# ── Blueprints ────────────────────────────────────────────────────────────────
from routes.deepfake   import deepfake_bp
from routes.voice      import voice_bp
from routes.phishing   import phishing_bp
from routes.whatsapp   import whatsapp_bp
from routes.website    import website_bp
from routes.detections import detections_bp
from routes.trends     import trends_bp
from routes.assistant  import assistant_bp

app = Flask(__name__)

# ── CORS ──────────────────────────────────────────────────────────────────────
@app.after_request
def cors(response: Response) -> Response:
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/api/<path:p>", methods=["OPTIONS"])
def preflight(p):
    return Response(status=200)

# ── Register blueprints ───────────────────────────────────────────────────────
app.register_blueprint(deepfake_bp,   url_prefix="/api/deepfake")
app.register_blueprint(voice_bp,      url_prefix="/api/voice")
app.register_blueprint(phishing_bp,   url_prefix="/api/phishing")
app.register_blueprint(whatsapp_bp,   url_prefix="/api/whatsapp")
app.register_blueprint(website_bp,    url_prefix="/api/website")
app.register_blueprint(detections_bp, url_prefix="/api/detections")
app.register_blueprint(trends_bp,     url_prefix="/api/trends")
app.register_blueprint(assistant_bp,  url_prefix="/api/assistant")

# ── Health & Cities ───────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    from db.database import get_conn
    try:
        conn  = get_conn()
        count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        conn.close()
        db_status = f"ok — {count} detections stored"
    except Exception as e:
        db_status = f"error: {e}"

    return jsonify({
        "status":   "operational",
        "platform": "ScamX — AI CyberShield  |  India Edition",
        "version":  "3.0.0",
        "database": db_status,
        "endpoints": {
            "deepfake":   "POST /api/deepfake/analyze   ?city=Name  (multipart file)",
            "voice":      "POST /api/voice/analyze      ?city=Name  (multipart file)",
            "phishing":   "POST /api/phishing/analyze   JSON {text, city}",
            "whatsapp":   "POST /api/whatsapp/analyze   JSON {message, city}",
            "website":    "POST /api/website/detect     ?city=Name  (multipart file)",
            "assistant":  "POST /api/assistant/chat     JSON {message}",
            "history":    "GET  /api/detections/         ?detection_type=&city=&limit=",
            "summary":    "GET  /api/detections/summary",
            "map":        "GET  /api/detections/map      ?detection_type=",
            "heatmap":    "GET  /api/detections/heatmap",
            "cities":     "GET  /api/detections/cities",
            "trends":     "GET  /api/trends/predict",
        },
    })


@app.route("/api/cities")
def cities():
    from db.crud import CITY_COORDS, CITY_TO_STATE
    return jsonify({
        "cities": [
            {"name": city, "state": CITY_TO_STATE.get(city), **coords}
            for city, coords in CITY_COORDS.items()
        ]
    })


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║  ScamX — AI CyberShield  v3.0  |  India Edition         ║")
    print("║  Database : cybershield.db  (SQLite)                    ║")
    print("║  API      : http://localhost:8000                        ║")
    print("║  Health   : http://localhost:8000/api/health             ║")
    print("╚══════════════════════════════════════════════════════════╝\n")
    app.run(host="0.0.0.0", port=8000, debug=True)
