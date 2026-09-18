"""
ScamX — AI CyberShield Platform
Flask Backend v3.1 | India Edition

Run:
    cd backend
    pip install -r requirements.txt
    python main.py

API: http://localhost:8000
Docs: http://localhost:8000/api/health
"""
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, Response, request
from werkzeug.exceptions import RequestEntityTooLarge

# ── Configuration ─────────────────────────────────────────────────────────────
MAX_FILE_MB = int(os.environ.get("SCAMX_MAX_FILE_MB", "500"))
MAX_CONTENT_LENGTH = MAX_FILE_MB * 1024 * 1024
DEBUG = os.environ.get("SCAMX_DEBUG", "0").lower() in ("1", "true", "yes")
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "SCAMX_ALLOWED_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500,file://",
    ).split(",")
    if o.strip()
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("scamx")

# ── DB init ───────────────────────────────────────────────────────────────────
from db.database import init_db, get_conn  # noqa: E402

init_db()

# ── Blueprints ────────────────────────────────────────────────────────────────
from routes.deepfake   import deepfake_bp    # noqa: E402
from routes.voice      import voice_bp       # noqa: E402
from routes.phishing   import phishing_bp    # noqa: E402
from routes.whatsapp   import whatsapp_bp    # noqa: E402
from routes.website    import website_bp     # noqa: E402
from routes.detections import detections_bp  # noqa: E402
from routes.trends     import trends_bp      # noqa: E402
from routes.assistant  import assistant_bp   # noqa: E402
from routes.fraud      import fraud_bp       # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ── CORS ──────────────────────────────────────────────────────────────────────
@app.after_request
def cors(response: Response) -> Response:
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS or origin.startswith("file://"):
        response.headers["Access-Control-Allow-Origin"] = origin
    else:
        response.headers["Access-Control-Allow-Origin"] = "null"
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
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
app.register_blueprint(fraud_bp,      url_prefix="/api/fraud")


# ── Consistent error handlers ─────────────────────────────────────────────────
def _error(code: str, message: str, status: int):
    return jsonify({"success": False, "error": {"code": code, "message": message}}), status


@app.errorhandler(400)
def bad_request(e):
    return _error("BAD_REQUEST", str(e.description) if hasattr(e, "description") else "Bad request", 400)


@app.errorhandler(404)
def not_found(e):
    return _error("NOT_FOUND", "The requested resource was not found.", 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return _error("METHOD_NOT_ALLOWED", "HTTP method not allowed for this endpoint.", 405)


@app.errorhandler(413)
def too_large(e):
    return _error("FILE_TOO_LARGE", f"Uploaded file exceeds the {MAX_FILE_MB} MB limit.", 413)


@app.errorhandler(415)
def unsupported_media(e):
    return _error("UNSUPPORTED_MEDIA_TYPE", "The uploaded file media type is not supported.", 415)


@app.errorhandler(500)
def server_error(e):
    log.exception("Unhandled server error")
    return _error("INTERNAL_ERROR", "An unexpected server error occurred.", 500)


# ── Health & Cities ───────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    try:
        conn = get_conn()
        count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        conn.close()
        db_status = f"ok — {count} detections stored"
    except Exception:
        log.exception("Database health check failed")
        db_status = "error"

    return jsonify({
        "status": "operational",
        "platform": "ScamX — AI CyberShield  |  India Edition",
        "version": "3.1.0",
        "database": db_status,
        "endpoints": {
            "deepfake":   "POST /api/deepfake/analyze   ?city=Name  (multipart file)",
            "voice":      "POST /api/voice/analyze      ?city=Name  (multipart file)",
            "phishing":   "POST /api/phishing/analyze   JSON {text, city}",
            "whatsapp":   "POST /api/whatsapp/analyze   JSON {message, city}",
            "website":    "POST /api/website/detect     ?city=Name  (multipart file)",
            "assistant":  "POST /api/assistant/chat     JSON {message}",
            "history":    "GET  /api/detections/         ?detection_type=&city=&limit=&offset=",
            "summary":    "GET  /api/detections/summary",
            "map":        "GET  /api/detections/map      ?detection_type=",
            "heatmap":    "GET  /api/detections/heatmap",
            "cities":     "GET  /api/detections/cities",
            "trends":     "GET  /api/trends/predict",
            "fraud":      "POST /api/fraud/predict     JSON {V1..V28, Time, Amount}",
            "fraud_info": "GET  /api/fraud/model-info",
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
    log.info("ScamX — AI CyberShield v3.1 | India Edition")
    log.info("Database: cybershield.db (SQLite)")
    log.info("API: http://localhost:8000  |  Health: http://localhost:8000/api/health")
    log.info("Debug mode: %s", "ON" if DEBUG else "OFF")
    app.run(host="0.0.0.0", port=8000, debug=DEBUG)
