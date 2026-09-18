"""
Scam Trend Predictions — Flask Blueprint
GET /api/trends/predict
Combines real DB-driven predictions with static India baseline intelligence.
"""
from flask import Blueprint, jsonify
from db import crud

trends_bp = Blueprint("trends", __name__)

BASELINE = [
    {
        "icon": "🎭", "category": "deepfake", "source": "baseline",
        "title": "Deepfake Political Disinformation",
        "prediction": "State-actor campaigns using GAN architectures for regional language deepfakes. 218% rise in Q1 2025.",
        "risk_level": "High", "probability": 91,
    },
    {
        "icon": "🎙️", "category": "voice", "source": "baseline",
        "title": "Voice Cloning in Banking (Vishing)",
        "prediction": "AI voice synthesis impersonating SBI/HDFC/Paytm care. 340% rise in metro vishing attacks.",
        "risk_level": "High", "probability": 88,
    },
    {
        "icon": "📱", "category": "whatsapp", "source": "baseline",
        "title": "WhatsApp KYC Fraud Escalation",
        "prediction": "Fake TRAI/Jio/Airtel KYC deactivation messages with personalised targeting from leaked telecom data.",
        "risk_level": "Medium", "probability": 74,
    },
    {
        "icon": "💸", "category": "phishing", "source": "baseline",
        "title": "UPI QR Code Impersonation",
        "prediction": "Malicious QR codes near ATMs/shops. Collect-vs-Pay confusion rising in Tier-2 cities.",
        "risk_level": "Medium", "probability": 68,
    },
]

ICONS = {
    "phishing": "🎣",
    "voice":    "🎙️",
    "deepfake": "🎭",
    "whatsapp": "📱",
    "website":  "🌐",
}


@trends_bp.route("/predict", methods=["GET"])
def predict():
    data_driven_raw = crud.get_trend_predictions()

    formatted = [{
        "icon":           ICONS.get(p["detection_type"], "⚠️"),
        "title":          f"{p['detection_type'].capitalize()} trend — {p['state']}",
        "prediction":     p["prediction"],
        "risk_level":     p["risk_level"],
        "probability":    min(40 + p["recent_count"] * 15, 95),
        "category":       p["detection_type"],
        "detection_type": p["detection_type"],
        "source":         "data",
        "trend":          p["trend"],
        "recent_count":   p["recent_count"],
        "state":          p["state"],
    } for p in data_driven_raw]

    return jsonify({
        "data_driven":       formatted,
        "baseline":          BASELINE,
        "has_real_data":     len(formatted) > 0,
        "total_predictions": len(formatted) + len(BASELINE),
    })
