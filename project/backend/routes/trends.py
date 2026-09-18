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
        "icon": "alert", "category": "deepfake", "source": "baseline",
        "title": "Deepfake Political Disinformation",
        "prediction": "State-actor campaigns using GAN architectures for regional language deepfakes. Significant rise reported in 2024-2025.",
        "risk_level": "High", "heuristic_score": 91,
    },
    {
        "icon": "mic", "category": "voice", "source": "baseline",
        "title": "Voice Cloning in Banking (Vishing)",
        "prediction": "AI voice synthesis impersonating SBI/HDFC/Paytm customer care. Rising metro vishing attacks reported.",
        "risk_level": "High", "heuristic_score": 88,
    },
    {
        "icon": "chat", "category": "whatsapp", "source": "baseline",
        "title": "WhatsApp KYC Fraud Escalation",
        "prediction": "Fake TRAI/Jio/Airtel KYC deactivation messages with personalised targeting from leaked telecom data.",
        "risk_level": "Medium", "heuristic_score": 74,
    },
    {
        "icon": "rupee", "category": "phishing", "source": "baseline",
        "title": "UPI QR Code Impersonation",
        "prediction": "Malicious QR codes near ATMs/shops. Collect-vs-Pay confusion rising in Tier-2 cities.",
        "risk_level": "Medium", "heuristic_score": 68,
    },
]

ICONS = {
    "phishing": "alert-circle",
    "voice": "mic",
    "deepfake": "alert",
    "whatsapp": "chat",
    "website": "globe",
}


@trends_bp.route("/predict", methods=["GET"])
def predict():
    data_driven_raw = crud.get_trend_predictions()

    formatted = [{
        "icon": ICONS.get(p["detection_type"], "alert-triangle"),
        "title": f"{p['detection_type'].capitalize()} trend — {p['state']}",
        "prediction": p["prediction"],
        "risk_level": p["risk_level"],
        "heuristic_score": min(40 + p["recent_count"] * 15, 95),
        "category": p["detection_type"],
        "detection_type": p["detection_type"],
        "source": "data",
        "trend": p["trend"],
        "recent_count": p["recent_count"],
        "state": p["state"],
    } for p in data_driven_raw]

    return jsonify({
        "success": True,
        "data": {
            "data_driven": formatted,
            "baseline": BASELINE,
            "has_real_data": len(formatted) > 0,
            "total_predictions": len(formatted) + len(BASELINE),
        },
    })
