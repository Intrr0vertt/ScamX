"""
WhatsApp Scam Analyzer — Flask Blueprint
POST /api/whatsapp/analyze  JSON {message, city}
Heuristic keyword + URL analysis — no trained NLP model.
URL trust is determined by parsing hostname with urllib.parse.urlparse.
"""
import time
import re
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from db import crud

whatsapp_bp = Blueprint("whatsapp", __name__)

URGENCY = [
    "urgent","immediately","now","expires","limited","block","suspended",
    "warning","final notice","last chance","deactivat","disconnect","action required",
    "claim now","claim your","collect your","redeem","hurry","offer ends",
]
FINANCIAL = [
    "upi","paytm","gpay","phonepe","payment","send money","bank account",
    "otp","prize","lottery","₹","transfer","neft","ifsc","rtgs","cashback",
    "lakh","crore","lucky draw","kbc","claim","registration fee","reward",
    "winner","won","winning","cash prize",
]
SOCIAL = ["forward","share","group","broadcast","viral","free","click","chain message"]
INDIA_KW = [
    "aadhaar","pan","kyc","jio","airtel","bsnl","sbi","hdfc","icici","irctc",
    "income tax","epfo","lic","trai","nsdl","uidai",
]

URL_RE = re.compile(r'https?://\S+|www\.\S+', re.I)

TRUSTED_DOMAINS = {
    "gov.in", "nic.in",
    "rbi.org.in", "npci.org.in", "uidai.gov.in",
    "sbi.co.in", "hdfc.com", "icicibank.com", "axisbank.com",
    "cybercrime.gov.in", "sachet.rbi.org.in",
}


def _is_trusted_url(raw_url: str) -> bool:
    try:
        parsed = urlparse(raw_url if raw_url.startswith("http") else "http://" + raw_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False
        for trusted in TRUSTED_DOMAINS:
            if host == trusted or host.endswith("." + trusted):
                return True
        return False
    except Exception:
        return False


def _analyze(message: str) -> dict:
    t0 = time.perf_counter()
    lt = message.lower()

    uh = [w for w in URGENCY if w in lt]
    fh = [w for w in FINANCIAL if w in lt]
    sh = [w for w in SOCIAL if w in lt]
    ih = [w for w in INDIA_KW if w in lt]
    urls = URL_RE.findall(message)
    susp_urls = [u for u in urls if not _is_trusted_url(u.split("?")[0])]
    emoji_ct = sum(1 for c in message if ord(c) > 0x1F300)

    score, reasons = 0, []
    if uh:
        pts = min(len(uh) * 13, 38); score += pts
        reasons.append(f"Urgency language ({len(uh)} indicators): {', '.join(uh[:3])}")
    if fh:
        pts = min(len(fh) * 12, 34); score += pts
        reasons.append(f"Financial keywords ({len(fh)} found): {', '.join(fh[:2])}")
    if ih:
        pts = min(len(ih) * 14, 30); score += pts
        reasons.append(f"India fraud pattern: {', '.join(ih[:2])}")
    if susp_urls:
        score += 22; reasons.append(f"Suspicious URL: {susp_urls[0][:55]}")
    elif urls:
        score += 10; reasons.append(f"URL detected ({len(urls)} link(s))")
    if sh:
        score += min(len(sh) * 8, 18)
        reasons.append(f"Viral/share-bait language: {', '.join(sh[:2])}")
    if emoji_ct > 5:
        score += 5; reasons.append(f"{emoji_ct} emojis — common in spam forwards")

    score = min(score, 98)
    confidence = round(min(42 + score * 0.56, 97), 1)
    level = "danger" if score > 58 else "warn" if score > 28 else "safe"
    prediction = "scam" if score > 58 else "suspicious" if score > 28 else "clean"
    verdict = "Potential Scam Message" if score > 58 else "Suspicious Message" if score > 28 else "Clean Message"

    return {
        "prediction": prediction,
        "confidence": confidence,
        "score": score,
        "verdict": verdict,
        "level": level,
        "reasons": reasons or ["No threat indicators found"],
        "method": "heuristic",
        "urls": urls,
        "suspicious_url": bool(susp_urls),
        "suspiciousUrl": bool(susp_urls),
        "categories": {
            "Urgency Language": round(min(len(uh) * 20, 98), 1),
            "Financial Keywords": round(min(len(fh) * 18, 98), 1),
            "India Fraud Pattern": round(min(len(ih) * 20, 98), 1),
            "Suspicious URL": round(min(len(susp_urls) * 30, 98), 1) if susp_urls else 3.0,
            "Social Engineering": round(min(len(sh) * 15, 92), 1),
        },
        "processing_time_ms": int((time.perf_counter() - t0) * 1000),
    }


@whatsapp_bp.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    city_raw = (body.get("city") or "").strip()
    if not message:
        return jsonify({"success": False, "error": {"code": "MISSING_MESSAGE", "message": "message is required."}}), 400
    if len(message) > 5_000:
        return jsonify({"success": False, "error": {"code": "MESSAGE_TOO_LONG", "message": "Message exceeds 5,000 character limit."}}), 400

    city = None
    try:
        city = crud.normalize_city(city_raw)
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_CITY", "message": str(e)}}), 400

    r = _analyze(message)
    det = crud.create_detection(
        detection_type="whatsapp", input_type="text",
        prediction=r["prediction"], confidence=r["confidence"],
        verdict=r["verdict"], level=r["level"],
        score=float(r["score"]), reasons=r["reasons"],
        city=city,
        processing_time_ms=r["processing_time_ms"],
    )
    return jsonify({"success": True, "data": {**r, "id": det["id"], "stored": True}})
