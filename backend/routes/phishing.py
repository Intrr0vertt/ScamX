"""
Phishing Message Analyzer — Flask Blueprint
POST /api/phishing/analyze  JSON {text, city}
"""
import time, re
from flask import Blueprint, request, jsonify
from db import crud

phishing_bp = Blueprint("phishing", __name__)

URGENCY = [
    "urgent","immediately","expires","act now","click here","verify",
    "suspended","blocked","restricted","final notice","otp","kyc",
    "aadhaar","pan card","upi","paytm","account locked","action required",
    "warning","limited time","last chance","24 hours","account will be",
    "deactivated","disconnected","freeze","frozen","suspend","expired",
    "claim","redeem","hurry","offer expires","within 24","48 hours",
]
FINANCIAL = [
    "bank account","credit card","wire transfer","bitcoin","gift card",
    "payment","refund","tax refund","prize","lottery","cashback",
    "sbi","hdfc","icici","axis bank","rbi","income tax","irctc",
    "epfo","gpay","phonepe","send money","neft","ifsc",
    "lakh","crore","lucky draw","kbc","winner","won","winning",
    "cash prize","registration fee","reward","claim prize","collect",
]
DOMAIN_RE   = re.compile(r'https?://[^\s]+|www\.[^\s]+|\b[\w-]+\.(?:xyz|tk|ml|ga|cf|click|online|info|site|live|top|win)\b', re.I)
SAFE_DOMAIN = re.compile(r'\.(gov\.in|nic\.in|rbi\.org\.in|npci\.org\.in|uidai\.gov\.in|sbi\.co\.in|hdfc\.com|icicibank\.com|axisbank\.com)$', re.I)


def _analyze(text: str) -> dict:
    t0 = time.perf_counter()
    lt = text.lower()

    uh = [w for w in URGENCY   if w in lt]
    fh = [w for w in FINANCIAL if w in lt]

    urls      = DOMAIN_RE.findall(text)
    susp_urls = [u for u in urls if not SAFE_DOMAIN.search(u.split("?")[0])]
    has_url   = bool(urls)
    has_susp  = bool(susp_urls)
    caps      = [w for w in text.split() if w.isupper() and len(w) > 2]
    exclaim   = text.count("!")

    score, reasons = 0, []
    if uh:
        pts = min(len(uh) * 14, 42); score += pts
        reasons.append(f"Urgency triggers ({len(uh)} found): {', '.join(uh[:3])}")
    if fh:
        pts = min(len(fh) * 12, 36); score += pts
        reasons.append(f"Financial keywords ({len(fh)} found): {', '.join(fh[:3])}")
    if has_susp:
        score += 24; reasons.append(f"Suspicious URL: {susp_urls[0][:60]}")
    elif has_url:
        score += 12; reasons.append(f"URL detected ({len(urls)} link(s))")
    if caps:
        score += min(len(caps) * 3, 9); reasons.append(f"Aggressive caps: {' '.join(caps[:3])}")
    if exclaim > 3:
        score += 6; reasons.append(f"{exclaim} exclamation marks — pressure tactic")
    if len(text.split()) < 20 and (uh or fh):
        score += 8; reasons.append("Short high-pressure message — smishing format")

    score = min(round(score), 98)
    signals    = len(uh) + len(fh) + (3 if has_susp else 1 if has_url else 0)
    confidence = round(min(50 + signals * 6 + score * 0.15, 97), 1)
    level      = "danger" if score > 60 else "warn" if score > 28 else "safe"
    prediction = "phishing" if score > 60 else "suspicious" if score > 28 else "clean"
    verdict    = "Phishing Detected" if score > 60 else "Suspicious Message" if score > 28 else "Clean Message"

    return {
        "prediction": prediction,
        "score":      float(score),
        "confidence": confidence,
        "verdict":    verdict,
        "level":      level,
        "reasons":    reasons or ["No threat indicators found"],
        "categories": {
            "Urgency Language":  round(min(len(uh) * 22, 98), 1),
            "Financial Request": round(min(len(fh) * 20, 98), 1),
            "Link Danger":       round(min(len(susp_urls) * 30, 98) if susp_urls else (35 if has_url else 5), 1),
            "Identity Spoofing": round(min(score * 0.7, 96), 1),
            "Data Harvesting":   round(min(score * 0.5, 88), 1),
        },
        "processing_time_ms": int((time.perf_counter() - t0) * 1000),
    }


@phishing_bp.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    city = (body.get("city") or "").strip()
    if not text:
        return jsonify({"error": "text is required."}), 400
    if len(text) > 10_000:
        return jsonify({"error": "Text too long. Max 10,000 characters."}), 400

    r = _analyze(text)
    det = crud.create_detection(
        detection_type="phishing", input_type="text",
        prediction=r["prediction"], confidence=r["confidence"],
        verdict=r["verdict"], level=r["level"],
        score=r["score"], reasons=r["reasons"],
        city=city or None,
        processing_time_ms=r["processing_time_ms"],
    )
    return jsonify({**r, "id": det["id"], "stored": True})
