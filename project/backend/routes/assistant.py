"""
Cyber AI Assistant — Flask Blueprint
POST /api/assistant/chat  JSON {message}
Returns: response, intent, emergency_contacts, suggestions, processing_time_ms
Rule-based knowledge base — no LLM backend.
"""
import time
import re
from flask import Blueprint, request, jsonify

assistant_bp = Blueprint("assistant", __name__)

KB = {
    "greetings": ["hi","hello","hey","namaste","hii","good morning","good evening"],
    "deepfake":  ["deepfake","fake video","synthetic video","face swap",
                  "manipulated video","ai video","forged video","deepfakes"],
    "voice":     ["voice scam","voice clone","voice cloning","vishing",
                  "fake call","ai voice","synthetic voice","cloned voice"],
    "phishing":  ["phishing","scam message","fake email","suspicious link",
                  "fraud email","phishing link"],
    "whatsapp":  ["whatsapp","wa message","forward message","viral message",
                  "whatsapp scam","whatsapp fraud"],
    "upi":       ["upi","paytm","gpay","phonepe","bhim","payment fraud",
                  "qr code","upi fraud","collect request"],
    "aadhaar":   ["aadhaar","aadhar","kyc","pan card","identity fraud",
                  "uidai","kyc update"],
    "otp":       ["otp","one time password","share otp","otp fraud",
                  "didn't request","unauthorized otp"],
    "safe":      ["stay safe","security tips","how to protect","prevent scam",
                  "cybersecurity","safe banking","internet safety"],
    "report":    ["report","complaint","helpline","cybercrime",
                  "file complaint","1930","how to report"],
}

EXACT_MATCH = {"greetings"}

RESPONSES = {
    "greetings": (
        "Namaste! I'm CyberShield AI — your India cybersecurity assistant. "
        "I can help with deepfakes, voice cloning scams, WhatsApp fraud, UPI payment fraud, "
        "Aadhaar/KYC threats, phishing messages, and general cybersecurity tips. "
        "What would you like to know?"
    ),
    "deepfake": (
        "Deepfakes are AI-synthesised videos or images that look real. "
        "Warning signs: lip-sync errors, unnatural blinking, blurry edges around the face, "
        "inconsistent lighting, and unnatural skin texture. "
        "Use the Deepfake Detector module to upload and analyse any suspicious video or image."
    ),
    "voice": (
        "Voice cloning scams use AI to mimic bank officers, family members, or government officials. "
        "Indian banks will NEVER call and ask for your OTP, PIN, or UPI password. "
        "Red flags: extreme urgency, threats of account suspension, requests for UPI transfers. "
        "If suspicious — hang up and call the bank's official number yourself. "
        "Use the Voice Analyzer module to upload and check any suspicious audio file."
    ),
    "phishing": (
        "Phishing attacks in India commonly impersonate: Income Tax Dept, SBI/HDFC/ICICI, "
        "IRCTC, Jio/Airtel, and TRAI. They use fake URLs like sbi-verify.xyz or incometax-refund.xyz. "
        "Always check the domain in full before clicking. Official govt sites end in .gov.in or .nic.in. "
        "Paste any suspicious message into the Phishing Analyzer for instant analysis."
    ),
    "whatsapp": (
        "Common WhatsApp India scams: fake Jio/TRAI KYC deactivation links, lottery prize forwards, "
        "UPI payment screenshot fraud (fake payment proofs), fake job offers, and OTP theft. "
        "Never click links from unknown numbers. Do not forward chain messages. "
        "Use the WhatsApp Analyzer to instantly check any suspicious message."
    ),
    "upi": (
        "UPI fraud red flags: 'collect' or 'request money' notifications disguised as payments, "
        "QR codes near ATMs/shops that withdraw money instead of receiving, "
        "fake PhonePe/GPay customer care numbers, UPI PIN requests from callers. "
        "Rule: You NEVER need to enter your UPI PIN to RECEIVE money — only to send."
    ),
    "aadhaar": (
        "No government agency asks you to update KYC via WhatsApp, SMS, or phone call. "
        "Use masked Aadhaar (shows only last 4 digits) for most verifications. "
        "UIDAI official website: uidai.gov.in — never use any other site. "
        "Report Aadhaar misuse: UIDAI helpline 1947."
    ),
    "otp": (
        "NEVER share your OTP with anyone — not your bank, not police, not RBI. "
        "No legitimate entity will ever ask for your OTP over a call or message. "
        "If you received an unexpected OTP, someone is attempting unauthorized access to your account. "
        "Immediately change your password and contact your bank to freeze the account."
    ),
    "safe": (
        "India cybersecurity tips: "
        "(1) Enable 2-factor authentication on all banking apps. "
        "(2) Never install APKs sent via WhatsApp or Telegram. "
        "(3) Verify callers claiming to be from bank/TRAI/police by calling the official number yourself. "
        "(4) Check URLs carefully — official govt sites end in .gov.in. "
        "(5) Report suspicious activity at cybercrime.gov.in or call 1930."
    ),
    "report": (
        "Report cybercrime in India: "
        "National Helpline 1930 (24x7) — call immediately for financial fraud. "
        "Online portal: cybercrime.gov.in — file detailed complaint with screenshots. "
        "UIDAI (Aadhaar fraud): 1947. "
        "RBI Banking Ombudsman: sachet.rbi.org.in. "
        "Also file an FIR at your nearest police station for financial losses."
    ),
    "default": (
        "I can help with: deepfakes, voice cloning, phishing messages, WhatsApp scams, "
        "UPI fraud, Aadhaar/KYC threats, and cybersecurity tips for India. "
        "What would you like to know? You can also use the detection modules "
        "to analyse suspicious files or messages directly."
    ),
}

EMERGENCY_CONTACTS = [
    {"label": "Cyber Crime Helpline", "value": "1930",              "type": "phone"},
    {"label": "Report Online",        "value": "cybercrime.gov.in", "type": "url"},
    {"label": "UIDAI (Aadhaar)",      "value": "1947",              "type": "phone"},
    {"label": "RBI Banking Fraud",    "value": "sachet.rbi.org.in", "type": "url"},
    {"label": "TRAI (Telecom)",       "value": "1800-11-0420",      "type": "phone"},
]

SUGGESTIONS = {
    "greetings": ["What is a deepfake?","How to report cybercrime?","UPI fraud tips"],
    "deepfake":  ["How to spot a deepfake?","What is voice cloning?","Report cybercrime"],
    "voice":     ["Voice cloning signs","UPI fraud safety","How to report?"],
    "phishing":  ["How to spot phishing?","WhatsApp scam signs","Report cybercrime"],
    "whatsapp":  ["WhatsApp scam signs","UPI fraud tips","How to report?"],
    "upi":       ["UPI safety tips","Report payment fraud","Aadhaar safety"],
    "aadhaar":   ["Protect Aadhaar","Report KYC fraud","OTP safety"],
    "otp":       ["OTP safety tips","How to report?","UPI fraud"],
    "safe":      ["Cybersecurity tips","How to report?","Aadhaar safety"],
    "report":    ["Report cybercrime","Emergency contacts","Aadhaar safety"],
    "default":   ["What is deepfake?","UPI fraud tips","Report cybercrime"],
}


def _detect_intent(msg: str) -> str:
    lt = msg.lower()
    for key, words in KB.items():
        if key in EXACT_MATCH:
            matched = any(re.search(r'\b' + re.escape(w) + r'\b', lt) for w in words)
        else:
            matched = any(w in lt for w in words)
        if matched:
            return key
    return "default"


@assistant_bp.route("/chat", methods=["POST"])
def chat():
    t0 = time.perf_counter()
    body = request.get_json(silent=True) or {}
    msg = (body.get("message") or "").strip()
    if not msg:
        return jsonify({"success": False, "error": {"code": "MISSING_MESSAGE", "message": "message is required."}}), 400
    if len(msg) > 2_000:
        return jsonify({"success": False, "error": {"code": "MESSAGE_TOO_LONG", "message": "Message exceeds 2,000 character limit."}}), 400

    intent = _detect_intent(msg)
    return jsonify({
        "success": True,
        "data": {
            "response": RESPONSES.get(intent, RESPONSES["default"]),
            "intent": intent,
            "emergency_contacts": EMERGENCY_CONTACTS,
            "suggestions": SUGGESTIONS.get(intent, SUGGESTIONS["default"]),
            "processing_time_ms": int((time.perf_counter() - t0) * 1000),
        },
    })
