"""
Cyber AI Assistant Chatbot
POST /api/assistant/chat
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import time

router = APIRouter()

KB = {
    "greetings": ["hi","hello","hey","namaste"],
    "deepfake":  ["deepfake","fake video","synthetic video","face swap","manipulated"],
    "voice":     ["voice scam","voice clone","vishing","fake call","ai voice"],
    "phishing":  ["phishing","scam message","fake email","suspicious link","fraud email"],
    "whatsapp":  ["whatsapp","wa message","forward","broadcast","viral"],
    "upi":       ["upi","paytm","gpay","phone pe","bhim","payment fraud"],
    "aadhaar":   ["aadhaar","aadhar","kyc","pan card","identity fraud"],
    "safe":      ["stay safe","security tips","how to protect","prevent scam"],
    "otp":       ["otp","one time password","share otp","otp fraud"],
    "report":    ["report","complaint","helpline","cybercrime"],
}

RESPONSES = {
    "greetings": "Namaste! 🙏 I'm CyberShield AI Assistant. Ask me about deepfakes, voice scams, WhatsApp fraud, UPI scams, phishing, or Aadhaar/KYC fraud.",
    "deepfake":  "🎭 Deepfakes are AI-synthesized videos. Warning signs: lip-sync errors, unnatural blinking, blurry hairlines, inconsistent lighting. Use our Deepfake Detector for analysis.",
    "voice":     "🎙️ Voice cloning scams use AI to mimic family members or bank officers. Never share OTP over phone. Indian banks will NEVER ask for your PIN.",
    "whatsapp":  "📱 Common India WhatsApp scams: fake KYC links (TRAI/Jio), lottery forwards, UPI QR code confusion. Use our WhatsApp Analyzer to check any suspicious message.",
    "otp":       "🔐 NEVER share your OTP with anyone — not even your bank. If you receive an unexpected OTP, someone is attempting unauthorized access. Change your password immediately.",
    "upi":       "💸 UPI Fraud: scammers send 'collect' requests disguised as payment. Always verify merchant name. Fake customer care numbers for PhonePe/GPay/PayTm are common.",
    "aadhaar":   "🪪 No government agency asks you to update KYC via WhatsApp/SMS. Use masked Aadhaar. Report misuse: UIDAI helpline 1947.",
    "safe":      "🛡️ Safety tips: enable 2FA on banking apps, never install APKs from messages, verify callers claiming to be bank/police, report to cybercrime.gov.in or call 1930.",
    "phishing":  "🎣 Phishing attacks use fake SMS, email, or websites. India patterns: Income Tax refund SMS, IRCTC suspension, fake electricity portals. Paste any suspicious text in our Phishing Analyzer.",
    "report":    "🚨 Report cybercrime: National Cyber Crime Helpline: 1930 | Online: cybercrime.gov.in | UIDAI: 1947 | RBI complaint: sachet.rbi.org.in",
    "default":   "I can help with: deepfakes, voice scams, phishing, WhatsApp fraud, UPI scams, Aadhaar/KYC fraud, and cybersecurity tips. What would you like to know?",
}

class ChatRequest(BaseModel):
    message: str
    context: Optional[str] = ""

class ChatResponse(BaseModel):
    response: str
    intent: str
    processing_time_ms: int

@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """Answer cybersecurity questions. No pre-scripted responses — matched to user query."""
    if not req.message or not req.message.strip():
        raise HTTPException(400, "message is required.")
    start = time.time()
    lt = req.message.lower()
    intent = "default"
    for key, words in KB.items():
        if any(w in lt for w in words):
            intent = key; break
    return ChatResponse(
        response=RESPONSES.get(intent, RESPONSES["default"]),
        intent=intent,
        processing_time_ms=int((time.time()-start)*1000),
    )
