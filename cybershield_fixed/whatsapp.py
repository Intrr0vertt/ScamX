"""
WhatsApp Scam Analyzer Router
POST /api/whatsapp/analyze
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import time, re

router = APIRouter()

class WhatsAppRequest(BaseModel):
    message: str
    city: Optional[str] = ""

class WhatsAppResult(BaseModel):
    prediction: str
    confidence: float
    score: int
    verdict: str
    level: str
    processing_time_ms: int
    reasons: List[str]
    urls: List[str]
    suspicious_url: bool
    categories: dict

def run_whatsapp_model(message: str) -> WhatsAppResult:
    start = time.time()
    lt = message.lower()
    urgency   = ['urgent','immediately','now','expires','limited','block','suspended','warning','final notice','last chance']
    financial = ['upi','paytm','gpay','payment','send money','bank','otp','prize','lottery','₹','transfer','account']
    social    = ['forward','share','group','broadcast','viral','free','click']
    india     = ['aadhaar','pan','kyc','jio','airtel','bsnl','sbi','hdfc','icici','irctc','income tax']

    uh = [w for w in urgency   if w in lt]
    fh = [w for w in financial if w in lt]
    sh = [w for w in social    if w in lt]
    ih = [w for w in india     if w in lt]
    urls = re.findall(r'https?://\S+|www\.\S+', message, re.IGNORECASE)
    suspicious_url = any(not re.search(r'\.(gov\.in|rbi\.org|npci\.org\.in|uidai\.gov\.in|sbi\.co\.in|hdfc\.com|icicibank\.com)', u) for u in urls)

    score, reasons = 0, []
    if uh: score += min(len(uh)*13, 38); reasons.append(f"Urgency language: {', '.join(uh[:3])}")
    if fh: score += min(len(fh)*12, 34); reasons.append(f"Financial keywords: {', '.join(fh[:2])}")
    if ih: score += min(len(ih)*15, 30); reasons.append(f"India fraud pattern: {', '.join(ih[:2])}")
    if urls: score += 18; reasons.append(f"{len(urls)} URL(s) detected")
    if suspicious_url: score += 16; reasons.append("Suspicious domain — not official Indian govt/bank site")
    if sh: score += min(len(sh)*8, 18); reasons.append("Viral forward / share bait language")
    score = min(score, 98)

    level      = "danger" if score > 58 else "warn" if score > 28 else "safe"
    prediction = "scam" if score > 58 else "suspicious" if score > 28 else "clean"
    verdict    = "WhatsApp Scam Detected" if score > 58 else "Suspicious Message" if score > 28 else "Clean Message"

    return WhatsAppResult(
        prediction=prediction, confidence=round(min(score*0.88+42, 97), 1),
        score=score, verdict=verdict, level=level,
        processing_time_ms=int((time.time()-start)*1000),
        reasons=reasons if reasons else ["No threat indicators found"],
        urls=urls, suspicious_url=suspicious_url,
        categories={
            "Urgency Language":    min(len(uh)*20, 98),
            "Financial Keywords":  min(len(fh)*18, 98),
            "India Fraud Pattern": min(len(ih)*22, 98),
            "Suspicious URL":      87 if suspicious_url else 3,
            "Social Engineering":  min(len(sh)*15, 92),
        },
    )

@router.post("/analyze", response_model=WhatsAppResult)
async def analyze_whatsapp(req: WhatsAppRequest):
    """Analyze a WhatsApp message for scam indicators. Requires non-empty message."""
    if not req.message or not req.message.strip():
        raise HTTPException(400, "message is required.")
    if len(req.message) > 5000:
        raise HTTPException(400, "Message too long. Max 5000 characters.")
    return run_whatsapp_model(req.message)
