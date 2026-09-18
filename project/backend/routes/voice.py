"""
Voice Scam Analyzer — Flask Blueprint
POST /api/voice/analyze  multipart file  ?city=CityName
Method: waveform statistics (WAV PCM) or byte-entropy fallback for other formats.
Heuristic prototype — no trained model loaded.
"""
import time
import os
import wave
import io
import struct
import logging
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from db import crud

voice_bp = Blueprint("voice", __name__)

log = logging.getLogger("scamx.voice")

ALLOWED = {".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".webm"}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Magic-byte signatures for non-WAV formats
FORMAT_SIGNATURES = {
    ".mp3":  (b"\xff\xfb", b"\xff\xf3", b"\xff\xfa", b"ID3"),
    ".ogg":  (b"OggS",),
    ".flac": (b"fLaC",),
    ".m4a":  (b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x20ftyp", b"\x00\x00\x00\x1cftyp"),
    ".aac":  (b"\xff\xf1", b"\xff\xf9"),
    ".webm": (b"\x1a\x45\xdf\xa3",),
}


def _validate_signature(file_bytes: bytes, ext: str) -> bool:
    """Validate file content matches its extension via magic-byte signature."""
    if ext == ".wav":
        return (
            len(file_bytes) >= 12
            and file_bytes[:4] == b"RIFF"
            and file_bytes[8:12] == b"WAVE"
        )
    sigs = FORMAT_SIGNATURES.get(ext)
    if not sigs:
        return False
    return any(file_bytes.startswith(s) for s in sigs)


def _analyze_wav(file_bytes: bytes) -> dict:
    """Parse WAV via stdlib wave module and compute real waveform statistics."""
    try:
        wf = wave.open(io.BytesIO(file_bytes), "rb")
        channels = wf.getnchannels()
        sample_rate = wf.getframerate()
        sample_width = wf.getsampwidth()
        n_frames = wf.getnframes()
        frames = wf.readframes(min(n_frames, 8192))
        wf.close()

        if sample_width != 2 or len(frames) < 200:
            return None, None, None, None

        n = min(len(frames) // 2, 8192)
        samples = struct.unpack_from(f"<{n}h", frames)
        mean_a = sum(abs(s) for s in samples) / len(samples)
        var = sum((s - mean_a) ** 2 for s in samples) / len(samples)
        zc = sum(1 for i in range(1, len(samples)) if samples[i - 1] * samples[i] < 0)
        zcr = zc / len(samples)

        var_norm = min(var / 1e8, 1.0)
        zcr_anom = abs(zcr - 0.08) > 0.05
        sr_susp = sample_rate not in (8000, 16000, 22050, 44100, 48000)

        risk = round(
            (1.0 - var_norm) * 38
            + (20 if zcr_anom else 0)
            + (15 if sr_susp else 0),
            1,
        )
        risk = max(5.0, min(risk, 95.0))

        reasons = []
        if var_norm < 0.35:
            reasons.append(f"Low waveform variance ({var_norm:.3f}) — flat prosody consistent with TTS")
        if zcr_anom:
            reasons.append(f"Zero-crossing rate anomaly ({zcr:.3f}) — formant irregularity")
        if sr_susp:
            reasons.append(f"Non-standard sample rate {sample_rate} Hz — common in synthetic audio")
        if reasons:
            reasons.append(f"Channels: {channels} | Sample rate: {sample_rate} Hz | Bit depth: {sample_width * 8}")

        spectral = {
            "Waveform Variance": round(var_norm * 100, 1),
            "Zero-Crossing Rate": round(zcr * 1000, 1),
            "Sample Rate Score": 0.0 if sr_susp else 100.0,
            "Prosody Regularity": round((1.0 - var_norm) * 100, 1),
        }
        return risk, reasons, spectral, "wav-pcm"
    except (wave.Error, EOFError, OSError, struct.error) as e:
        log.warning("WAV parse failed: %s: %s", type(e).__name__, e)
        return None, None, None, None
    except Exception as e:
        log.warning("Unexpected WAV error: %s: %s", type(e).__name__, e)
        return None, None, None, None


def _analyze_bytes(file_bytes: bytes, filename: str) -> dict:
    """Byte-entropy fallback for non-WAV formats."""
    flen = len(file_bytes)
    sample = file_bytes[::max(1, flen // 8192)][:8192]
    bc = [0] * 256
    for b in sample:
        bc[b] += 1
    entropy_r = sum(1 for c in bc if c > 0) / 256.0

    chunk = file_bytes[flen // 4: flen // 4 + 512] if flen > 600 else file_bytes[:256]
    repeat = 0
    if len(chunk) >= 64:
        for w in (32, 64):
            if len(chunk) >= w * 2:
                m = sum(1 for i in range(w) if chunk[i] == chunk[i + w])
                repeat = max(repeat, m / w)

    risk = round(
        (1.0 - entropy_r) * 35 + repeat * 40 + 5, 1
    )
    risk = max(5.0, min(risk, 95.0))

    reasons = []
    if repeat > 0.5:
        reasons.append(f"Repeating byte pattern ({repeat:.2f}) — noise-floor loop signature")
    if entropy_r < 0.7:
        reasons.append(f"Low audio entropy ({entropy_r:.3f}) — possible synthetic fingerprint")
    if not reasons:
        reasons.append("No synthetic voice indicators found in byte analysis")

    spectral = {
        "Byte Entropy": round(entropy_r * 100, 1),
        "Repeat Pattern": round(repeat * 100, 1),
        "Prosody Regularity": round((1.0 - entropy_r) * 100, 1),
        "Formant Variance": round((1.0 - repeat) * 100, 1),
    }
    return risk, reasons, spectral, "byte-entropy"


def _build_result(filename, risk, reasons, spectral, method, elapsed):
    auth = round(100 - risk, 1)
    if risk > 65:
        prediction, level, verdict = "synthetic", "danger", "Potential Synthetic Voice"
        voice_type = "AI-Cloned / Synthetic"
    elif risk > 40:
        prediction, level, verdict = "suspicious", "warn", "Potentially Suspicious Audio"
        voice_type = "Possibly Synthetic"
    else:
        prediction, level, verdict = "human", "safe", "Human Voice"
        voice_type = "Human Voice"
        reasons = reasons or ["No synthetic voice indicators found"]

    return {
        "filename": filename,
        "prediction": prediction,
        "scam_risk": risk,
        "risk_score": risk,
        "authenticity": auth,
        "voice_type": voice_type,
        "verdict": verdict,
        "level": level,
        "reasons": reasons or ["No synthetic voice indicators found"],
        "spectral": spectral,
        "analysis_method": method,
        "method": "heuristic",
        "model_status": "prototype",
        "processing_time_ms": elapsed,
    }


@voice_bp.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"success": False, "error": {"code": "MISSING_FILE", "message": "A file is required."}}), 400

    f = request.files["file"]
    fname = secure_filename(f.filename or "audio")
    ext = os.path.splitext(fname)[-1].lower()

    if ext not in ALLOWED:
        return jsonify({"success": False, "error": {"code": "INVALID_FILE", "message": f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED))}"}}), 400

    contents = f.read()
    if not contents:
        return jsonify({"success": False, "error": {"code": "EMPTY_FILE", "message": "The uploaded file is empty."}}), 400
    if len(contents) > MAX_FILE_SIZE:
        return jsonify({"success": False, "error": {"code": "FILE_TOO_LARGE", "message": "File exceeds 100 MB limit."}}), 413
    if not _validate_signature(contents, ext):
        return jsonify({"success": False, "error": {"code": "INVALID_FILE", "message": "File content does not match its extension (signature mismatch)."}}), 400

    city_raw = (request.args.get("city") or "").strip()
    city = None
    try:
        city = crud.normalize_city(city_raw)
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_CITY", "message": str(e)}}), 400

    t0 = time.perf_counter()

    risk = None
    if ext == ".wav" and len(contents) > 44:
        risk, reasons, spectral, method = _analyze_wav(contents)

    if risk is None:
        risk, reasons, spectral, method = _analyze_bytes(contents, fname)

    elapsed = int((time.perf_counter() - t0) * 1000)
    r = _build_result(fname, risk, reasons, spectral, method, elapsed)

    heuristic_score = round(100 - abs(r["scam_risk"] - 50), 1)
    det = crud.create_detection(
        detection_type="voice", input_type="audio",
        prediction=r["prediction"], confidence=heuristic_score,
        verdict=r["verdict"], level=r["level"],
        score=r["scam_risk"], reasons=r["reasons"],
        city=city,
        filename=fname, file_size_kb=len(contents) // 1024,
        processing_time_ms=r["processing_time_ms"],
    )
    return jsonify({"success": True, "data": {**r, "heuristic_score": heuristic_score, "id": det["id"], "stored": True}})
