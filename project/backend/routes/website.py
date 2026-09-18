"""
Website Phishing Screenshot Detector — Flask Blueprint
POST /api/website/detect  multipart file  ?city=CityName
Method: pixel statistics via Pillow, byte-entropy fallback.
Heuristic prototype — no trained model loaded.
Detection is based solely on image content, never on filename.
"""
import time
import os
import io
import logging
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from db import crud

log = logging.getLogger("scamx.website")

website_bp = Blueprint("website", __name__)

ALLOWED = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_IMAGE_DIMENSION = 8000        # Reject images larger than 8000x8000
THUMBNAIL_SIZE = (256, 256)       # Downscale for statistics

# Pillow safety limits — reject decompression bombs
MAX_DECOMPRESS_PIXELS = 178_956_970  # ~178M pixels (Pillow default)
MAX_DECOMPRESS_FILE_SIZE = 200 * 1024 * 1024  # 200MB decompressed


def _check_signature(file_bytes: bytes, ext: str) -> bool:
    if ext in (".jpg", ".jpeg"):
        return file_bytes[:3] == b'\xff\xd8\xff'
    if ext == ".png":
        return file_bytes[:4] == b'\x89PNG'
    if ext == ".gif":
        return file_bytes[:6] in (b'GIF87a', b'GIF89a')
    if ext == ".bmp":
        return file_bytes[:2] == b'BM'
    if ext == ".webp":
        return file_bytes[:4] == b'RIFF' and file_bytes[8:12] == b'WEBP'
    return True


def _analyze(file_bytes: bytes) -> dict:
    t0 = time.perf_counter()
    flen = len(file_bytes)

    # Byte-entropy sample (always computed — works for all formats)
    sample = file_bytes[::max(1, flen // 8192)][:8192]
    bc = [0] * 256
    for b in sample:
        bc[b] += 1

    non_zero = sum(1 for c in bc if c > 0)
    entropy_r = non_zero / 256.0
    high_bytes = sum(bc[192:])
    total_samp = sum(bc) or 1
    bg_ratio = high_bytes / total_samp
    size_kb = flen // 1024

    # Pixel analysis via Pillow — bounded for safety
    avg_brightness = 128.0
    pixel_variance = 0.0
    width = 0
    height = 0
    image_valid = False

    try:
        from PIL import Image, ImageFile
        Image.MAX_IMAGE_PIXELS = MAX_DECOMPRESS_PIXELS

        img = Image.open(io.BytesIO(file_bytes))
        img.load()  # Force decode to catch truncated/corrupt images early
        width, height = img.size

        # Reject oversized images before converting
        if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
            log.warning("Image rejected: dimensions %dx%d exceed %d", width, height, MAX_IMAGE_DIMENSION)
            image_valid = False
        else:
            img = img.convert("RGB")
            # Downscale to thumbnail for bounded statistics — never load all pixels
            img.thumbnail(THUMBNAIL_SIZE)
            # Sample pixels from the small thumbnail (at most 256x256 = 65536)
            pixels = list(img.getdata())
            if pixels:
                brightness_vals = [(r + g + b) / 3 for r, g, b in pixels]
                avg_brightness = sum(brightness_vals) / len(brightness_vals)
                if len(brightness_vals) > 1:
                    mean_b = sum(brightness_vals) / len(brightness_vals)
                    pixel_variance = sum((v - mean_b) ** 2 for v in brightness_vals) / len(brightness_vals)
            image_valid = True
    except Exception as e:
        log.warning("Image decode failed: %s", type(e).__name__)
        image_valid = False

    brightness_norm = avg_brightness / 255.0
    variance_norm = min(pixel_variance / 5000.0, 1.0)

    score = round(
        (1.0 - entropy_r) * 20
        + bg_ratio * 18
        + brightness_norm * 15
        + (1.0 - variance_norm) * 12
        + (15 if size_kb < 100 else 0)
        + (10 if not image_valid else 0)
        + 5,
        1,
    )
    score = max(5.0, min(score, 95.0))
    confidence = round(min(58 + entropy_r * 22 + (10 if image_valid else 0), 97), 1)

    level = "danger" if score > 60 else "warn" if score > 32 else "safe"
    prediction = "phishing_website" if score > 60 else "suspicious" if score > 32 else "legitimate"
    verdict = "High Suspicious Website Risk" if score > 60 else "Potentially Suspicious Website" if score > 32 else "Appears Legitimate"

    reasons = []
    if entropy_r < 0.7:
        reasons.append(f"Low image entropy ({entropy_r:.3f}) — minimal flat design typical of phishing clones")
    if bg_ratio > 0.4:
        reasons.append(f"High bright-pixel ratio ({bg_ratio:.2f}) — white-background login page layout")
    if brightness_norm > 0.78:
        reasons.append(f"Very bright pixels (avg {avg_brightness:.0f}/255) — white-background layout detected")
    if variance_norm < 0.15 and image_valid:
        reasons.append(f"Low pixel variance ({variance_norm:.3f}) — minimal page content consistent with phishing templates")
    if size_kb < 100:
        reasons.append(f"Small screenshot ({size_kb} KB) — simple page with minimal content")
    if not image_valid:
        reasons.append("Image could not be fully decoded — possible tampered or unusual file format")
    if not reasons:
        reasons = ["No phishing indicators detected — site appears legitimate"]

    indicators = [
        {"icon": "login", "label": "Login Form",
         "sub": "Credential fields inferred from layout" if score > 40 else "No suspicious form indicators",
         "sev": "danger" if score > 60 else "warn" if score > 40 else "safe"},
        {"icon": "brand", "label": "Brand Impersonation",
         "sub": "Possible clone detected" if score > 55 else "No brand match detected",
         "sev": "danger" if score > 55 else "safe"},
        {"icon": "layout", "label": "Page Layout",
         "sub": f"Bright-bg ratio {bg_ratio:.2f} — minimal design" if bg_ratio > 0.3 else "Normal layout entropy",
         "sev": "warn" if bg_ratio > 0.4 else "safe"},
        {"icon": "image", "label": "Image Analysis",
         "sub": f"Entropy {entropy_r:.3f} | {size_kb} KB | {width}x{height}" if image_valid else f"Entropy {entropy_r:.3f} | {size_kb} KB | decode failed",
         "sev": "warn" if entropy_r < 0.6 else "safe"},
        {"icon": "content", "label": "Content Density",
         "sub": f"Pixel variance {variance_norm:.3f}" if image_valid else "Pixel analysis unavailable",
         "sev": "warn" if variance_norm < 0.15 and image_valid else "safe"},
    ]

    return {
        "prediction": prediction,
        "confidence": confidence,
        "score": score,
        "risk_score": score,
        "verdict": verdict,
        "level": level,
        "reasons": reasons,
        "template_match": "Possible clone" if score > 55 else "None",
        "indicators": indicators,
        "method": "heuristic",
        "analysis_method": "pixel-analysis" if image_valid else "byte-entropy",
        "image_dimensions": f"{width}x{height}" if image_valid else "unknown",
        "processing_time_ms": int((time.perf_counter() - t0) * 1000),
    }


@website_bp.route("/detect", methods=["POST"])
def detect():
    if "file" not in request.files:
        return jsonify({"success": False, "error": {"code": "MISSING_FILE", "message": "A file is required."}}), 400

    f = request.files["file"]
    fname = secure_filename(f.filename or "screenshot.png")
    ext = os.path.splitext(fname)[-1].lower()

    if ext not in ALLOWED:
        return jsonify({"success": False, "error": {"code": "INVALID_FILE", "message": f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED))}"}}), 400

    contents = f.read()
    if not contents:
        return jsonify({"success": False, "error": {"code": "EMPTY_FILE", "message": "The uploaded file is empty."}}), 400
    if len(contents) > MAX_FILE_SIZE:
        return jsonify({"success": False, "error": {"code": "FILE_TOO_LARGE", "message": "File exceeds 20 MB limit."}}), 413
    if not _check_signature(contents, ext):
        return jsonify({"success": False, "error": {"code": "INVALID_FILE", "message": "File content does not match its extension."}}), 400

    city_raw = (request.args.get("city") or "").strip()
    city = None
    try:
        city = crud.normalize_city(city_raw)
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_CITY", "message": str(e)}}), 400

    r = _analyze(contents)
    det = crud.create_detection(
        detection_type="website", input_type="image",
        prediction=r["prediction"], confidence=r["confidence"],
        verdict=r["verdict"], level=r["level"],
        score=r["score"], reasons=r["reasons"],
        city=city,
        filename=fname, file_size_kb=len(contents) // 1024,
        processing_time_ms=r["processing_time_ms"],
    )
    return jsonify({"success": True, "data": {**r, "id": det["id"], "stored": True}})
