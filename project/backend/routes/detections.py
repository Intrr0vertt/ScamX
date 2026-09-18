"""
Detections History API — Flask Blueprint
GET /api/detections/          — paginated history
GET /api/detections/summary   — dashboard KPIs
GET /api/detections/map       — markers with coordinates
GET /api/detections/heatmap   — state-level counts
GET /api/detections/cities    — per-city aggregated stats
GET /api/detections/<id>      — single record
"""
from flask import Blueprint, request, jsonify
from db import crud

detections_bp = Blueprint("detections", __name__)


def _safe_int(val, default, lo=None, hi=None):
    try:
        v = int(val)
    except (TypeError, ValueError):
        return default
    if lo is not None:
        v = max(v, lo)
    if hi is not None:
        v = min(v, hi)
    return v


@detections_bp.route("/", methods=["GET"])
def list_detections():
    try:
        dtype = crud.validate_detection_type(request.args.get("detection_type"))
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_TYPE", "message": str(e)}}), 400

    city_raw = (request.args.get("city") or "").strip()
    state = (request.args.get("state") or "").strip() or None

    city = None
    try:
        city = crud.normalize_city(city_raw)
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_CITY", "message": str(e)}}), 400

    try:
        level = crud.validate_level(request.args.get("level"))
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_LEVEL", "message": str(e)}}), 400

    limit = _safe_int(request.args.get("limit"), 100, lo=1, hi=500)
    offset = _safe_int(request.args.get("offset"), 0, lo=0)

    rows = crud.get_detections(
        detection_type=dtype, city=city, state=state,
        level=level, limit=limit, offset=offset,
    )
    total = crud.count_detections(
        detection_type=dtype, city=city, state=state, level=level,
    )
    return jsonify({
        "success": True,
        "data": rows,
        "pagination": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": (offset + limit) < total,
        },
    })


@detections_bp.route("/summary", methods=["GET"])
def summary():
    return jsonify({"success": True, "data": crud.get_session_summary()})


@detections_bp.route("/map", methods=["GET"])
def map_markers():
    try:
        dtype = crud.validate_detection_type(request.args.get("detection_type"))
    except ValueError as e:
        return jsonify({"success": False, "error": {"code": "INVALID_TYPE", "message": str(e)}}), 400
    return jsonify({"success": True, "data": crud.get_map_markers(dtype)})


@detections_bp.route("/heatmap", methods=["GET"])
def heatmap():
    return jsonify({"success": True, "data": crud.get_state_heatmap()})


@detections_bp.route("/cities", methods=["GET"])
def cities():
    return jsonify({"success": True, "data": crud.get_city_stats()})


@detections_bp.route("/<int:det_id>", methods=["GET"])
def single(det_id: int):
    row = crud.get_detection_by_id(det_id)
    if not row:
        return jsonify({"success": False, "error": {"code": "NOT_FOUND", "message": f"Detection {det_id} not found."}}), 404
    return jsonify({"success": True, "data": row})
