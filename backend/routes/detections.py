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


@detections_bp.route("/", methods=["GET"])
def list_detections():
    dtype  = request.args.get("detection_type")
    city   = request.args.get("city")
    state  = request.args.get("state")
    level  = request.args.get("level")
    limit  = min(int(request.args.get("limit",  200)), 1000)
    offset = max(int(request.args.get("offset",   0)), 0)

    rows = crud.get_detections(
        detection_type=dtype, city=city, state=state,
        level=level, limit=limit, offset=offset,
    )
    return jsonify(rows)


@detections_bp.route("/summary", methods=["GET"])
def summary():
    return jsonify(crud.get_session_summary())


@detections_bp.route("/map", methods=["GET"])
def map_markers():
    dtype = request.args.get("detection_type")
    return jsonify(crud.get_map_markers(dtype))


@detections_bp.route("/heatmap", methods=["GET"])
def heatmap():
    return jsonify(crud.get_state_heatmap())


@detections_bp.route("/cities", methods=["GET"])
def cities():
    return jsonify(crud.get_city_stats())


@detections_bp.route("/<int:det_id>", methods=["GET"])
def single(det_id: int):
    row = crud.get_detection_by_id(det_id)
    if not row:
        return jsonify({"error": f"Detection {det_id} not found."}), 404
    return jsonify(row)
