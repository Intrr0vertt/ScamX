"""
CyberShield AI — CRUD Operations
All database interactions are centralised here.
"""
import json
from datetime import date, timedelta
from typing import Optional, List, Dict, Any

from db.database import get_conn

# ── City metadata ─────────────────────────────────────────────────────────────
CITY_TO_STATE: Dict[str, str] = {
    "Bengaluru":      "Karnataka",
    "Hyderabad":      "Telangana",
    "Delhi":          "Delhi",
    "Mumbai":         "Maharashtra",
    "Chennai":        "Tamil Nadu",
    "Kolkata":        "West Bengal",
    "Pune":           "Maharashtra",
    "Ahmedabad":      "Gujarat",
    "Jaipur":         "Rajasthan",
    "Lucknow":        "Uttar Pradesh",
    "Chandigarh":     "Punjab",
    "Kochi":          "Kerala",
    "Bhopal":         "Madhya Pradesh",
    "Patna":          "Bihar",
    "Nagpur":         "Maharashtra",
    "Surat":          "Gujarat",
    "Indore":         "Madhya Pradesh",
    "Visakhapatnam":  "Andhra Pradesh",
    "Coimbatore":     "Tamil Nadu",
    "Vadodara":       "Gujarat",
}

CITY_COORDS: Dict[str, Dict[str, float]] = {
    "Bengaluru":     {"lat": 12.9716, "lng": 77.5946},
    "Hyderabad":     {"lat": 17.3850, "lng": 78.4867},
    "Delhi":         {"lat": 28.6139, "lng": 77.2090},
    "Mumbai":        {"lat": 19.0760, "lng": 72.8777},
    "Chennai":       {"lat": 13.0827, "lng": 80.2707},
    "Kolkata":       {"lat": 22.5726, "lng": 88.3639},
    "Pune":          {"lat": 18.5204, "lng": 73.8567},
    "Ahmedabad":     {"lat": 23.0225, "lng": 72.5714},
    "Jaipur":        {"lat": 26.9124, "lng": 75.7873},
    "Lucknow":       {"lat": 26.8467, "lng": 80.9462},
    "Chandigarh":    {"lat": 30.7333, "lng": 76.7794},
    "Kochi":         {"lat":  9.9312, "lng": 76.2673},
    "Bhopal":        {"lat": 23.2599, "lng": 77.4126},
    "Patna":         {"lat": 25.5941, "lng": 85.1376},
    "Nagpur":        {"lat": 21.1458, "lng": 79.0882},
    "Surat":         {"lat": 21.1702, "lng": 72.8311},
    "Indore":        {"lat": 22.7196, "lng": 75.8577},
    "Visakhapatnam": {"lat": 17.6868, "lng": 83.2185},
    "Coimbatore":    {"lat": 11.0168, "lng": 76.9558},
    "Vadodara":      {"lat": 22.3072, "lng": 73.1812},
}

CITY_ALIASES: Dict[str, str] = {
    "bangalore": "Bengaluru",
    "bombay": "Mumbai",
    "madras": "Chennai",
    "calcutta": "Kolkata",
    "new delhi": "Delhi",
    "ncr": "Delhi",
}

DETECTION_TYPES = {"deepfake", "voice", "phishing", "whatsapp", "website"}
LEVELS = {"danger", "warn", "safe"}


def _row_to_dict(row) -> dict:
    return dict(row) if row else {}


def normalize_city(city: Optional[str]) -> Optional[str]:
    """Normalize a city name. Returns None if empty, raises ValueError if unsupported."""
    if not city or not city.strip():
        return None
    city = city.strip()
    if city in CITY_TO_STATE:
        return city
    lower = city.lower()
    if lower in CITY_ALIASES:
        return CITY_ALIASES[lower]
    raise ValueError(f"Unsupported city '{city}'. Supported: {', '.join(sorted(CITY_TO_STATE))}")


def validate_detection_type(dtype: Optional[str]) -> Optional[str]:
    if not dtype:
        return None
    if dtype not in DETECTION_TYPES:
        raise ValueError(f"Invalid detection_type '{dtype}'. Valid: {', '.join(sorted(DETECTION_TYPES))}")
    return dtype


def validate_level(level: Optional[str]) -> Optional[str]:
    if not level:
        return None
    if level not in LEVELS:
        raise ValueError(f"Invalid level '{level}'. Valid: {', '.join(sorted(LEVELS))}")
    return level


# ── Create ────────────────────────────────────────────────────────────────────
def create_detection(
    *,
    detection_type: str,
    input_type: str,
    prediction: str,
    confidence: float,
    verdict: str,
    level: str,
    score: Optional[float] = None,
    reasons: Optional[List[str]] = None,
    city: Optional[str] = None,
    filename: Optional[str] = None,
    file_size_kb: Optional[int] = None,
    processing_time_ms: Optional[int] = None,
) -> dict:
    state  = CITY_TO_STATE.get(city) if city else None
    coords = CITY_COORDS.get(city, {}) if city else {}

    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO detections
               (detection_type, input_type, prediction, confidence, verdict, level,
                score, explanation, city, state, lat, lng, filename, file_size_kb,
                processing_time_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                detection_type,
                input_type,
                prediction,
                round(float(confidence), 2),
                verdict,
                level,
                round(float(score), 2) if score is not None else None,
                json.dumps(reasons) if reasons else None,
                city or None,
                state,
                coords.get("lat"),
                coords.get("lng"),
                filename,
                file_size_kb,
                processing_time_ms,
            ),
        )
        conn.commit()
        det_id = cur.lastrowid

        if city:
            _upsert_city_stats(conn, city, detection_type, state, coords)

        row = conn.execute("SELECT * FROM detections WHERE id=?", (det_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def _upsert_city_stats(conn, city, dtype, state, coords):
    existing = conn.execute(
        "SELECT * FROM city_stats WHERE city=?", (city,)
    ).fetchone()

    if existing:
        col_map = {
            "deepfake": "deepfake_count",
            "voice":    "voice_count",
            "phishing": "phishing_count",
            "whatsapp": "whatsapp_count",
            "website":  "website_count",
        }
        col = col_map.get(dtype, "total")
        conn.execute(
            f"UPDATE city_stats SET total=total+1, {col}={col}+1, "
            f"last_updated=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE city=?",
            (city,),
        )
    else:
        counts = {k: 0 for k in ["deepfake","voice","phishing","whatsapp","website"]}
        if dtype in counts:
            counts[dtype] = 1
        conn.execute(
            """INSERT INTO city_stats
               (city,state,lat,lng,total,deepfake_count,voice_count,
                phishing_count,whatsapp_count,website_count,last_updated)
               VALUES (?,?,?,?,1,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'))""",
            (city, state, coords.get("lat"), coords.get("lng"),
             counts["deepfake"], counts["voice"],
             counts["phishing"], counts["whatsapp"], counts["website"]),
        )
    conn.commit()


# ── Read ──────────────────────────────────────────────────────────────────────
def get_detections(
    *,
    detection_type: Optional[str] = None,
    city: Optional[str] = None,
    state: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[dict]:
    where, params = [], []
    if detection_type:
        where.append("detection_type=?"); params.append(detection_type)
    if city:
        where.append("city=?"); params.append(city)
    if state:
        where.append("state=?"); params.append(state)
    if level:
        where.append("level=?"); params.append(level)

    sql = "SELECT * FROM detections"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    result = []
    for row in rows:
        d = _row_to_dict(row)
        if d.get("explanation"):
            try:
                d["explanation"] = json.loads(d["explanation"])
            except Exception:
                d["explanation"] = [d["explanation"]]
        result.append(d)
    return result


def count_detections(
    *,
    detection_type: Optional[str] = None,
    city: Optional[str] = None,
    state: Optional[str] = None,
    level: Optional[str] = None,
) -> int:
    where, params = [], []
    if detection_type:
        where.append("detection_type=?"); params.append(detection_type)
    if city:
        where.append("city=?"); params.append(city)
    if state:
        where.append("state=?"); params.append(state)
    if level:
        where.append("level=?"); params.append(level)

    sql = "SELECT COUNT(*) FROM detections"
    if where:
        sql += " WHERE " + " AND ".join(where)

    conn = get_conn()
    try:
        return conn.execute(sql, params).fetchone()[0] or 0
    finally:
        conn.close()


def get_detection_by_id(det_id: int) -> Optional[dict]:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM detections WHERE id=?", (det_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    d = _row_to_dict(row)
    if d.get("explanation"):
        try:
            d["explanation"] = json.loads(d["explanation"])
        except Exception:
            d["explanation"] = [d["explanation"]]
    return d


def get_session_summary() -> Dict[str, Any]:
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] or 0
        by_type = {}
        for row in conn.execute(
            "SELECT detection_type, COUNT(*) as c FROM detections GROUP BY detection_type"
        ):
            by_type[row["detection_type"]] = row["c"]

        by_level = {}
        for row in conn.execute(
            "SELECT level, COUNT(*) as c FROM detections GROUP BY level"
        ):
            by_level[row["level"]] = row["c"]

        by_city = {}
        for row in conn.execute(
            "SELECT city, COUNT(*) as c FROM detections WHERE city IS NOT NULL GROUP BY city"
        ):
            by_city[row["city"]] = row["c"]
    finally:
        conn.close()

    return {
        "total":         total,
        "threats":       total,
        "by_type":       by_type,
        "by_level":      by_level,
        "by_city":       by_city,
        "deepfakes":     by_type.get("deepfake",  0),
        "voices":        by_type.get("voice",     0),
        "phishing":      by_type.get("phishing",  0),
        "whatsapp":      by_type.get("whatsapp",  0),
        "website":       by_type.get("website",   0),
        "danger_count":  by_level.get("danger",   0),
        "warn_count":    by_level.get("warn",     0),
        "safe_count":    by_level.get("safe",     0),
        "safety_score":  max(0, 100 - total * 5),
    }


def get_map_markers(detection_type: Optional[str] = None) -> List[dict]:
    conn = get_conn()
    try:
        sql = "SELECT * FROM detections WHERE lat IS NOT NULL"
        params = []
        if detection_type and detection_type != "all":
            sql += " AND detection_type=?"
            params.append(detection_type)
        sql += " ORDER BY id DESC"
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    result = []
    for row in rows:
        d = _row_to_dict(row)
        if d.get("explanation"):
            try:
                d["explanation"] = json.loads(d["explanation"])
            except Exception:
                d["explanation"] = [d["explanation"]]
        result.append(d)
    return result


def get_state_heatmap() -> Dict[str, Dict[str, int]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT state, detection_type, COUNT(*) as c "
            "FROM detections WHERE state IS NOT NULL "
            "GROUP BY state, detection_type"
        ).fetchall()
    finally:
        conn.close()

    result: Dict[str, Dict[str, int]] = {}
    for row in rows:
        st = row["state"]
        if st not in result:
            result[st] = {"total": 0}
        result[st][row["detection_type"]] = row["c"]
        result[st]["total"] += row["c"]
    return result


def get_city_stats() -> List[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM city_stats ORDER BY total DESC"
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_dict(r) for r in rows]


def get_trend_predictions() -> List[dict]:
    today     = date.today()
    week_ago  = (today - timedelta(days=7)).isoformat()
    two_weeks = (today - timedelta(days=14)).isoformat()

    conn = get_conn()
    try:
        recent = conn.execute(
            "SELECT state, detection_type, COUNT(*) as c FROM detections "
            "WHERE state IS NOT NULL AND timestamp >= ? "
            "GROUP BY state, detection_type",
            (week_ago,),
        ).fetchall()

        prev = conn.execute(
            "SELECT state, detection_type, COUNT(*) as c FROM detections "
            "WHERE state IS NOT NULL AND timestamp >= ? AND timestamp < ? "
            "GROUP BY state, detection_type",
            (two_weeks, week_ago),
        ).fetchall()
    finally:
        conn.close()

    prev_map = {(r["state"], r["detection_type"]): r["c"] for r in prev}
    results  = []

    for row in sorted(recent, key=lambda x: -x["c"]):
        st, dtype, rc = row["state"], row["detection_type"], row["c"]
        pc = prev_map.get((st, dtype), 0)

        if pc == 0:
            trend = "new"; change = 100
        else:
            change = round((rc - pc) / pc * 100)
            trend  = "increasing" if change > 10 else "decreasing" if change < -10 else "stable"

        risk = "High" if rc >= 3 else "Medium" if rc >= 2 else "Low"
        labels = {
            "phishing": "phishing attacks",
            "deepfake": "deepfake incidents",
            "voice":    "voice cloning scams",
            "whatsapp": "WhatsApp fraud",
            "website":  "phishing websites",
        }
        label = labels.get(dtype, dtype)
        if trend == "increasing":
            pred = f"{label.capitalize()} in {st} are trending upward — {rc} detection(s) this week."
        elif trend == "new":
            pred = f"New {label} activity detected in {st} — {rc} case(s) this week with no prior baseline."
        elif trend == "decreasing":
            pred = f"{label.capitalize()} in {st} appear to be declining based on recent data."
        else:
            pred = f"{label.capitalize()} in {st} remain stable — {rc} detection(s) this week."

        results.append({
            "state":          st,
            "detection_type": dtype,
            "recent_count":   rc,
            "previous_count": pc,
            "trend":          trend,
            "change_pct":     change,
            "risk_level":     risk,
            "prediction":     pred,
        })

    return results[:10]
