"""
CyberShield AI — Database Layer
SQLite via stdlib sqlite3. No external ORM required.
DB file: backend/cybershield.db  (auto-created on first run)
"""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'cybershield.db')

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS detections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    detection_type      TEXT    NOT NULL,
    input_type          TEXT    NOT NULL,
    prediction          TEXT    NOT NULL,
    confidence          REAL    NOT NULL,
    verdict             TEXT    NOT NULL,
    level               TEXT    NOT NULL,
    score               REAL,
    explanation         TEXT,
    city                TEXT,
    state               TEXT,
    lat                 REAL,
    lng                 REAL,
    filename            TEXT,
    file_size_kb        INTEGER,
    processing_time_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS ix_det_type  ON detections(detection_type);
CREATE INDEX IF NOT EXISTS ix_det_city  ON detections(city);
CREATE INDEX IF NOT EXISTS ix_det_state ON detections(state);
CREATE INDEX IF NOT EXISTS ix_det_level ON detections(level);

CREATE TABLE IF NOT EXISTS city_stats (
    city            TEXT PRIMARY KEY,
    state           TEXT,
    lat             REAL,
    lng             REAL,
    total           INTEGER DEFAULT 0,
    deepfake_count  INTEGER DEFAULT 0,
    voice_count     INTEGER DEFAULT 0,
    phishing_count  INTEGER DEFAULT 0,
    whatsapp_count  INTEGER DEFAULT 0,
    website_count   INTEGER DEFAULT 0,
    last_updated    TEXT
);
"""


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[DB] Initialised → {os.path.abspath(DB_PATH)}")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
