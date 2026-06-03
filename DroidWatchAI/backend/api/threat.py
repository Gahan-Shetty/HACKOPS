# backend/api/threat.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Threat Data Endpoints
# Owner: Gahan Shetty
# GET /api/threats/<scan_id>        → all events for a scan
# GET /api/threats/<scan_id>/summary → AI threat summary
# GET /api/threats/demo             → returns sample_events (no sandbox needed)
# ─────────────────────────────────────────────────────────────

import json
import os
from flask import Blueprint, jsonify
from backend.utils.logger import get_logger

threat_bp = Blueprint("threat", __name__)
logger = get_logger("threat")

SAMPLE_EVENTS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "shared", "sample_events.json"
)


@threat_bp.route("/threats/demo", methods=["GET"])
def get_demo_events():
    """
    Returns the sample_events.json for frontend demo/testing.
    Use this when the sandbox isn't running yet.
    """
    try:
        with open(SAMPLE_EVENTS_PATH) as f:
            events = json.load(f)
        return jsonify({"scan_id": "demo", "events": events, "count": len(events)}), 200
    except FileNotFoundError:
        return jsonify({"error": "sample_events.json not found in shared/"}), 404


@threat_bp.route("/threats/<scan_id>", methods=["GET"])
def get_threats(scan_id: str):
    """
    Returns all threat events for a scan_id.
    TODO: Gahan — replace stub with real DB query once database layer is wired.
    """
    if scan_id == "demo":
        return get_demo_events()

    from backend.database.db import get_conn
    conn = get_conn()
    rows = conn.execute("SELECT * FROM events WHERE scan_id=?", (scan_id,)).fetchall()
    events = [dict(row) for row in rows]
    conn.close()
    logger.info(f"Threat query for scan_id={scan_id}")
    return jsonify({
        "scan_id": scan_id,
        "events": [],
        "count": 0,
        "message": "Scan in progress or not found"
    }), 200


@threat_bp.route("/threats/<scan_id>/summary", methods=["GET"])
def get_summary(scan_id: str):
    """
    Returns the AI-generated threat summary for a scan.
    TODO: Rajath — this calls ai_engine/summarizer after Gahan wires in DB events.
    """
    # Stub summary for demo
    return jsonify({
        "scan_id": scan_id,
        "threat_level": "HIGH",
        "total_score": 87,
        "malware_type": "Spyware / Remote Access Trojan",
        "mitre_techniques": ["T1071.001", "T1568.002", "T1412", "T1398"],
        "ai_summary": (
            "The analyzed APK exhibits multiple high-severity behaviors consistent with "
            "spyware or RAT activity. It establishes persistent C2 communication, "
            "intercepts SMS messages (likely for OTP theft), drops hidden DEX payloads, "
            "and survives device reboots via a BOOT_COMPLETED receiver."
        ),
        "layer_breakdown": {
            "network": 3,
            "filesystem": 2,
            "system": 3
        }
    }), 200
