# backend/api/defense.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Defense Simulation Endpoints
# Owner: Gahan Shetty
# POST /api/defense/<scan_id>/trigger  → trigger a defense action
# GET  /api/defense/<scan_id>/actions  → list triggered actions
# ─────────────────────────────────────────────────────────────

from flask import Blueprint, request, jsonify
from backend.utils.logger import get_logger
from shared.schemas import DefenseAction, WSEvents
from datetime import datetime
import uuid

defense_bp = Blueprint("defense", __name__)
logger = get_logger("defense")

# In-memory store for demo (replace with DB later)
_defense_log: list = []


DEFENSE_RESPONSES = {
    DefenseAction.BLOCK_IP: {
        "message": "Malicious IP blocked at firewall level",
        "icon": "🔥",
        "layer": "network"
    },
    DefenseAction.QUARANTINE_FILE: {
        "message": "Suspicious file moved to quarantine",
        "icon": "🗂️",
        "layer": "filesystem"
    },
    DefenseAction.REVOKE_PERMISSION: {
        "message": "Abused permission revoked from app",
        "icon": "🚫",
        "layer": "system"
    },
    DefenseAction.KILL_PROCESS: {
        "message": "Malicious process terminated",
        "icon": "💀",
        "layer": "system"
    },
    DefenseAction.ISOLATE_NETWORK: {
        "message": "App network access fully isolated",
        "icon": "🔒",
        "layer": "network"
    },
    DefenseAction.TERMINATE_SERVICE: {
        "message": "Background service forcefully stopped",
        "icon": "⛔",
        "layer": "system"
    },
}


@defense_bp.route("/defense/<scan_id>/trigger", methods=["POST"])
def trigger_defense(scan_id: str):
    """
    Triggers a simulated defense action for a given event/scan.
    Body: { "action": "block_ip", "event_id": "evt_001", "target": "185.220.101.47" }
    """
    data = request.get_json()
    if not data or "action" not in data:
        return jsonify({"error": "Missing 'action' in request body"}), 400

    action = data.get("action")
    event_id = data.get("event_id", "unknown")
    target = data.get("target", "unknown")

    if action not in DEFENSE_RESPONSES:
        return jsonify({"error": f"Unknown action: {action}"}), 400

    response_info = DEFENSE_RESPONSES[action]
    defense_event = {
        "id": f"def_{uuid.uuid4().hex[:6]}",
        "scan_id": scan_id,
        "event_id": event_id,
        "action": action,
        "target": target,
        "layer": response_info["layer"],
        "message": response_info["message"],
        "icon": response_info["icon"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "executed"
    }

    _defense_log.append(defense_event)
    logger.info(f"Defense triggered: {action} on {target} for scan {scan_id}")

    # TODO: Gahan — emit via socketio so dashboard updates live
    # socketio.emit(WSEvents.DEFENSE_TRIGGER, defense_event)

    return jsonify({"success": True, "defense_event": defense_event}), 200


@defense_bp.route("/defense/<scan_id>/actions", methods=["GET"])
def get_defense_actions(scan_id: str):
    """Returns all defense actions taken for a scan."""
    actions = [a for a in _defense_log if a["scan_id"] == scan_id]
    return jsonify({"scan_id": scan_id, "actions": actions, "count": len(actions)}), 200
