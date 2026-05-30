# backend/api/upload.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — APK Upload Endpoint
# Owner: Gahan Shetty
# POST /api/upload  → receives APK, queues sandbox analysis
# ─────────────────────────────────────────────────────────────

import os
import uuid
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from backend.utils.logger import get_logger

upload_bp = Blueprint("upload", __name__)
logger = get_logger("upload")

ALLOWED_EXTENSIONS = {"apk"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@upload_bp.route("/upload", methods=["POST"])
def upload_apk():
    """
    Accepts an APK file upload.
    Returns a scan_id that the frontend uses to track progress via WebSocket.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only .apk files are accepted"}), 400

    # Save file with a unique scan ID
    scan_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], scan_id)
    os.makedirs(save_path, exist_ok=True)
    apk_path = os.path.join(save_path, filename)
    file.save(apk_path)

    logger.info(f"APK uploaded: {filename} → scan_id={scan_id}")

    # TODO: Gahan — call orchestrator.start_scan(scan_id, apk_path) here
    # For now, return the scan_id so frontend can subscribe to WS events

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "filename": filename,
        "message": "APK received. Sandbox analysis will begin shortly.",
        "ws_channel": f"scan_{scan_id}"
    }), 200


@upload_bp.route("/scans", methods=["GET"])
def list_scans():
    """Return list of all scan IDs (for demo/debug)."""
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    if not os.path.exists(upload_folder):
        return jsonify({"scans": []}), 200
    scans = [d for d in os.listdir(upload_folder) if os.path.isdir(os.path.join(upload_folder, d))]
    return jsonify({"scans": scans, "count": len(scans)}), 200
