# backend/api/routes.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — API Route Registration
# Owner: Gahan Shetty
# ─────────────────────────────────────────────────────────────

from flask import Flask
from flask_socketio import SocketIO
from backend.api.upload import upload_bp
from backend.api.threat import threat_bp
from backend.api.defense import defense_bp
from backend.core.event_manager import EventManager


def register_routes(app: Flask, socketio: SocketIO, event_manager: EventManager):
    """Register all API blueprints."""

    # Pass shared dependencies into blueprints
    upload_bp.event_manager = event_manager
    upload_bp.socketio = socketio

    threat_bp.event_manager = event_manager
    defense_bp.event_manager = event_manager

    app.register_blueprint(upload_bp,  url_prefix="/api")
    app.register_blueprint(threat_bp,  url_prefix="/api")
    app.register_blueprint(defense_bp, url_prefix="/api")

    # ── Health check ─────────────────────────────────────────
    @app.route("/health")
    def health():
        return {"status": "ok", "service": "DroidWatch AI", "version": "0.1.0"}, 200

    @app.route("/api/status")
    def status():
        return {
            "status": "running",
            "sandbox_ready": True,
            "active_scans": len(event_manager.get_events("demo")),
        }, 200
