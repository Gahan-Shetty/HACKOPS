# backend/app.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Main Backend Server
# Owner: Gahan Shetty
# Run: python app.py
# ─────────────────────────────────────────────────────────────

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
from dotenv import load_dotenv

from backend.api.routes import register_routes
from backend.core.event_manager import EventManager
from backend.database.db import init_db
from backend.utils.logger import get_logger

load_dotenv()
logger = get_logger("app")

# ── App Setup ─────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "droidwatch-dev-secret")
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "./uploads")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB max APK size

CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Init ──────────────────────────────────────────────────────
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
init_db()
event_manager = EventManager(socketio)

# ── Register Routes ───────────────────────────────────────────
register_routes(app, socketio, event_manager)

# ── WebSocket Events ──────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.info("Client connected")
    socketio.emit("status", {"message": "Connected to DroidWatch AI", "status": "ready"})

@socketio.on("disconnect")
def on_disconnect():
    logger.info("Client disconnected")

@socketio.on("ping")
def on_ping(data):
    socketio.emit("pong", {"message": "pong", "data": data})

# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting DroidWatch AI backend on port 5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
