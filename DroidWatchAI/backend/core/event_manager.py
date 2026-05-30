# backend/core/event_manager.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Event Manager
# Owner: Gahan Shetty
#
# Central hub: receives events from sandbox/network/ai modules
# and broadcasts them over WebSocket to the frontend.
# ─────────────────────────────────────────────────────────────

import json
from flask_socketio import SocketIO
from shared.schemas import ThreatEvent, WSEvents
from backend.utils.logger import get_logger

logger = get_logger("event_manager")


class EventManager:
    def __init__(self, socketio: SocketIO):
        self.socketio = socketio
        self._event_store: dict[str, list] = {}  # scan_id → [events]

    # ── Emit a threat event ───────────────────────────────────
    def emit_threat(self, scan_id: str, event: ThreatEvent):
        """
        Called by sandbox/logcat reader when a new threat is detected.
        Stores the event and broadcasts it to all connected frontend clients.
        """
        if scan_id not in self._event_store:
            self._event_store[scan_id] = []

        event_dict = event.to_dict()
        self._event_store[scan_id].append(event_dict)

        logger.info(f"[{scan_id}] Emitting threat: {event.type} ({event.severity})")

        self.socketio.emit(WSEvents.NEW_THREAT, {
            "scan_id": scan_id,
            "event": event_dict
        })

    # ── Emit a defense action ─────────────────────────────────
    def emit_defense(self, scan_id: str, defense_event: dict):
        """
        Called when a defense action is triggered.
        Broadcasts to frontend so timeline updates in real time.
        """
        logger.info(f"[{scan_id}] Emitting defense: {defense_event.get('action')}")
        self.socketio.emit(WSEvents.DEFENSE_TRIGGER, {
            "scan_id": scan_id,
            "defense": defense_event
        })

    # ── Emit scan lifecycle events ────────────────────────────
    def emit_scan_started(self, scan_id: str, apk_name: str):
        self.socketio.emit(WSEvents.SCAN_STARTED, {
            "scan_id": scan_id,
            "apk_name": apk_name,
            "message": f"Sandbox analysis started for {apk_name}"
        })

    def emit_scan_complete(self, scan_id: str, summary: dict):
        self.socketio.emit(WSEvents.SCAN_COMPLETE, {
            "scan_id": scan_id,
            "summary": summary
        })

    # ── Emit AI summary ───────────────────────────────────────
    def emit_ai_summary(self, scan_id: str, summary: dict):
        """
        Called by Rajath's AI engine once threat scoring is done.
        """
        logger.info(f"[{scan_id}] Emitting AI summary: threat_level={summary.get('threat_level')}")
        self.socketio.emit(WSEvents.THREAT_SUMMARY, {
            "scan_id": scan_id,
            "summary": summary
        })

    # ── Replay mode (for demo without live sandbox) ───────────
    def replay_sample_events(self, scan_id: str, events_path: str, delay_ms: int = 800):
        """
        Reads sample_events.json and emits each event with a delay.
        Use this during demo if the sandbox is not cooperating.
        """
        import time
        import threading

        def _replay():
            with open(events_path) as f:
                events = json.load(f)

            logger.info(f"Replaying {len(events)} sample events for scan_id={scan_id}")
            self.emit_scan_started(scan_id, "demo_malware.apk")

            for raw_event in events:
                time.sleep(delay_ms / 1000)
                self.socketio.emit(WSEvents.NEW_THREAT, {
                    "scan_id": scan_id,
                    "event": raw_event
                })

            # Emit a canned summary at the end
            self.socketio.emit(WSEvents.SCAN_COMPLETE, {
                "scan_id": scan_id,
                "summary": {
                    "threat_level": "HIGH",
                    "total_score": 87,
                    "event_count": len(events),
                    "malware_type": "Spyware / Remote Access Trojan"
                }
            })

        thread = threading.Thread(target=_replay, daemon=True)
        thread.start()

    # ── Getters ───────────────────────────────────────────────
    def get_events(self, scan_id: str) -> list:
        return self._event_store.get(scan_id, [])
