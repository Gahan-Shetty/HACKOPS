# DroidWatch AI — Team Setup Guide

## Quick Start (Day 1)

```bash
# 1. Clone and go to project root
cd DroidWatchAI

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy env file
cp .env.example .env

# 5. Run backend
python -m backend.app
```

Backend runs on → `http://localhost:5000`  
WebSocket on  → `ws://localhost:5000`

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/api/status` | Sandbox status |
| POST | `/api/upload` | Upload APK file |
| GET | `/api/scans` | List all scans |
| GET | `/api/threats/demo` | Get sample events (no sandbox needed) |
| GET | `/api/threats/<scan_id>` | Get events for a scan |
| GET | `/api/threats/<scan_id>/summary` | Get AI threat summary |
| POST | `/api/defense/<scan_id>/trigger` | Trigger a defense action |
| GET | `/api/defense/<scan_id>/actions` | List defense actions |

---

## WebSocket Events (for Thanvi)

Connect to `ws://localhost:5000` with socket.io client.

### Events emitted BY server → frontend

| Event | Payload | When |
|-------|---------|------|
| `status` | `{message, status}` | On connect |
| `new_threat` | `{scan_id, event}` | New detection |
| `defense_trigger` | `{scan_id, defense}` | Defense action fires |
| `scan_started` | `{scan_id, apk_name}` | Scan begins |
| `scan_complete` | `{scan_id, summary}` | Scan finished |
| `threat_summary` | `{scan_id, summary}` | AI summary ready |

### Events emitted BY frontend → server

| Event | Payload |
|-------|---------|
| `ping` | `{}` |

---

## Event Schema (shared/sample_events.json)

All threat events follow this structure:

```json
{
  "id": "evt_001",
  "timestamp": "2025-06-01T10:23:45Z",
  "layer": "network | filesystem | system",
  "type": "c2_callback | dns_abuse | hidden_file_creation | ...",
  "severity": "critical | high | medium | low | info",
  "description": "Human-readable description",
  "details": { ... },
  "raw": "original logcat line",
  "mitre_technique": "T1071.001",
  "defense_triggered": false
}
```

---

## Team Responsibilities

| Member | Module | Key Files |
|--------|--------|-----------|
| **Gahan** | Backend + Sandbox | `backend/`, `sandbox/` |
| **Rajath** | AI Engine | `ai_engine/` |
| **Dhanush** | Network Analysis | `network_analysis/` |
| **Thanvi** | Frontend | `frontend/` |

---

## Demo Mode (no sandbox)

If the emulator isn't running, the demo mode replays `shared/sample_events.json`:

```
GET /api/threats/demo
```

Or trigger replay via WebSocket:
```js
socket.emit('start_demo', { scan_id: 'demo' })
```
