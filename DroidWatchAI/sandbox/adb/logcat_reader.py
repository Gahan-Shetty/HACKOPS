# sandbox/adb/logcat_reader.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Logcat Reader
# Owner: Gahan Shetty
#
# Streams ADB logcat output and parses lines into ThreatEvents.
# Calls EventManager to broadcast detections to the frontend.
# ─────────────────────────────────────────────────────────────

import subprocess
import threading
import re
from backend.utils.logger import get_logger
from backend.core.event_manager import EventManager
from shared.schemas import ThreatEvent, Severity, Layer, EventType

logger = get_logger("logcat_reader")

ADB = "adb"

# ── Signature Rules ───────────────────────────────────────────
# Each rule: (regex_pattern, event_type, layer, severity, description_template)
LOGCAT_RULES = [
    (
        r"connect\s+([\d\.]+):(\d+)",
        EventType.SUSPICIOUS_IP, Layer.NETWORK, Severity.HIGH,
        "Outbound TCP connection to {ip}:{port}"
    ),
    (
        r"DNS query.*?(\S+\.(?:tk|xyz|top|ru|cn|pw))",
        EventType.DNS_ABUSE, Layer.NETWORK, Severity.MEDIUM,
        "Suspicious TLD domain queried: {domain}"
    ),
    (
        r"File created.*?(\.dex|\.so|\.jar)",
        EventType.HIDDEN_FILE, Layer.FILESYSTEM, Severity.HIGH,
        "Potentially malicious file type created on device"
    ),
    (
        r"Permission request.*?(android\.permission\.\S+)",
        EventType.PERMISSION_ABUSE, Layer.SYSTEM, Severity.MEDIUM,
        "Runtime permission requested: {permission}"
    ),
    (
        r"Start service.*?/\.services\.\S+",
        EventType.BACKGROUND_SVC, Layer.SYSTEM, Severity.MEDIUM,
        "Background service started"
    ),
    (
        r"SMS received",
        EventType.SMS_INTERCEPT, Layer.SYSTEM, Severity.CRITICAL,
        "SMS interception detected — possible OTP theft"
    ),
    (
        r"BOOT_COMPLETED",
        EventType.PERSISTENCE_FILE, Layer.FILESYSTEM, Severity.HIGH,
        "App registered BOOT_COMPLETED — will auto-start on reboot"
    ),
    (
        r"AccessibilityService",
        EventType.ACCESSIBILITY, Layer.SYSTEM, Severity.HIGH,
        "Accessibility service activated — potential screen scraping"
    ),
]


class LogcatReader:
    def __init__(self, event_manager: EventManager, device_id: str = "emulator-5554"):
        self.event_manager = event_manager
        self.device_id = device_id
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self, scan_id: str, package_filter: str | None = None):
        """
        Start streaming logcat in a background thread.
        Optionally filter by package name to reduce noise.
        """
        self._running = True
        self._thread = threading.Thread(
            target=self._stream_logcat,
            args=(scan_id, package_filter),
            daemon=True
        )
        self._thread.start()
        logger.info(f"Logcat reader started for scan_id={scan_id}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Logcat reader stopped.")

    def _stream_logcat(self, scan_id: str, package_filter: str | None):
        cmd = [ADB, "-s", self.device_id, "logcat", "-v", "time"]
        if package_filter:
            # Filter to specific package + system logs
            cmd += ["--pid", self._get_pid(package_filter)]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                if not self._running:
                    process.terminate()
                    break
                self._parse_line(scan_id, line.strip())
        except Exception as e:
            logger.error(f"Logcat stream error: {e}")

    def _parse_line(self, scan_id: str, line: str):
        """Check line against all detection rules and emit events."""
        for pattern, event_type, layer, severity, desc_template in LOGCAT_RULES:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # Build description with capture groups
                groups = match.groups()
                description = desc_template
                if len(groups) >= 2:
                    description = desc_template.format(
                        ip=groups[0], port=groups[1],
                        domain=groups[0], permission=groups[0],
                        **{}
                    )
                elif len(groups) == 1:
                    description = desc_template.format(
                        ip=groups[0], domain=groups[0],
                        permission=groups[0], port="", **{}
                    )

                event = ThreatEvent(
                    layer=layer,
                    type=event_type,
                    severity=severity,
                    description=description,
                    raw=line[:300]  # cap raw log length
                )
                self.event_manager.emit_threat(scan_id, event)
                break  # one event per line

    def _get_pid(self, package_name: str) -> str:
        try:
            result = subprocess.run(
                [ADB, "-s", self.device_id, "shell", "pidof", package_name],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except Exception:
            return ""
