# analyzer.py
# ─────────────────────────────────────────────────────────────
# DroidWatch AI — Logcat Analyzer
# Owner: Gahan Shetty
#
# Reads a logcat dump (logs.txt) and produces structured threat
# events compatible with the shared ThreatEvent schema.
#
# Usage:
#   python analyzer.py                    # analyze logs.txt
#   python analyzer.py --file custom.txt  # custom log file
#   python analyzer.py --json             # output as JSON
#   python analyzer.py --post             # POST events to backend
# ─────────────────────────────────────────────────────────────

import re
import json
import argparse
from datetime import datetime
from collections import defaultdict


# ── Detection Rules ───────────────────────────────────────────
# Each rule: (keyword/pattern, layer, severity, clean_description)
# Order matters — first match wins per line (prevents duplicate alerts)

RULES = [
    # CRITICAL
    (r"sms|read_sms|send_sms|intercept.*sms",
     "system",     "CRITICAL", "SMS interception or access detected"),
    (r"accessibilityservice|accessibility.*enabled",
     "system",     "CRITICAL", "Accessibility service activated (screen scraping risk)"),

    # HIGH
    (r"connect\s+\d{1,3}(?:\.\d{1,3}){3}|http[s]?://|okhttp|volley",
     "network",    "HIGH",     "Outbound network connection initiated"),
    (r"\.dex|\.so|\.jar|droiddex|classloader",
     "filesystem", "HIGH",     "Dynamic code loading or payload file detected"),
    (r"boot_completed|bootreceiver|autostart",
     "filesystem", "HIGH",     "Persistence mechanism via BOOT_COMPLETED receiver"),
    (r"c2|command.*control|beacon|heartbeat.*remote",
     "network",    "HIGH",     "Possible C2 communication pattern"),
    (r"root|su\b|superuser|privilege.*escalat",
     "system",     "HIGH",     "Privilege escalation or root access attempt"),

    # MEDIUM
    (r"background.*service|startservice|foreground.*service",
     "system",     "MEDIUM",   "Background service started"),
    (r"dns|nslookup|getaddrinfo",
     "network",    "MEDIUM",   "DNS resolution activity"),
    (r"hidden|setvisibility.*gone|\.\s*hidden",
     "filesystem", "MEDIUM",   "Hidden UI element or file operation detected"),
    (r"camera|microphone|audio.*record|mediarecorder",
     "system",     "MEDIUM",   "Sensitive hardware access (camera/mic)"),
    (r"contact|read_contacts|call_log",
     "system",     "MEDIUM",   "Contact or call log access detected"),

    # LOW
    (r"permission|requestpermission|checkpermission",
     "system",     "LOW",      "Permission request or check"),
    (r"network|connectivity|wifi|mobile.*data",
     "network",    "LOW",      "Network state check"),
    (r"storage|read_external|write_external",
     "filesystem", "LOW",      "External storage access"),
    (r"service",
     "system",     "LOW",      "Generic service activity"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25}

MITRE_MAP = {
    "SMS interception":          "T1412",
    "Accessibility service":     "T1417",
    "Outbound network":          "T1071.001",
    "Dynamic code loading":      "T1027",
    "Persistence mechanism":     "T1398",
    "Possible C2":               "T1132",
    "Privilege escalation":      "T1068",
    "Background service":        "T1624",
    "DNS resolution":            "T1568",
    "Sensitive hardware":        "T1429",
    "Contact or call log":       "T1636",
    "Permission":                "T1404",
}


# ── Parser ────────────────────────────────────────────────────

def match_rule(line: str):
    """Returns (layer, severity, description) for the first matching rule, or None."""
    for pattern, layer, severity, description in RULES:
        if re.search(pattern, line, re.IGNORECASE):
            return layer, severity, description
    return None


def get_mitre(description: str) -> str:
    for key, technique in MITRE_MAP.items():
        if key.lower() in description.lower():
            return technique
    return ""


def parse_timestamp(line: str) -> str:
    """Try to extract timestamp from logcat line format: MM-DD HH:MM:SS.mmm"""
    match = re.match(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)", line)
    if match:
        ts = match.group(1)
        year = datetime.now().year
        try:
            dt = datetime.strptime(f"{year}-{ts}", "%Y-%m-%d %H:%M:%S.%f")
            return dt.isoformat() + "Z"
        except ValueError:
            pass
    return datetime.utcnow().isoformat() + "Z"


def analyze(log_path: str) -> list[dict]:
    """
    Read a logcat file and return a list of structured threat events.
    Each line matches at most ONE rule (no duplicate alerts per line).
    """
    try:
        with open(log_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {log_path}")
        return []

    events = []
    seen_lines = set()
    event_counter = defaultdict(int)

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or len(line) < 10:
            continue

        # Deduplicate near-identical lines (same first 80 chars)
        fingerprint = line[:80].lower()
        if fingerprint in seen_lines:
            continue
        seen_lines.add(fingerprint)

        result = match_rule(line)
        if result:
            layer, severity, description = result
            event_counter[severity] += 1
            event_id = f"evt_{len(events) + 1:04d}"

            events.append({
                "id":               event_id,
                "timestamp":        parse_timestamp(line),
                "layer":            layer,
                "severity":         severity,
                "description":      description,
                "mitre_technique":  get_mitre(description),
                "raw":              line[:300],
                "line_number":      i + 1,
                "defense_triggered": False,
            })

    # Sort by severity (CRITICAL first)
    events.sort(key=lambda e: SEVERITY_ORDER.get(e["severity"], 99))
    return events


# ── Threat Scoring ────────────────────────────────────────────

def compute_threat_level(events: list[dict]) -> tuple[str, int]:
    if not events:
        return "CLEAN", 0

    total = sum(SEVERITY_SCORE.get(e["severity"], 0) for e in events)
    score = min(100, total // max(len(events), 1) + (len(events) * 2))

    if any(e["severity"] == "CRITICAL" for e in events):
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return level, score


def build_summary(events: list[dict], apk_name: str) -> dict:
    threat_level, score = compute_threat_level(events)

    layer_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    mitre_set = set()

    for e in events:
        layer_counts[e["layer"]] += 1
        severity_counts[e["severity"]] += 1
        if e["mitre_technique"]:
            mitre_set.add(e["mitre_technique"])

    # Infer malware type from patterns
    has_sms     = any("SMS"         in e["description"] for e in events)
    has_c2      = any("C2"          in e["description"] for e in events)
    has_access  = any("Accessibility" in e["description"] for e in events)
    has_root    = any("Privilege"   in e["description"] for e in events)

    if has_sms and has_c2:
        malware_type = "Spyware / Banking Trojan"
    elif has_access and has_sms:
        malware_type = "Accessibility-based Spyware"
    elif has_root:
        malware_type = "Rootkit / Privilege Escalation Malware"
    elif has_c2:
        malware_type = "Remote Access Trojan (RAT)"
    elif has_sms:
        malware_type = "SMS Stealer"
    else:
        malware_type = "Potentially Unwanted Application (PUA)"

    return {
        "apk_name":         apk_name,
        "threat_level":     threat_level,
        "total_score":      score,
        "event_count":      len(events),
        "severity_counts":  dict(severity_counts),
        "layer_breakdown":  dict(layer_counts),
        "malware_type":     malware_type,
        "mitre_techniques": sorted(mitre_set),
        "analyzed_at":      datetime.utcnow().isoformat() + "Z",
    }


# ── Console Report ────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[92m",   # green
}
RESET = "\033[0m"


def print_report(events: list[dict], summary: dict):
    print("\n" + "═" * 60)
    print("  🛡  DROIDWATCH AI — THREAT ANALYSIS REPORT")
    print("═" * 60)
    print(f"  APK       : {summary['apk_name']}")
    print(f"  Analyzed  : {summary['analyzed_at']}")
    print(f"  Malware   : {summary['malware_type']}")
    print()

    level  = summary['threat_level']
    score  = summary['total_score']
    color  = SEVERITY_COLOR.get(level, "")
    bar    = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"  THREAT LEVEL : {color}{level}{RESET}")
    print(f"  SCORE        : {color}{bar} {score}/100{RESET}")
    print()

    sc = summary['severity_counts']
    print(f"  Events   : {summary['event_count']} total  |  "
          f"\033[91mCRITICAL:{sc.get('CRITICAL',0)}\033[0m  "
          f"\033[93mHIGH:{sc.get('HIGH',0)}\033[0m  "
          f"\033[94mMEDIUM:{sc.get('MEDIUM',0)}\033[0m  "
          f"\033[92mLOW:{sc.get('LOW',0)}\033[0m")

    lb = summary['layer_breakdown']
    print(f"  Layers   : Network:{lb.get('network',0)}  "
          f"Filesystem:{lb.get('filesystem',0)}  "
          f"System:{lb.get('system',0)}")

    if summary['mitre_techniques']:
        print(f"  MITRE    : {', '.join(summary['mitre_techniques'])}")

    print("\n" + "─" * 60)
    print("  DETECTED EVENTS")
    print("─" * 60)

    for e in events:
        color = SEVERITY_COLOR.get(e["severity"], "")
        mitre = f" [{e['mitre_technique']}]" if e["mitre_technique"] else ""
        print(f"\n  {color}[{e['severity']:8}]{RESET} {e['description']}{mitre}")
        print(f"  {'':10} Layer: {e['layer']}  |  Line #{e['line_number']}")
        # Trim raw log to 100 chars for readability
        raw_preview = e['raw'][:100] + ("..." if len(e['raw']) > 100 else "")
        print(f"  {'':10} \033[90m{raw_preview}\033[0m")

    print("\n" + "═" * 60 + "\n")


# ── Entry Point ───────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DroidWatch AI — Logcat Analyzer")
    parser.add_argument("--file",  default="logs.txt",    help="Path to logcat file")
    parser.add_argument("--apk",   default="unknown.apk", help="APK name for report")
    parser.add_argument("--json",  action="store_true",   help="Output raw JSON")
    parser.add_argument("--save",  action="store_true",   help="Save JSON report to file")
    parser.add_argument("--post",  action="store_true",   help="POST events to backend API")
    args = parser.parse_args()

    events  = analyze(args.file)
    summary = build_summary(events, args.apk)

    if args.json:
        print(json.dumps({"summary": summary, "events": events}, indent=2))
    else:
        print_report(events, summary)

    if args.save:
        out_path = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out_path, "w") as f:
            json.dump({"summary": summary, "events": events}, f, indent=2)
        print(f"[+] Report saved to {out_path}")

    if args.post:
        import requests
        try:
            r = requests.post(
                "http://localhost:5000/api/events/ingest",
                json={"summary": summary, "events": events},
                timeout=5
            )
            print(f"[+] Posted to backend: {r.status_code}")
        except Exception as e:
            print(f"[!] Could not reach backend: {e}")
