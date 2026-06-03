import re
import os
from datetime import datetime

# Regular expressions for extraction
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DNS_PATTERN = r'(?:DNS request for|query|resolving)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
FILE_PATH_PATTERN = r'(?:file|directory|path|created|dropped|modified|deleted|quarantined|write)(?:\s+|:\s+|\s*:\s*)([a-zA-Z0-9_\-./\\]*(?:[./\\])[a-zA-Z0-9_\-./\\]*)'
PERMISSION_PATTERN = r'(?:android\.permission\.[A-Z_]+)'

def parse_log_line(line: str) -> dict:
    """
    Parses a single log line into a structured event.
    Returns a dictionary representing the event.
    """
    line_clean = line.strip()
    if not line_clean:
        return {}

    # Initialize event structure
    event = {
        "timestamp": datetime.now().isoformat(),
        "layer": "system",  # default layer
        "level": "INFO",
        "message": line_clean,
        "indicators": {}
    }

    # Extract time metadata if present (e.g., "[2026-05-30 23:05:00]")
    time_match = re.match(r'^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]?', line_clean)
    if time_match:
        try:
            event["timestamp"] = time_match.group(1)
            # Remove timestamp prefix from message
            line_clean = line_clean[time_match.end():].strip().lstrip("-").strip()
            event["message"] = line_clean
        except Exception:
            pass

    line_lower = line_clean.lower()

    # Determine security level
    if "critical" in line_lower or "exploit" in line_lower or "hijack" in line_lower or "abuse" in line_lower:
        event["level"] = "CRITICAL"
    elif "warning" in line_lower or "suspicious" in line_lower or "alert" in line_lower or "threat" in line_lower:
        event["level"] = "WARNING"
    elif "error" in line_lower or "failed" in line_lower:
        event["level"] = "ERROR"

    # Identify layer and extract indicators
    
    # 1. Network Layer indicators
    has_network = False
    if any(k in line_lower for k in ["dns", "http", "socket", "ip", "c2", "port", "traffic", "connect", "beacon"]):
        event["layer"] = "network"
        has_network = True
        
        # IP Extraction
        ips = re.findall(IP_PATTERN, line_clean)
        if ips:
            # Exclude loopback or standard broadcast if possible, but keep for indicators
            event["indicators"]["ips"] = list(set(ips))
        
        # DNS Domain Extraction
        dns_match = re.search(DNS_PATTERN, line_clean, re.IGNORECASE)
        if dns_match:
            event["indicators"]["dns_query"] = dns_match.group(1)
            
        # Port Extraction
        port_match = re.search(r'\bport\s+(\d+)\b', line_clean, re.IGNORECASE)
        if port_match:
            event["indicators"]["port"] = int(port_match.group(1))

    # 2. File System Layer indicators
    has_filesystem = False
    if any(k in line_lower for k in ["file", "dir", "path", "read_external", "write_external", "payload", "quarantine", "persistence", "inject", "drop"]):
        # Network can sometimes overlap, but filesystem is specific to disk activity
        if not has_network or "file" in line_lower or "payload" in line_lower or "quarantine" in line_lower:
            event["layer"] = "filesystem"
            has_filesystem = True
            
            # File Path Extraction
            paths = re.findall(FILE_PATH_PATTERN, line_clean, re.IGNORECASE)
            # Filter out generic words that might be matched
            valid_paths = [p for p in paths if '/' in p or '\\' in p or '.' in p or len(p) > 5]
            if valid_paths:
                event["indicators"]["file_paths"] = valid_paths

    # 3. System Layer indicators (default, but make it explicit if SMS, permission, accessibility, background service)
    if any(k in line_lower for k in ["permission", "sms", "accessibility", "service", "broadcast", "receiver", "process", "kill", "privilege", "root"]):
        if not has_network and not has_filesystem:
            event["layer"] = "system"
        
        # Permission Extraction
        permissions = re.findall(PERMISSION_PATTERN, line_clean)
        if permissions:
            event["indicators"]["permissions"] = list(set(permissions))
            
        # Phone number extraction (common in SMS interception logs)
        phone_match = re.search(r'\b(?:\+\d{1,3}[- ]?)?\d{10}\b', line_clean)
        if phone_match:
            event["indicators"]["phone_number"] = phone_match.group(0)

    return event

def parse_log_file(file_path: str) -> list[dict]:
    """
    Reads a text log file and returns a list of parsed event dictionaries.
    """
    if not os.path.exists(file_path):
        return []
    
    events = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events
