import re

class BehaviorClassifier:
    """
    Identifies specific malicious behaviors in Android dynamic events.
    """
    def __init__(self):
        # Specific keywords and regex patterns for each behavior type
        self.patterns = {
            "C2_COMMUNICATION": [
                r'\bc2\b', r'callback', r'command\s+and\s+control',
                r'dns\s+request\s+for', r'resolving', r'connected\s+to\s+ip',
                r'beacon', r'reverse\s+shell', r'socket\s+connection'
            ],
            "SMS_INTERCEPTION": [
                r'sms', r'short\s+message', r'intercept', r'read_sms',
                r'receive_sms', r'send_sms', r'incoming\s+message'
            ],
            "ACCESSIBILITY_ABUSE": [
                r'accessibility', r'bind_accessibility_service',
                r'node\s+clicked', r'window\s+state\s+changed', r'overlay'
            ],
            "PERSISTENCE_ESTABLISHED": [
                r'persistence', r'boot_completed', r'autostart', 
                r'init\.d', r'startup', r'run-at-boot', r'scheduled\s+task',
                r'relaunch', r'cron'
            ],
            "PAYLOAD_EXTRACTION": [
                r'payload', r'extract', r'drop', r'dex', r'apk',
                r'\.bin', r'\.so', r'dynamic\s+load', r'quarantine',
                r'decrypted\s+file'
            ],
            "PRIVILEGE_ESCALATION": [
                r'privilege', r'escalat', r'root', r'\bsu\b', 
                r'superuser', r'bypass', r'exploit', r'chmod'
            ],
            "DATA_EXFILTRATION": [
                r'exfiltrat', r'upload', r'send\s+data', r'post\s+request',
                r'leak', r'dump', r'contacts', r'read_external'
            ]
        }

    def predict(self, events: list[dict]) -> dict[str, dict]:
        """
        Analyzes events list and returns behavior detection results.
        Returns:
            dict mapping behavior_name to:
                {
                    "detected": bool,
                    "confidence": float,
                    "evidence": list[str] (matching log messages)
                }
        """
        results = {}

        for behavior_name, patterns in self.patterns.items():
            evidence = []
            confidence_accumulator = 0.0
            
            for event in events:
                message = event.get("message", "")
                indicators = event.get("indicators", {})
                layer = event.get("layer", "")
                level = event.get("level", "")
                
                matched = False
                matched_reason = ""
                
                # Check regex patterns against raw message
                for pattern in patterns:
                    if re.search(pattern, message, re.IGNORECASE):
                        matched = True
                        matched_reason = "pattern_match"
                        break
                
                # Behavioral heuristic checks based on parsed indicators
                if behavior_name == "C2_COMMUNICATION":
                    if layer == "network" and ("ips" in indicators or "dns_query" in indicators):
                        matched = True
                        matched_reason = "network_indicators"
                
                elif behavior_name == "SMS_INTERCEPTION":
                    if "permissions" in indicators and any("SMS" in p for p in indicators["permissions"]):
                        matched = True
                        matched_reason = "sms_permission"
                    if "phone_number" in indicators:
                        matched = True
                        matched_reason = "phone_indicator"
                        
                elif behavior_name == "ACCESSIBILITY_ABUSE":
                    if "permissions" in indicators and any("ACCESSIBILITY" in p for p in indicators["permissions"]):
                        matched = True
                        matched_reason = "accessibility_permission"
                        
                elif behavior_name == "PAYLOAD_EXTRACTION":
                    if layer == "filesystem" and "file_paths" in indicators:
                        # Check if file path ends with suspicious extension
                        for path in indicators["file_paths"]:
                            if any(ext in path.lower() for ext in [".bin", ".apk", ".dex", ".so", ".sh"]):
                                matched = True
                                matched_reason = "payload_file_extension"
                                break

                if matched:
                    evidence.append(message)
                    
                    # Compute confidence contribution
                    increment = 0.25
                    if level == "CRITICAL":
                        increment = 0.50
                    elif level == "WARNING":
                        increment = 0.35
                        
                    if matched_reason in ["sms_permission", "accessibility_permission"]:
                        increment = 0.40
                    elif matched_reason == "network_indicators" and "ips" in indicators:
                        increment = 0.45
                        
                    confidence_accumulator += increment

            # Limit confidence between 0.0 and 1.0
            confidence = min(round(confidence_accumulator, 2), 1.0)
            
            # Ensure a minimal confidence if evidence is found
            if evidence and confidence == 0.0:
                confidence = 0.50
                
            results[behavior_name] = {
                "detected": len(evidence) > 0,
                "confidence": confidence if len(evidence) > 0 else 0.0,
                "evidence": list(set(evidence))  # Unique evidence lines
            }

        return results
