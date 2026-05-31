class ThreatScoreCalculator:
    """
    Computes numerical threat scores based on behaviors, layer events, and severity indicators.
    """
    def __init__(self):
        pass

    def calculate(self, category: str, behaviors: dict, events: list[dict]) -> dict:
        """
        Calculates granular threat scores (overall and layer-specific sub-scores).
        Returns:
            dict containing:
                "overall_score": float (0.0 to 100.0)
                "network_score": float (0.0 to 100.0)
                "filesystem_score": float (0.0 to 100.0)
                "system_score": float (0.0 to 100.0)
                "indicators_triggered": int
        """
        if not events:
            return {
                "overall_score": 0.0,
                "network_score": 0.0,
                "filesystem_score": 0.0,
                "system_score": 0.0,
                "indicators_triggered": 0
            }

        # Initialize raw scores for each layer
        net_raw = 0.0
        fs_raw = 0.0
        sys_raw = 0.0
        indicators_triggered = 0

        # Network layer analysis
        unique_ips = set()
        has_dns_abuse = False
        has_c2 = False
        
        # File system layer analysis
        has_hidden_file = False
        has_payload_drop = False
        has_persistence_file = False
        
        # System layer analysis
        has_sms_intercept = False
        has_sms_permission = False
        has_accessibility_abuse = False
        has_root_check = False

        # Scan events for scoring indicators
        for e in events:
            msg = e.get("message", "").lower()
            inds = e.get("indicators", {})
            layer = e.get("layer", "")
            
            if layer == "network":
                if "ips" in inds:
                    unique_ips.update(inds["ips"])
                if "dns_query" in inds or "dns" in msg:
                    has_dns_abuse = True
                if "c2" in msg or "callback" in msg:
                    has_c2 = True
                    
            elif layer == "filesystem":
                if "file_paths" in inds:
                    for path in inds["file_paths"]:
                        if "/." in path or "\\." in path or "hidden" in msg:
                            has_hidden_file = True
                        if any(ext in path.lower() for ext in [".bin", ".apk", ".dex", ".so", ".sh"]):
                            has_payload_drop = True
                        if "persistence" in msg or any(k in path.lower() for k in ["init.d", "autostart", "startup"]):
                            has_persistence_file = True
                            
            elif layer == "system":
                if "permissions" in inds:
                    perms = inds["permissions"]
                    if any("SMS" in p for p in perms):
                        has_sms_permission = True
                    if any("ACCESSIBILITY" in p for p in perms):
                        has_accessibility_abuse = True
                if "sms" in msg and "intercept" in msg:
                    has_sms_intercept = True
                if any(k in msg for k in ["accessibility", "bind_accessibility_service"]):
                    has_accessibility_abuse = True
                if any(k in msg for k in ["su", "root", "superuser"]):
                    has_root_check = True

        # Calculate Network Score
        if has_c2 or behaviors.get("C2_COMMUNICATION", {}).get("detected", False):
            net_raw += 55.0
            indicators_triggered += 1
        if has_dns_abuse:
            net_raw += 25.0
            indicators_triggered += 1
        if unique_ips:
            net_raw += min(len(unique_ips) * 10.0, 30.0)
            indicators_triggered += len(unique_ips)
            
        net_score = min(net_raw, 100.0)

        # Calculate Filesystem Score
        if has_persistence_file or behaviors.get("PERSISTENCE_ESTABLISHED", {}).get("detected", False):
            fs_raw += 45.0
            indicators_triggered += 1
        if has_payload_drop or behaviors.get("PAYLOAD_EXTRACTION", {}).get("detected", False):
            fs_raw += 35.0
            indicators_triggered += 1
        if has_hidden_file:
            fs_raw += 20.0
            indicators_triggered += 1
            
        fs_score = min(fs_raw, 100.0)

        # Calculate System Score
        if has_sms_intercept or behaviors.get("SMS_INTERCEPTION", {}).get("detected", False):
            sys_raw += 50.0
            indicators_triggered += 1
        if has_sms_permission:
            sys_raw += 20.0
            indicators_triggered += 1
        if has_accessibility_abuse or behaviors.get("ACCESSIBILITY_ABUSE", {}).get("detected", False):
            sys_raw += 45.0
            indicators_triggered += 1
        if has_root_check or behaviors.get("PRIVILEGE_ESCALATION", {}).get("detected", False):
            sys_raw += 35.0
            indicators_triggered += 1
            
        sys_score = min(sys_raw, 100.0)

        # Dynamic layer weighting based on malware category
        # Default weights: Network 35%, Filesystem 30%, System 35%
        weights = {"network": 0.35, "filesystem": 0.30, "system": 0.35}

        if category == "Ransomware":
            weights = {"network": 0.20, "filesystem": 0.60, "system": 0.20}
        elif category == "Adware":
            weights = {"network": 0.60, "filesystem": 0.20, "system": 0.20}
        elif category == "Spyware":
            weights = {"network": 0.35, "filesystem": 0.15, "system": 0.50}
        elif category == "Worm":
            weights = {"network": 0.50, "filesystem": 0.20, "system": 0.30}
        elif category == "Trojan":
            weights = {"network": 0.30, "filesystem": 0.40, "system": 0.30}

        overall_score = (
            (net_score * weights["network"]) +
            (fs_score * weights["filesystem"]) +
            (sys_score * weights["system"])
        )

        # Apply a base score floor for known malicious categories if any malicious behavior was detected
        has_detected_behaviors = any(b.get("detected", False) for b in behaviors.values())
        if category != "Benign" and has_detected_behaviors:
            overall_score = max(overall_score, 45.0)

        return {
            "overall_score": round(overall_score, 2),
            "network_score": round(net_score, 2),
            "filesystem_score": round(fs_score, 2),
            "system_score": round(sys_score, 2),
            "indicators_triggered": indicators_triggered
        }
