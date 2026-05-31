class AttackExplainer:
    """
    Correlates runtime events to MITRE ATT&CK techniques and explains the attack phases chronologically.
    """
    def __init__(self):
        # Mapping definitions: trigger keyword -> (Mitre ID, Technique Name, Tactical Phase, Explanation Template)
        self.mitre_mappings = [
            ("accessibility", (
                "T1546.015", 
                "Event Triggered Execution: Accessibility Features", 
                "Execution", 
                "Abused Android Accessibility service hooks to monitor user interface actions and intercept user inputs."
            )),
            ("sms", (
                "T1639", 
                "Inbound SMS Redirection / Interception", 
                "Collection", 
                "Monitored and intercepted incoming SMS broadcast events to harvest authentication codes or personal data."
            )),
            ("c2", (
                "T1071.001", 
                "Application Layer Protocol: Web Protocols", 
                "Command and Control", 
                "Initiated callback connections to command-and-control server indicating active beaconing."
            )),
            ("callback", (
                "T1071.001", 
                "Application Layer Protocol: Web Protocols", 
                "Command and Control", 
                "Established command channel communication with remote threat controller."
            )),
            ("dns request for", (
                "T1071.004", 
                "Application Layer Protocol: DNS", 
                "Command and Control", 
                "Abused DNS queries to resolve remote C2 server domains, bypassing standard IP filters."
            )),
            ("boot_completed", (
                "T1547.001", 
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", 
                "Persistence", 
                "Registered broadcast receivers for boot completion to automatically execute malware payload upon device boot."
            )),
            ("autostart", (
                "T1547.001", 
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", 
                "Persistence", 
                "Configured startup services to ensure persistence across device power cycles."
            )),
            ("su", (
                "T1548.002", 
                "Abuse Elevation Control Mechanism: Bypass User Account Control", 
                "Privilege Escalation", 
                "Executed shell commands ('su') to inspect system privileges or gain superuser root permissions."
            )),
            ("root", (
                "T1548.002", 
                "Abuse Elevation Control Mechanism: Bypass User Account Control", 
                "Privilege Escalation", 
                "Attempted root access verification, looking to bypass security settings and gain unrestricted execution privileges."
            )),
            ("payload", (
                "T1105", 
                "Ingress Tool Transfer", 
                "Execution", 
                "Extracted or dropped executable files (.bin, .apk, .so) into secondary directories, indicating multi-stage execution."
            )),
            ("exfiltrat", (
                "T1041", 
                "Exfiltration Over C2 Channel", 
                "Exfiltration", 
                "Attempted exfiltration of local sensitive datasets (contacts, device info) to remote repositories."
            )),
            ("upload", (
                "T1041", 
                "Exfiltration Over C2 Channel", 
                "Exfiltration", 
                "Transferred local datasets to external IP addresses over HTTP/HTTPS."
            )),
            ("read_external", (
                "T1083", 
                "File and Directory Discovery", 
                "Discovery", 
                "Enumerated internal directory listings or read from external storage folders without user authorization."
            ))
        ]

    def explain(self, events: list[dict]) -> list[dict]:
        """
        Reconstructs the attack timeline by mapping events to MITRE ATT&CK techniques.
        Returns:
            list of dicts, each containing:
                "timestamp": str
                "phase": str (Tactical Phase)
                "technique_id": str (MITRE ID)
                "technique_name": str
                "explanation": str
                "log_evidence": str
        """
        timeline = []
        seen_techniques = set()

        for event in events:
            message = event.get("message", "")
            timestamp = event.get("timestamp", "")
            
            # Match against MITRE definitions
            for keyword, (mitre_id, tech_name, phase, explanation_tmpl) in self.mitre_mappings:
                if keyword in message.lower():
                    # Deduplicate repeating techniques on the timeline unless they are different messages
                    tech_key = (mitre_id, message)
                    if tech_key not in seen_techniques:
                        seen_techniques.add(tech_key)
                        
                        timeline.append({
                            "timestamp": timestamp,
                            "phase": phase,
                            "technique_id": mitre_id,
                            "technique_name": tech_name,
                            "explanation": explanation_tmpl,
                            "log_evidence": message
                        })
                        # Stop matching other keywords for this specific event to prevent duplicates
                        break
                        
        # Sort chronologically by timestamp
        try:
            timeline.sort(key=lambda x: x["timestamp"])
        except Exception:
            pass
            
        return timeline
