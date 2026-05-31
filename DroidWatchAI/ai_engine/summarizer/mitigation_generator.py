class MitigationGenerator:
    """
    Generates tailored, layer-specific active mitigations based on detected malware behaviors and events.
    """
    def __init__(self):
        pass

    def generate(self, behaviors: dict, events: list[dict]) -> dict:
        """
        Generates actionable defense mitigations.
        Returns:
            dict containing lists of recommendations:
                "network": list[str]
                "filesystem": list[str]
                "system": list[str]
        """
        network_mitigations = []
        filesystem_mitigations = []
        system_mitigations = []

        # Extract indicators to personalize mitigations
        ips_to_block = set()
        domains_to_sinkhole = set()
        files_to_quarantine = set()
        permissions_to_revoke = set()

        for event in events:
            inds = event.get("indicators", {})
            if "ips" in inds:
                ips_to_block.update(inds["ips"])
            if "dns_query" in inds:
                domains_to_sinkhole.add(inds["dns_query"])
            if "file_paths" in inds:
                files_to_quarantine.update(inds["file_paths"])
            if "permissions" in inds:
                permissions_to_revoke.update(inds["permissions"])

        # 1. Network Layer Mitigations
        if behaviors.get("C2_COMMUNICATION", {}).get("detected", False) or ips_to_block or domains_to_sinkhole:
            network_mitigations.append("🔒 Enable firewall isolation rules to restrict outward device communications.")
            
            for ip in sorted(list(ips_to_block))[:3]:
                network_mitigations.append(f"🚫 Blacklist malicious Command & Control IP: {ip}")
                
            for domain in sorted(list(domains_to_sinkhole))[:3]:
                network_mitigations.append(f"🌐 Sinkhole DNS domain lookup for: {domain}")
                
            if not ips_to_block:
                network_mitigations.append("🚫 Restrict network sockets bound to unauthorized foreign destinations.")
        else:
            network_mitigations.append("✅ Monitor outgoing connection attempts for unusual UDP/TCP port binds.")

        # 2. Filesystem / Storage Layer Mitigations
        if behaviors.get("PAYLOAD_EXTRACTION", {}).get("detected", False) or files_to_quarantine:
            for filepath in sorted(list(files_to_quarantine))[:3]:
                filename = filepath.split('/')[-1].split('\\')[-1]
                network_mitigations.append(f"🛡️ Quarantine dropped binary payload: {filename} at {filepath}")
                filesystem_mitigations.append(f"📁 Move {filename} to sandbox secure quarantine zone and block execution.")
                
            filesystem_mitigations.append("🔍 Perform file integrity hash checks (SHA-256) on modified storage directories.")
        
        if behaviors.get("PERSISTENCE_ESTABLISHED", {}).get("detected", False):
            filesystem_mitigations.append("⚙️ Remove unauthorized launch agents, autostart scripts, or cron entries.")
            filesystem_mitigations.append("🗄️ Revert modifications to boot-receiver configuration files.")
            
        if not filesystem_mitigations:
            filesystem_mitigations.append("✅ Standard storage sandbox isolation is active. No modifications detected.")

        # 3. System Layer Mitigations
        if behaviors.get("SMS_INTERCEPTION", {}).get("detected", False) or any("SMS" in p for p in permissions_to_revoke):
            system_mitigations.append("📱 Revoke SMS intercept permissions: android.permission.RECEIVE_SMS and android.permission.READ_SMS.")
            system_mitigations.append("💬 Audit runtime SMS broadcast receivers and restrict application notification monitoring.")
            
        if behaviors.get("ACCESSIBILITY_ABUSE", {}).get("detected", False) or any("ACCESSIBILITY" in p for p in permissions_to_revoke):
            system_mitigations.append("♿ Disable Accessibility Service privileges in Android System settings.")
            system_mitigations.append("🚫 Block overlay permissions to prevent UI redressing / clickjacking attacks.")
            
        if behaviors.get("PRIVILEGE_ESCALATION", {}).get("detected", False):
            system_mitigations.append("🔑 Revoke root superuser ('su') privileges from the application runtime.")
            system_mitigations.append("🔄 Perform full device integrity verification to check for unlocked bootloader states.")

        if behaviors.get("DATA_EXFILTRATION", {}).get("detected", False):
            system_mitigations.append("🔏 Terminate background services to stop active reading of contacts and system logs.")
            system_mitigations.append("🛑 Revoke storage permissions to restrict access to local device folders.")

        # Default system mitigations if empty
        if not system_mitigations:
            system_mitigations.append("✅ Keep system APIs restricted. Force dynamic runtime user prompts for critical operations.")

        return {
            "network": network_mitigations,
            "filesystem": filesystem_mitigations,
            "system": system_mitigations
        }
