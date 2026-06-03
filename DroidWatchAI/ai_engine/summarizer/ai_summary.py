class AISummaryGenerator:
    """
    Generates a natural language executive summary explaining threat analysis findings.
    """
    def __init__(self):
        # Base templates for malware categories
        self.category_summaries = {
            "Benign": (
                "The application was executed in the dynamic sandbox and showed no signs of "
                "malicious activity. System calls, network connections, and filesystem accesses "
                "remained within normal, benign parameters. No high-risk permissions were abused."
            ),
            "Spyware": (
                "The application exhibits classic Spyware behaviors. During execution, it actively "
                "monitors user communications, grabs sensitive system permissions, and attempts to "
                "intercept incoming SMS messages or abuse accessibility services to record device state "
                "and user inputs, posing a critical threat to user privacy."
            ),
            "Trojan": (
                "Dynamic execution revealed that this application functions as a Trojan. It disguises "
                "itself as a harmless utility while silently setting up persistence mechanisms (e.g., "
                "run-at-boot receivers) and dropping hidden payloads or executable scripts into "
                "system directories to facilitate unauthorized backend access."
            ),
            "Adware": (
                "The application was flagged as Adware due to an excessively high volume of network "
                "requests to advertising networks, background clicks, and the rendering of unseen "
                "overlays. While not destructive, it severely impacts device performance and data usage."
            ),
            "Ransomware": (
                "The application shows dangerous Ransomware patterns. It attempted to scan the external "
                "storage filesystem, access sensitive directories, and execute file locking/encryption "
                "routines. The payload aims to deny access to user files, typically followed by a demand "
                "for ransom."
            ),
            "Worm": (
                "The APK shows propagation behavior typical of a Worm. It attempts to read contacts, "
                "abuse messaging services, and scan nearby network segments (such as Bluetooth and local IPs) "
                "to self-replicate and spread to other connected devices."
            )
        }

    def generate(self, category: str, behaviors: list[str], severity: str) -> str:
        """
        Generates a readable security summary.
        Args:
            category: str (e.g., 'Spyware', 'Benign')
            behaviors: list of active behavior names (e.g., ['C2_COMMUNICATION', 'SMS_INTERCEPTION'])
            severity: str (e.g., 'CRITICAL', 'HIGH')
        """
        base_desc = self.category_summaries.get(category, self.category_summaries["Benign"])
        
        if category == "Benign" and not behaviors:
            return (
                f"🛡️ **System Report: {severity} Risk Detected**\n\n"
                f"{base_desc} The system classifies this APK as safe for general deployment, "
                "as no signature or behavioral anomalies were detected."
            )

        # Build list of readable behaviors
        behavior_labels = [b.replace("_", " ").title() for b in behaviors]
        
        if behavior_labels:
            if len(behavior_labels) == 1:
                behavior_str = f"**{behavior_labels[0]}**"
            elif len(behavior_labels) == 2:
                behavior_str = f"**{behavior_labels[0]}** and **{behavior_labels[1]}**"
            else:
                behavior_str = ", ".join([f"**{b}**" for b in behavior_labels[:-1]]) + f", and **{behavior_labels[-1]}**"
        else:
            behavior_str = "suspicious background executions"

        # Construct explanation based on severity
        severity_explanations = {
            "INFORMATIONAL": "indicating negligible risk which does not require immediate action.",
            "LOW": "representing a minor security anomaly. Monitoring is recommended.",
            "MEDIUM": "representing a moderate security risk. Recommended defensive policies should be evaluated.",
            "HIGH": "indicating a significant threat. Device containment and mitigation should be prioritized immediately.",
            "CRITICAL": "representing an active, highly destructive compromise. Automated isolation and full forensic cleanup are required."
        }
        
        sev_desc = severity_explanations.get(severity, "requiring investigation.")

        summary = (
            f"🤖 **AI Analysis Summary: {severity} Severity Threat Detected**\n\n"
            f"{base_desc}\n\n"
            f"The application's runtime profile triggers a **{severity}** risk rating, {sev_desc} "
            f"The core indicators identified during monitoring include: {behavior_str}. "
            f"These actions confirm active compromise attempts across system layers. "
            f"It is strongly advised to deploy simulated defense mitigations to secure the environment."
        )

        return summary
