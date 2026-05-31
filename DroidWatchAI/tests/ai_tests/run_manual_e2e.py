import os
import sys
import json
import io

# Set terminal encoding to UTF-8 for windows emoji support
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Adjust sys.path to find DroidWatchAI components relatively
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# Handle direct import inside DroidWatchAI
dw_root = os.path.join(project_root, "DroidWatchAI")
if os.path.exists(dw_root) and dw_root not in sys.path:
    sys.path.insert(0, dw_root)

# Resolve package folder relatively
try:
    from ai_engine import analyze_log_file
except ImportError:
    # If executing from outside, try adding grandparent
    sys.path.insert(0, os.path.abspath(os.path.join(current_dir, "..")))
    from ai_engine import analyze_log_file

# Define simulated log file contents
SIMULATED_LOGS = """
[2026-05-30T23:05:00] INFO: Device boot completed. System services initialized.
[2026-05-30T23:05:05] WARNING: Application requested sensitive permissions: android.permission.RECEIVE_SMS, android.permission.READ_SMS.
[2026-05-30T23:05:10] CRITICAL: Accessibility service registered: com.security.service.AccessibilityTracker.
[2026-05-30T23:05:15] WARNING: File created: /data/user/0/com.security.service/files/payload.bin
[2026-05-30T23:05:20] WARNING: DNS request for malware-c2-channel.com
[2026-05-30T23:05:25] WARNING: TCP connection established to C2 IP 185.220.101.5 on port 8080.
[2026-05-30T23:05:30] CRITICAL: Incoming SMS intercepted from +15550199 - 'Your login authentication OTP is 482109'
[2026-05-30T23:05:35] CRITICAL: Exfiltrated SMS payload logs to remote C2 IP 185.220.101.5.
"""

def main():
    # 1. Write simulated logs to file
    log_file_path = os.path.join(current_dir, "simulated_spyware_logs.txt")
    with open(log_file_path, "w", encoding="utf-8") as f:
        f.write(SIMULATED_LOGS.strip())
    print(f"[*] Wrote simulated logs to: {log_file_path}")

    # 2. Run analysis
    print("[*] Running AI Threat Intelligence Engine...")
    report = analyze_log_file(log_file_path, asset_criticality="HIGH", vulnerability_rating="CRITICAL")

    # 3. Print report beautifully
    print("\n" + "="*60)
    print("                 DROIDWATCH AI REPORT SUMMARY")
    print("="*60)
    print(f"MALWARE CATEGORY : {report['malware_category']} (Confidence: {report['malware_confidence']:.2f})")
    print(f"THREAT SCORE     : {report['threat_score']}/100.0")
    print(f"SEVERITY LEVEL   : {report['severity']}")
    print(f"RISK RATING      : {report['risk_level']} (Score: {report['risk_score']}/100.0)")
    print(f"CONTEXT          : Criticality={report['context']['asset_criticality']}, Vulnerability={report['context']['vulnerability_rating']}")
    print("-"*60)
    print("LAYER THREAT SCORES:")
    print(f"  Network Layer      : {report['layer_scores']['network']}/100")
    print(f"  File System Layer  : {report['layer_scores']['filesystem']}/100")
    print(f"  System Layer       : {report['layer_scores']['system']}/100")
    print("-"*60)
    print("DETECTED MALWARE BEHAVIORS:")
    for behavior, details in report["detected_behaviors"].items():
        if details["detected"]:
            print(f"  [!] {behavior:<25} (Confidence: {details['confidence']:.2f})")
            for proof in details["evidence"][:2]:
                print(f"      - Evidence: {proof}")
    print("-"*60)
    print("MITRE ATT&CK TIMELINE:")
    for step in report["mitre_timeline"]:
        print(f"  [{step['timestamp']}] {step['phase']}: {step['technique_name']} ({step['technique_id']})")
        print(f"      Description: {step['explanation']}")
        print(f"      Log Line: '{step['log_evidence']}'")
    print("-"*60)
    print("RECOMMENDED DEFENSIVE MITIGATIONS:")
    print("  Network Mitigations:")
    for mit in report["mitigations"]["network"]:
        print(f"    {mit}")
    print("  Filesystem Mitigations:")
    for mit in report["mitigations"]["filesystem"]:
        print(f"    {mit}")
    print("  System Mitigations:")
    for mit in report["mitigations"]["system"]:
        print(f"    {mit}")
    print("="*60)

    # Clean up
    if os.path.exists(log_file_path):
        os.remove(log_file_path)

if __name__ == "__main__":
    main()
