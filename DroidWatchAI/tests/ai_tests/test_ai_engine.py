import os
import sys
import unittest
from datetime import datetime

# Adjust sys.path to find DroidWatchAI components
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# Also insert DroidWatchAI root to handle relative imports from inside it
dw_root = os.path.join(project_root, "DroidWatchAI")
if dw_root not in sys.path:
    sys.path.insert(0, dw_root)

from ai_engine.parser import parse_log_line, parse_log_file
from ai_engine.models.threat_classifier import ThreatClassifier
from ai_engine.models.behavior_classifier import BehaviorClassifier
from ai_engine.models.severity_predictor import SeverityPredictor
from ai_engine.scoring.threat_score import ThreatScoreCalculator
from ai_engine.scoring.risk_engine import RiskEngine
from ai_engine.summarizer.ai_summary import AISummaryGenerator
from ai_engine.summarizer.attack_explainer import AttackExplainer
from ai_engine.summarizer.mitigation_generator import MitigationGenerator
from ai_engine import analyze_events, analyze_log_file

class TestParser(unittest.TestCase):
    def test_parse_network_line(self):
        line = "TCP connection to 185.220.101.5 on port 8080"
        event = parse_log_line(line)
        self.assertEqual(event["layer"], "network")
        self.assertIn("185.220.101.5", event["indicators"]["ips"])
        self.assertEqual(event["indicators"]["port"], 8080)
        
    def test_parse_dns_line(self):
        line = "DNS request for suspect-domain.com"
        event = parse_log_line(line)
        self.assertEqual(event["layer"], "network")
        self.assertEqual(event["indicators"]["dns_query"], "suspect-domain.com")
        
    def test_parse_filesystem_line(self):
        line = "File created: /sdcard/Download/payload.bin"
        event = parse_log_line(line)
        self.assertEqual(event["layer"], "filesystem")
        self.assertIn("/sdcard/Download/payload.bin", event["indicators"]["file_paths"])

    def test_parse_system_permission(self):
        line = "Permission granted: android.permission.RECEIVE_SMS"
        event = parse_log_line(line)
        self.assertEqual(event["layer"], "system")
        self.assertIn("android.permission.RECEIVE_SMS", event["indicators"]["permissions"])

class TestModels(unittest.TestCase):
    def test_behavior_classifier(self):
        events = [
            {"message": "DNS request for suspect-domain.com", "layer": "network", "indicators": {"dns_query": "suspect-domain.com"}, "level": "WARNING"},
            {"message": "Permission granted: android.permission.RECEIVE_SMS", "layer": "system", "indicators": {"permissions": ["android.permission.RECEIVE_SMS"]}, "level": "INFO"},
            {"message": "SMS intercepted from +1234567890", "layer": "system", "indicators": {"phone_number": "+1234567890"}, "level": "CRITICAL"}
        ]
        clf = BehaviorClassifier()
        results = clf.predict(events)
        self.assertTrue(results["C2_COMMUNICATION"]["detected"])
        self.assertTrue(results["SMS_INTERCEPTION"]["detected"])
        self.assertFalse(results["PAYLOAD_EXTRACTION"]["detected"])
        self.assertGreater(results["SMS_INTERCEPTION"]["confidence"], 0.5)

    def test_threat_classifier(self):
        # Build features representing Spyware profile
        events = [
            {"message": "DNS request for suspect-domain.com", "layer": "network", "indicators": {"dns_query": "suspect-domain.com"}, "level": "WARNING"},
            {"message": "Permission granted: android.permission.RECEIVE_SMS", "layer": "system", "indicators": {"permissions": ["android.permission.RECEIVE_SMS"]}, "level": "INFO"},
            {"message": "SMS intercepted from +1234567890", "layer": "system", "indicators": {"phone_number": "+1234567890"}, "level": "CRITICAL"},
            {"message": "Accessibility service registered: my.malicious.service", "layer": "system", "indicators": {"permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"]}, "level": "CRITICAL"}
        ]
        clf = ThreatClassifier()
        res = clf.predict(events)
        self.assertEqual(res["category"], "Spyware")
        self.assertGreaterEqual(res["confidence"], 0.5)

    def test_severity_predictor(self):
        pred = SeverityPredictor()
        # Spyware with multiple behaviors -> CRITICAL
        sev = pred.predict("Spyware", ["C2_COMMUNICATION", "SMS_INTERCEPTION", "ACCESSIBILITY_ABUSE"])
        self.assertEqual(sev, "CRITICAL")
        
        # Benign with 0 behaviors -> INFORMATIONAL
        sev_benign = pred.predict("Benign", [])
        self.assertEqual(sev_benign, "INFORMATIONAL")

class TestScoring(unittest.TestCase):
    def test_threat_score_calculation(self):
        calc = ThreatScoreCalculator()
        behaviors = {
            "C2_COMMUNICATION": {"detected": True},
            "SMS_INTERCEPTION": {"detected": True},
            "PAYLOAD_EXTRACTION": {"detected": False}
        }
        events = [
            {"message": "c2 callback attempt", "layer": "network"},
            {"message": "SMS intercepted", "layer": "system"}
        ]
        scores = calc.calculate("Spyware", behaviors, events)
        self.assertGreater(scores["overall_score"], 40.0)
        self.assertGreater(scores["network_score"], 50.0)
        self.assertGreater(scores["system_score"], 40.0)
        self.assertEqual(scores["filesystem_score"], 0.0)

    def test_risk_engine(self):
        engine = RiskEngine()
        # High threat + high assets -> CRITICAL risk
        res = engine.evaluate(threat_score=80.0, asset_criticality="HIGH", vulnerability_rating="HIGH")
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertGreater(res["risk_score"], 80.0)
        
        # Low threat -> LOW risk
        res_low = engine.evaluate(threat_score=10.0, asset_criticality="LOW", vulnerability_rating="LOW")
        self.assertEqual(res_low["risk_level"], "LOW")

class TestE2EPipeline(unittest.TestCase):
    def test_pipeline_orchestration(self):
        events = [
            {"message": "System booted", "layer": "system", "level": "INFO"},
            {"message": "Permission granted: android.permission.RECEIVE_SMS", "layer": "system", "indicators": {"permissions": ["android.permission.RECEIVE_SMS"]}, "level": "INFO"},
            {"message": "SMS intercepted from +19876543210", "layer": "system", "indicators": {"phone_number": "+19876543210"}, "level": "CRITICAL"},
            {"message": "DNS request for botnet-c2-cnc.net", "layer": "network", "indicators": {"dns_query": "botnet-c2-cnc.net"}, "level": "WARNING"},
            {"message": "Connected to C2 IP 192.168.1.100", "layer": "network", "indicators": {"ips": ["192.168.1.100"]}, "level": "WARNING"}
        ]
        
        report = analyze_events(events, asset_criticality="HIGH", vulnerability_rating="MEDIUM")
        
        # Validate output dictionary structure
        self.assertEqual(report["malware_category"], "Spyware")
        self.assertIn("severity", report)
        self.assertIn("threat_score", report)
        self.assertIn("risk_score", report)
        self.assertIn("risk_level", report)
        self.assertTrue(report["detected_behaviors"]["SMS_INTERCEPTION"]["detected"])
        self.assertTrue(report["detected_behaviors"]["C2_COMMUNICATION"]["detected"])
        self.assertIn("ai_summary", report)
        self.assertGreater(len(report["mitre_timeline"]), 0)
        self.assertIn("mitigations", report)

if __name__ == "__main__":
    unittest.main()
