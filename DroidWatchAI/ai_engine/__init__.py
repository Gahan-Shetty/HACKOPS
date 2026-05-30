from .parser import parse_log_line, parse_log_file
from .models import ThreatClassifier, BehaviorClassifier, SeverityPredictor
from .scoring import ThreatScoreCalculator, RiskEngine
from .summarizer import AISummaryGenerator, AttackExplainer, MitigationGenerator

__all__ = [
    "parse_log_line",
    "parse_log_file",
    "ThreatClassifier",
    "BehaviorClassifier",
    "SeverityPredictor",
    "ThreatScoreCalculator",
    "RiskEngine",
    "AISummaryGenerator",
    "AttackExplainer",
    "MitigationGenerator",
    "analyze_events",
    "analyze_log_file"
]

def analyze_events(events: list[dict], asset_criticality: str = "MEDIUM", vulnerability_rating: str = "MEDIUM") -> dict:
    """
    Orchestrates the entire AI Threat Analysis pipeline for a list of structured events.
    
    Args:
        events: list of dict events parsed from system logs
        asset_criticality: str ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        vulnerability_rating: str ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        
    Returns:
        dict: A comprehensive JSON-serializable threat report
    """
    # 1. Instantiate the modules
    threat_clf = ThreatClassifier()
    behavior_clf = BehaviorClassifier()
    severity_pred = SeverityPredictor()
    score_calc = ThreatScoreCalculator()
    risk_eng = RiskEngine()
    summary_gen = AISummaryGenerator()
    explainer = AttackExplainer()
    mitig_gen = MitigationGenerator()

    # 2. Run analysis pipeline
    # 2.1 Behaviors
    behaviors = behavior_clf.predict(events)
    active_behaviors = [name for name, b_info in behaviors.items() if b_info["detected"]]
    
    # 2.2 Threat Classification
    threat_info = threat_clf.predict(events)
    category = threat_info["category"]
    confidence = threat_info["confidence"]
    probabilities = threat_info["probabilities"]
    
    # 2.3 Severity
    severity = severity_pred.predict(category, active_behaviors)
    
    # 2.4 Threat Score
    threat_score_info = score_calc.calculate(category, behaviors, events)
    threat_score = threat_score_info["overall_score"]
    
    # 2.5 Risk Evaluation
    risk_info = risk_eng.evaluate(threat_score, asset_criticality, vulnerability_rating)
    
    # 2.6 Summaries and Explanations
    ai_summary = summary_gen.generate(category, active_behaviors, severity)
    mitre_timeline = explainer.explain(events)
    mitigations = mitig_gen.generate(behaviors, events)

    # 3. Compile report
    return {
        "malware_category": category,
        "malware_confidence": confidence,
        "class_probabilities": probabilities,
        "severity": severity,
        "threat_score": threat_score,
        "layer_scores": {
            "network": threat_score_info["network_score"],
            "filesystem": threat_score_info["filesystem_score"],
            "system": threat_score_info["system_score"]
        },
        "indicators_triggered": threat_score_info["indicators_triggered"],
        "risk_score": risk_info["risk_score"],
        "risk_level": risk_info["risk_level"],
        "context": {
            "asset_criticality": risk_info["asset_criticality"],
            "vulnerability_rating": risk_info["vulnerability_rating"]
        },
        "detected_behaviors": behaviors,
        "ai_summary": ai_summary,
        "mitre_timeline": mitre_timeline,
        "mitigations": mitigations
    }

def analyze_log_file(file_path: str, asset_criticality: str = "MEDIUM", vulnerability_rating: str = "MEDIUM") -> dict:
    """
    Parses a log file and orchestrates the AI Threat Analysis pipeline.
    """
    events = parse_log_file(file_path)
    return analyze_events(events, asset_criticality, vulnerability_rating)
