import re
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Standard categories
CATEGORIES = ["Benign", "Spyware", "Trojan", "Adware", "Ransomware", "Worm"]

# Predefined profiles for synthetic training: [num_total, num_net, num_fs, num_sys, num_crit, num_warn, has_sms, has_acc, has_c2, has_persist, has_quar, has_ad, has_ransom, has_worm]
SYNTHETIC_DATA = [
    # Benign
    ([2, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Benign"),
    ([5, 1, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Benign"),
    ([10, 2, 4, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], "Benign"),
    ([8, 1, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Benign"),
    ([3, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Benign"),
    
    # Spyware
    ([25, 12, 3, 10, 4, 8, 1, 1, 1, 0, 0, 0, 0, 0], "Spyware"),
    ([20, 10, 2, 8, 3, 6, 1, 0, 1, 0, 0, 0, 0, 0], "Spyware"),
    ([30, 15, 5, 10, 5, 10, 1, 1, 1, 1, 0, 0, 0, 0], "Spyware"),
    ([18, 8, 2, 8, 2, 5, 0, 1, 1, 0, 0, 0, 0, 0], "Spyware"),
    ([22, 11, 4, 7, 3, 7, 1, 1, 0, 0, 0, 0, 0, 0], "Spyware"),
    
    # Trojan
    ([15, 3, 6, 6, 2, 4, 0, 0, 0, 1, 1, 0, 0, 0], "Trojan"),
    ([20, 5, 8, 7, 3, 5, 0, 1, 1, 1, 1, 0, 0, 0], "Trojan"),
    ([12, 2, 5, 5, 2, 3, 0, 0, 0, 1, 0, 0, 0, 0], "Trojan"),
    ([25, 7, 10, 8, 4, 6, 0, 1, 0, 1, 1, 0, 0, 0], "Trojan"),
    ([14, 4, 5, 5, 1, 3, 0, 0, 0, 1, 1, 0, 0, 0], "Trojan"),
    
    # Adware
    ([40, 30, 2, 8, 0, 3, 0, 0, 0, 0, 0, 1, 0, 0], "Adware"),
    ([35, 25, 3, 7, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0], "Adware"),
    ([50, 40, 2, 8, 1, 4, 0, 0, 0, 1, 0, 1, 0, 0], "Adware"),
    ([25, 18, 1, 6, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0], "Adware"),
    ([45, 32, 4, 9, 0, 3, 0, 0, 0, 0, 0, 1, 0, 0], "Adware"),
    
    # Ransomware
    ([30, 2, 20, 8, 6, 8, 0, 0, 0, 1, 1, 0, 1, 0], "Ransomware"),
    ([25, 1, 18, 6, 5, 7, 0, 0, 0, 0, 1, 0, 1, 0], "Ransomware"),
    ([40, 3, 28, 9, 7, 10, 0, 1, 0, 1, 1, 0, 1, 0], "Ransomware"),
    ([35, 2, 24, 9, 6, 9, 0, 0, 0, 1, 1, 0, 1, 0], "Ransomware"),
    ([22, 1, 15, 6, 4, 6, 0, 0, 0, 0, 0, 0, 1, 0], "Ransomware"),
    
    # Worm
    ([28, 18, 2, 8, 3, 6, 0, 0, 1, 0, 0, 0, 0, 1], "Worm"),
    ([32, 22, 3, 7, 4, 7, 0, 0, 0, 0, 0, 0, 0, 1], "Worm"),
    ([26, 16, 2, 8, 2, 5, 0, 0, 1, 1, 0, 0, 0, 1], "Worm"),
    ([38, 26, 4, 8, 4, 8, 0, 0, 1, 0, 0, 0, 0, 1], "Worm"),
    ([20, 12, 1, 7, 2, 4, 0, 0, 0, 0, 0, 0, 0, 1], "Worm"),
    
    # Low-event malicious profiles
    ([4, 1, 0, 3, 2, 2, 1, 1, 1, 0, 0, 0, 0, 0], "Spyware"),
    ([4, 2, 0, 2, 1, 2, 1, 0, 1, 0, 0, 0, 0, 0], "Spyware"),
    ([3, 0, 2, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0], "Trojan"),
    ([5, 1, 2, 2, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0], "Trojan"),
    ([4, 0, 3, 1, 2, 2, 0, 0, 0, 0, 1, 0, 1, 0], "Ransomware"),
    ([3, 2, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1], "Worm")
]

class ThreatClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
        self.train()

    def _extract_features(self, events: list[dict]) -> list:
        """
        Extracts the 14-dimensional feature vector from a list of events.
        """
        num_total = len(events)
        if num_total == 0:
            return [0] * 14
            
        num_net = sum(1 for e in events if e.get("layer") == "network")
        num_fs = sum(1 for e in events if e.get("layer") == "filesystem")
        num_sys = sum(1 for e in events if e.get("layer") == "system")
        
        num_crit = sum(1 for e in events if e.get("level") == "CRITICAL")
        num_warn = sum(1 for e in events if e.get("level") == "WARNING")
        
        has_sms = 0
        has_acc = 0
        has_c2 = 0
        has_persist = 0
        has_quar = 0
        has_ad = 0
        has_ransom = 0
        has_worm = 0
        
        for e in events:
            msg = e.get("message", "").lower()
            inds = e.get("indicators", {})
            
            # SMS Indicators
            if "sms" in msg or "permissions" in inds and any("SMS" in p for p in inds.get("permissions", [])):
                has_sms = 1
                
            # Accessibility Indicators
            if "accessibility" in msg or "permissions" in inds and any("ACCESSIBILITY" in p for p in inds.get("permissions", [])):
                has_acc = 1
                
            # C2 Indicators
            if "c2" in msg or "callback" in msg or "dns_query" in inds or "ips" in inds:
                has_c2 = 1
                
            # Persistence Indicators
            if any(k in msg for k in ["persistence", "init.d", "autostart", "boot_completed", "startup", "payload"]):
                has_persist = 1
                
            # Quarantine Indicators
            if "quarantine" in msg or "payload" in msg:
                has_quar = 1
                
            # Ad Indicators
            if any(k in msg for k in ["admob", "ads", "advertisement", "clicker", "banner"]):
                has_ad = 1
                
            # Ransom Indicators
            if any(k in msg for k in ["encrypt", "decrypt", "ransom", "bitcoin", "lock", "wallet"]):
                has_ransom = 1
                
            # Worm Indicators
            if any(k in msg for k in ["propagate", "spread", "mail", "contact", "bluetooth"]):
                has_worm = 1
                
        return [
            num_total, num_net, num_fs, num_sys, num_crit, num_warn,
            has_sms, has_acc, has_c2, has_persist, has_quar, has_ad, has_ransom, has_worm
        ]

    def train(self) -> None:
        """
        Trains the RandomForest model on synthetic profile data.
        """
        X = []
        y = []
        for features, label in SYNTHETIC_DATA:
            X.append(features)
            y.append(label)
            
        try:
            self.model.fit(X, y)
            self.is_trained = True
        except Exception:
            self.is_trained = False

    def predict(self, events: list[dict]) -> dict:
        """
        Predicts the threat category, along with the confidence and breakdown of probabilities.
        """
        if not events:
            return {
                "category": "Benign",
                "confidence": 1.0,
                "probabilities": {c: 1.0 if c == "Benign" else 0.0 for c in CATEGORIES}
            }
            
        features = self._extract_features(events)
        
        # Rule-based fallback or heuristic validator
        heuristic_prediction = self._fallback_rule_based(features)
        
        if not self.is_trained:
            return {
                "category": heuristic_prediction,
                "confidence": 0.80,
                "probabilities": {c: 0.80 if c == heuristic_prediction else 0.04 for c in CATEGORIES}
            }
            
        try:
            features_arr = np.array([features])
            pred_class = self.model.predict(features_arr)[0]
            probs = self.model.predict_proba(features_arr)[0]
            
            # Map classes to their probabilities
            class_probs = {}
            for cls, prob in zip(self.model.classes_, probs):
                class_probs[cls] = float(prob)
                
            # Ensure all categories exist in output
            for cat in CATEGORIES:
                if cat not in class_probs:
                    class_probs[cat] = 0.0
                    
            confidence = class_probs.get(pred_class, 0.0)
            
            # Override if ML predicts Benign but critical malicious indicators are active
            has_malicious_indicators = any([has_sms, has_acc, has_c2, has_persist, has_quar, has_ad, has_ransom, has_worm])
            if pred_class == "Benign" and has_malicious_indicators:
                pred_class = heuristic_prediction
                confidence = max(class_probs.get(pred_class, 0.0), 0.70)
                class_probs[pred_class] = confidence
                
            # Heuristic override if machine learning confidence is low but rule-based is very strong
            elif confidence < 0.50 and heuristic_prediction != pred_class:
                pred_class = heuristic_prediction
                confidence = max(confidence, 0.60)
                class_probs[pred_class] = confidence
                
            return {
                "category": pred_class,
                "confidence": round(confidence, 2),
                "probabilities": {k: round(v, 2) for k, v in class_probs.items()}
            }
        except Exception:
            return {
                "category": heuristic_prediction,
                "confidence": 0.75,
                "probabilities": {c: 0.75 if c == heuristic_prediction else 0.05 for c in CATEGORIES}
            }

    def _fallback_rule_based(self, features: list) -> str:
        """
        Simple rule-based classifier acting as fallback and reinforcement.
        """
        (
            num_total, num_net, num_fs, num_sys, num_crit, num_warn,
            has_sms, has_acc, has_c2, has_persist, has_quar, has_ad, has_ransom, has_worm
        ) = features
        
        if num_total == 0:
            return "Benign"
            
        if has_ransom:
            return "Ransomware"
        if has_worm:
            return "Worm"
        if has_ad:
            return "Adware"
        if has_sms or (has_acc and has_c2):
            return "Spyware"
        if has_persist or has_quar:
            return "Trojan"
            
        if num_crit > 2 or (num_net > 5 and has_c2):
            return "Spyware"
            
        if num_warn > 3 or has_c2 or has_persist:
            return "Trojan"
            
        return "Benign"
