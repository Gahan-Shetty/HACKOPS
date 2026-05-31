import numpy as np
from sklearn.tree import DecisionTreeClassifier

# Severity levels mapping
SEVERITY_LEVELS = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CATEGORIES_MAP = {"Benign": 0, "Adware": 1, "Trojan": 2, "Spyware": 3, "Ransomware": 4, "Worm": 5}

# Training set: [category_index, num_behaviors, has_critical_behavior] -> severity_level
TRAINING_DATA = [
    # Benign
    ([0, 0, 0], "INFORMATIONAL"),
    ([0, 1, 0], "LOW"),
    ([0, 2, 0], "MEDIUM"),
    # Adware
    ([1, 1, 0], "LOW"),
    ([1, 2, 0], "MEDIUM"),
    ([1, 3, 0], "MEDIUM"),
    ([1, 4, 1], "HIGH"),
    # Trojan
    ([2, 1, 0], "MEDIUM"),
    ([2, 2, 0], "HIGH"),
    ([2, 3, 0], "HIGH"),
    ([2, 4, 1], "CRITICAL"),
    # Spyware
    ([3, 1, 0], "HIGH"),
    ([3, 2, 0], "HIGH"),
    ([3, 3, 1], "CRITICAL"),
    ([3, 4, 1], "CRITICAL"),
    # Ransomware
    ([4, 1, 0], "HIGH"),
    ([4, 2, 1], "CRITICAL"),
    ([4, 3, 1], "CRITICAL"),
    # Worm
    ([5, 1, 0], "HIGH"),
    ([5, 2, 0], "CRITICAL"),
    ([5, 3, 1], "CRITICAL"),
    # Critical flags overriding categories
    ([0, 1, 1], "HIGH"),
    ([1, 2, 1], "HIGH"),
    ([2, 1, 1], "CRITICAL"),
    ([3, 1, 1], "CRITICAL")
]

class SeverityPredictor:
    def __init__(self):
        self.model = DecisionTreeClassifier(max_depth=4, random_state=42)
        self.is_trained = False
        self.train()

    def train(self) -> None:
        """
        Trains the DecisionTree model on severity rules.
        """
        X = []
        y = []
        for features, label in TRAINING_DATA:
            X.append(features)
            y.append(label)
            
        try:
            self.model.fit(X, y)
            self.is_trained = True
        except Exception:
            self.is_trained = False

    def predict(self, category: str, detected_behaviors: list[str], critical_behaviors: list[str] = None) -> str:
        """
        Predicts the severity level (INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL).
        """
        # Feature 1: Category encoding
        cat_encoded = CATEGORIES_MAP.get(category, 0)
        
        # Feature 2: Behavior Count
        num_behaviors = len(detected_behaviors)
        
        # Feature 3: Critical behavior presence
        if critical_behaviors is None:
            critical_behaviors = ["PRIVILEGE_ESCALATION", "ACCESSIBILITY_ABUSE", "SMS_INTERCEPTION"]
            
        has_critical = 0
        for b in detected_behaviors:
            if b in critical_behaviors:
                has_critical = 1
                break
                
        features = [cat_encoded, num_behaviors, has_critical]
        
        # Fallback heuristic
        heuristic_val = self._fallback_rule_based(features)
        
        if not self.is_trained:
            return heuristic_val
            
        try:
            features_arr = np.array([features])
            prediction = self.model.predict(features_arr)[0]
            
            # Ensure prediction is a valid severity level
            if prediction in SEVERITY_LEVELS:
                return prediction
            return heuristic_val
        except Exception:
            return heuristic_val

    def _fallback_rule_based(self, features: list) -> str:
        """
        Standard rule-based severity calculator for validation and fallback.
        """
        cat_encoded, num_behaviors, has_critical = features
        
        if has_critical:
            if cat_encoded >= 2:  # Trojan, Spyware, Ransomware, Worm
                return "CRITICAL"
            return "HIGH"
            
        if cat_encoded == 0:  # Benign
            if num_behaviors == 0:
                return "INFORMATIONAL"
            elif num_behaviors == 1:
                return "LOW"
            return "MEDIUM"
            
        if cat_encoded == 1:  # Adware
            if num_behaviors <= 1:
                return "LOW"
            return "MEDIUM"
            
        if cat_encoded in [2, 3, 4, 5]:  # Malicious
            if num_behaviors >= 3:
                return "CRITICAL"
            if num_behaviors >= 2:
                return "HIGH"
            return "MEDIUM"
            
        return "LOW"
