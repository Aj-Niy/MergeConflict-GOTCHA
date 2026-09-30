from typing import Dict, List, Any, Tuple
from app.schemas.finding import FindingSchema, SeverityEnum
from app.schemas.policy import PolicyEvaluationOut

DECISION_ORDER = {
    "BLOCK": 4,
    "RESTRICT": 3,
    "WARN": 2,
    "ALLOW": 1
}

DEFAULT_SECURITY_POLICY = {
    "Shell": "BLOCK",
    "UndisclosedShellExecution": "BLOCK",
    "CredentialExfiltrationRisk": "BLOCK",
    "SecretExposure": "BLOCK",
    "EnvironmentStealerPattern": "RESTRICT",
    "NativeCodeExecution": "RESTRICT",
    "DynamicBackdoorRisk": "RESTRICT",
    "Subprocess": "WARN",
    "Network": "ALLOW",
    "Environment": "ALLOW",
    "Filesystem": "ALLOW",
    "Database": "ALLOW"
}

class PolicyEngine:
    def evaluate(
        self,
        policy_rules: Dict[str, str],
        findings: List[FindingSchema],
        hidden_behaviors: List[str]
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Evaluates findings deterministically against policy rules.
        Returns:
            (overall_decision: ALLOW|WARN|RESTRICT|BLOCK, triggered_rules: List[Dict])
        """
        highest_decision = "ALLOW"
        triggered = []

        rules = policy_rules if policy_rules else DEFAULT_SECURITY_POLICY

        # 1. Check undisclosed behaviors against rules
        for hb in hidden_behaviors:
            if hb in rules:
                rule_action = rules[hb].upper()
                if rule_action in ("WARN", "RESTRICT", "BLOCK"):
                    triggered.append({
                        "rule": f"Undisclosed-{hb}",
                        "action": rule_action,
                        "reason": f"Undisclosed capability '{hb}' triggered policy action '{rule_action}'."
                    })
                    if DECISION_ORDER.get(rule_action, 1) > DECISION_ORDER.get(highest_decision, 1):
                        highest_decision = rule_action

        # 2. Check findings capability_labels / categories
        for f in findings:
            key = f.capability_label or f.category
            if key in rules:
                rule_action = rules[key].upper()
                if rule_action in ("WARN", "RESTRICT", "BLOCK"):
                    triggered.append({
                        "rule": key,
                        "action": rule_action,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "reason": f.description
                    })
                    if DECISION_ORDER.get(rule_action, 1) > DECISION_ORDER.get(highest_decision, 1):
                        highest_decision = rule_action

        return highest_decision, triggered
