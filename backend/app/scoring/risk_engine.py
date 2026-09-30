from typing import List, Dict, Any, Tuple
from app.schemas.scan import DimensionScore
from app.schemas.finding import FindingSchema, ComparisonEntrySchema, VulnerabilitySchema, SecretFindingSchema, SeverityEnum, FindingCategoryEnum

class WeightedRiskEngine:
    WEIGHTS = {
        "code_safety": 0.25,
        "secret_exposure": 0.20,
        "dependency_security": 0.20,
        "capability_risk": 0.15,
        "claim_behavior_gap": 0.20
    }

    def calculate_score(
        self,
        findings: List[FindingSchema],
        comparisons: List[ComparisonEntrySchema],
        vulnerabilities: List[VulnerabilitySchema],
        secrets: List[SecretFindingSchema],
        hidden_behaviors: List[str]
    ) -> Tuple[float, float, str, str, str, List[DimensionScore]]:
        """
        Returns:
            (risk_score, trust_score, risk_category, verdict, verdict_summary, dimension_breakdown)
        """
        # 1. Code Safety Dimension (Static & Threat Findings)
        code_penalties = 0.0
        code_evidence = []
        for f in findings:
            if f.category in (FindingCategoryEnum.STATIC, FindingCategoryEnum.THREAT_RULE):
                if f.severity == SeverityEnum.CRITICAL:
                    code_penalties += 40.0
                    code_evidence.append(f"Critical: {f.description}")
                elif f.severity == SeverityEnum.HIGH:
                    code_penalties += 25.0
                    code_evidence.append(f"High: {f.description}")
                elif f.severity == SeverityEnum.MEDIUM:
                    code_penalties += 10.0
                    code_evidence.append(f"Medium: {f.description}")
        dim_code_safety = min(100.0, code_penalties)

        # 2. Secret Exposure Dimension
        secret_penalties = 0.0
        secret_evidence = []
        for s in secrets:
            secret_penalties += 50.0
            secret_evidence.append(f"Exposed {s.secret_type} in {s.file_path}:{s.line_number or 1}")
        dim_secret_exposure = min(100.0, secret_penalties)

        # 3. Dependency Security Dimension
        dep_penalties = 0.0
        dep_evidence = []
        for v in vulnerabilities:
            if v.severity == "CRITICAL":
                dep_penalties += 40.0
            elif v.severity == "HIGH":
                dep_penalties += 25.0
            elif v.severity in ("MEDIUM", "MODERATE"):
                dep_penalties += 10.0
            else:
                dep_penalties += 5.0
            dep_evidence.append(f"{v.cve_id} ({v.package_name}@{v.version})")
        dim_dependency = min(100.0, dep_penalties)

        # 4. Capability Inherent Sensitivity
        cap_penalties = 0.0
        cap_evidence = []
        all_caps = {f.capability_label for f in findings if f.capability_label}
        if "Shell" in all_caps:
            cap_penalties += 40.0
            cap_evidence.append("Active Shell execution capability")
        if "NativeCodeExecution" in all_caps:
            cap_penalties += 35.0
            cap_evidence.append("Native binary / ctypes execution capability")
        if "Subprocess" in all_caps:
            cap_penalties += 25.0
            cap_evidence.append("Subprocess spawning capability")
        if "Environment" in all_caps:
            cap_penalties += 15.0
            cap_evidence.append("Environment variable inspection")
        if "Network" in all_caps:
            cap_penalties += 15.0
            cap_evidence.append("Outbound network connectivity")
        dim_capability = min(100.0, cap_penalties)

        # 5. Claim ↔ Behavior Gap Dimension
        gap_penalties = 0.0
        gap_evidence = []
        for hb in hidden_behaviors:
            if hb == "Shell":
                gap_penalties += 50.0
            elif hb in ("Subprocess", "Environment"):
                gap_penalties += 35.0
            elif hb == "Network":
                gap_penalties += 30.0
            else:
                gap_penalties += 20.0
            gap_evidence.append(f"Undisclosed capability: '{hb}'")
        
        for comp in comparisons:
            if comp.match_state == "mismatch":
                gap_penalties += 10.0
                gap_evidence.append(f"Claim mismatch: '{comp.claimed_capability}' claimed but not observed")
        dim_gap = min(100.0, gap_penalties)

        # Compute weighted aggregate
        breakdown = [
            DimensionScore(
                dimension="Code Safety",
                penalty=dim_code_safety,
                weight=self.WEIGHTS["code_safety"],
                weighted_penalty=round(dim_code_safety * self.WEIGHTS["code_safety"], 2),
                evidence=code_evidence
            ),
            DimensionScore(
                dimension="Secret Exposure",
                penalty=dim_secret_exposure,
                weight=self.WEIGHTS["secret_exposure"],
                weighted_penalty=round(dim_secret_exposure * self.WEIGHTS["secret_exposure"], 2),
                evidence=secret_evidence
            ),
            DimensionScore(
                dimension="Dependency Security",
                penalty=dim_dependency,
                weight=self.WEIGHTS["dependency_security"],
                weighted_penalty=round(dim_dependency * self.WEIGHTS["dependency_security"], 2),
                evidence=dep_evidence
            ),
            DimensionScore(
                dimension="Capability Inherent Risk",
                penalty=dim_capability,
                weight=self.WEIGHTS["capability_risk"],
                weighted_penalty=round(dim_capability * self.WEIGHTS["capability_risk"], 2),
                evidence=cap_evidence
            ),
            DimensionScore(
                dimension="Claim-Behavior Gap",
                penalty=dim_gap,
                weight=self.WEIGHTS["claim_behavior_gap"],
                weighted_penalty=round(dim_gap * self.WEIGHTS["claim_behavior_gap"], 2),
                evidence=gap_evidence
            ),
        ]

        total_risk = sum(item.weighted_penalty for item in breakdown)
        total_risk = round(min(100.0, max(0.0, total_risk)), 1)
        trust_score = round(100.0 - total_risk, 1)

        # Risk category categorization
        if trust_score < 40 or total_risk >= 60:
            category = "CRITICAL"
            verdict = "Critical Risk — Review Required"
            verdict_summary = f"Detected high-severity security concerns ({len(hidden_behaviors)} undisclosed capability/ies, {len(secrets)} secrets, {len(vulnerabilities)} CVEs). Immediate quarantine or audit required."
        elif trust_score < 60 or total_risk >= 41:
            category = "HIGH"
            verdict = "High Risk — Unverified Capabilities"
            verdict_summary = "Significant discrepancy detected between claimed functionality and observed code execution patterns."
        elif trust_score < 80 or total_risk >= 21:
            category = "MEDIUM"
            verdict = "Conditionally Trusted"
            verdict_summary = "Minor capability discrepancies or low-severity dependencies detected. Review recommended before privileged deployment."
        else:
            category = "LOW"
            verdict = "Trusted Repository"
            verdict_summary = "Code behavior aligns precisely with documentation claims. No critical anomalies or undisclosed privileged vectors detected."

        return total_risk, trust_score, category, verdict, verdict_summary, breakdown
