import json
from typing import List, Dict, Any, Tuple
from openai import OpenAI
from app.config import settings
from app.schemas.finding import FindingSchema, ComparisonEntrySchema, VulnerabilitySchema, SecretFindingSchema
from app.schemas.scan import DimensionScore

EXPLAINER_SYSTEM_PROMPT = """
You are the GOTCHA AI Security Intelligence Analyst.
You are given a structured evidence bundle from a static and behavioral audit of a software repository.
Your task is to provide:
1. An executive explanation synthesizing the exact risk posture, trust discrepancies, and threat vectors found.
2. A list of concrete, prioritized remediation steps.

Rules:
- Strictly reference only the findings, capabilities, secrets, or vulnerabilities provided in the evidence bundle.
- Do NOT hallucinate nonexistent files or finding IDs.
- Return valid JSON with schema:
{
  "explanation": "...",
  "remediation": "..."
}
"""

def generate_deterministic_explanation(
    trust_score: float,
    risk_category: str,
    claims: List[str],
    hidden_behaviors: List[str],
    findings: List[FindingSchema],
    secrets: List[SecretFindingSchema],
    vulnerabilities: List[VulnerabilitySchema]
) -> Tuple[str, str]:
    explanation_parts = []
    remediation_parts = []

    if risk_category in ("CRITICAL", "HIGH"):
        explanation_parts.append(
            f"Security Audit Verdict: {risk_category} Risk (Trust Score: {trust_score}/100)."
        )
        if hidden_behaviors:
            explanation_parts.append(
                f"Static analysis detected {len(hidden_behaviors)} undisclosed capability/ies ({', '.join(hidden_behaviors)}) that are actively executed in the codebase but omitted from documentation."
            )
            remediation_parts.append(
                f"1. Audit and document or sandbox all undisclosed operations ({', '.join(hidden_behaviors)})."
            )
        if secrets:
            explanation_parts.append(
                f"Identified {len(secrets)} exposed hardcoded credential(s) or private key(s)."
            )
            remediation_parts.append(
                "2. Revoke and rotate all exposed API keys and secrets immediately; migrate to an environment secret manager."
            )
        if vulnerabilities:
            explanation_parts.append(
                f"Identified {len(vulnerabilities)} vulnerable third-party dependencies from OSV database."
            )
            remediation_parts.append(
                "3. Upgrade vulnerable dependencies to their patched versions."
            )
    elif risk_category == "MEDIUM":
        explanation_parts.append(
            f"Security Audit Verdict: Medium Risk (Trust Score: {trust_score}/100). Minor discrepancies were observed between declared capabilities and static behavior."
        )
        if hidden_behaviors:
            explanation_parts.append(
                f"Code accesses {', '.join(hidden_behaviors)} without full documentation."
            )
        remediation_parts.append(
            "1. Clarify repository documentation to reflect observed filesystem/network requirements."
        )
    else:
        explanation_parts.append(
            f"Security Audit Verdict: High Trust / Low Risk (Trust Score: {trust_score}/100). Observed code behavior strictly conforms to stated documentation without unexpected privileged execution vectors."
        )
        remediation_parts.append(
            "1. Maintain continuous automated CI/CD verification against new pull requests."
        )

    return "\n\n".join(explanation_parts), "\n".join(remediation_parts)

class AIExplainer:
    def __init__(self):
        self.api_key = settings.LLM_API_KEY
        self.client = None
        if self.api_key:
            try:
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=settings.LLM_BASE_URL
                )
            except Exception:
                self.client = None

    def explain(
        self,
        trust_score: float,
        risk_category: str,
        claims: List[str],
        behaviors: List[str],
        hidden_behaviors: List[str],
        findings: List[FindingSchema],
        secrets: List[SecretFindingSchema],
        vulnerabilities: List[VulnerabilitySchema],
        dimension_breakdown: List[DimensionScore]
    ) -> Tuple[str, str]:
        # Fallback if no LLM configured
        if not self.client:
            return generate_deterministic_explanation(
                trust_score=trust_score,
                risk_category=risk_category,
                claims=claims,
                hidden_behaviors=hidden_behaviors,
                findings=findings,
                secrets=secrets,
                vulnerabilities=vulnerabilities
            )

        evidence_bundle = {
            "trust_score": trust_score,
            "risk_category": risk_category,
            "declared_claims": claims,
            "detected_behaviors": behaviors,
            "undisclosed_behaviors": hidden_behaviors,
            "top_findings": [f.model_dump() for f in findings[:15]],
            "exposed_secrets": [s.model_dump() for s in secrets],
            "vulnerabilities": [v.model_dump() for v in vulnerabilities[:10]],
            "dimension_scores": [d.model_dump() for d in dimension_breakdown]
        }

        try:
            resp = self.client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[
                    {"role": "system", "content": EXPLAINER_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Evidence Bundle:\n{json.dumps(evidence_bundle, indent=2)}"}
                ],
                temperature=0.2,
                response_format={"type": "json_object"} if "gpt" in settings.LLM_MODEL.lower() else None
            )
            res_content = resp.choices[0].message.content.strip()
            data = json.loads(res_content)
            explanation = data.get("explanation", "")
            remediation = data.get("remediation", "")
            if explanation and remediation:
                return explanation, remediation
        except Exception as e:
            print(f"LLM explanation fallback triggered: {e}")

        return generate_deterministic_explanation(
            trust_score=trust_score,
            risk_category=risk_category,
            claims=claims,
            hidden_behaviors=hidden_behaviors,
            findings=findings,
            secrets=secrets,
            vulnerabilities=vulnerabilities
        )
