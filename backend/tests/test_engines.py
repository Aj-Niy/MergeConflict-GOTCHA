from app.correlation.correlator import ClaimBehaviorCorrelator
from app.rules.threat_rules import ThreatRuleEngine
from app.scoring.risk_engine import WeightedRiskEngine
from app.policies.policy_engine import PolicyEngine, DEFAULT_SECURITY_POLICY
from app.attestation.signer import create_signed_attestation
from app.attestation.verifier import verify_attestation
from app.schemas.finding import FindingSchema, SeverityEnum, FindingCategoryEnum

def test_correlation_and_hidden_detection():
    claims = ["Filesystem", "Database"]
    detected = ["Filesystem", "Database", "Network", "Shell"]

    correlator = ClaimBehaviorCorrelator()
    comparisons, hidden = correlator.correlate(claims, detected)

    assert "Network" in hidden
    assert "Shell" in hidden
    
    matches = [c for c in comparisons if c.match_state == "match"]
    assert len(matches) == 2

def test_threat_rule_credential_exfil():
    findings = [
        FindingSchema(category=FindingCategoryEnum.SECRET, capability_label="SecretExposure", severity=SeverityEnum.CRITICAL, description="Found secret"),
        FindingSchema(category=FindingCategoryEnum.CAPABILITY, capability_label="Network", severity=SeverityEnum.INFO, description="Network call")
    ]
    rule_engine = ThreatRuleEngine()
    threats = rule_engine.evaluate_rules(findings, [], [])
    
    threat_labels = {t.capability_label for t in threats}
    assert "CredentialExfiltrationRisk" in threat_labels

def test_policy_engine_blocking():
    findings = [
        FindingSchema(category=FindingCategoryEnum.STATIC, capability_label="Shell", severity=SeverityEnum.CRITICAL, description="eval called")
    ]
    engine = PolicyEngine()
    decision, triggered = engine.evaluate(DEFAULT_SECURITY_POLICY, findings, ["Shell"])
    
    assert decision == "BLOCK"
    assert len(triggered) >= 1

def test_ed25519_attestation_lifecycle():
    content_hash, sig_hex, pub_hex, payload = create_signed_attestation(
        scan_id="scan-123",
        repository_url="https://github.com/test/repo",
        trust_score=95.0,
        risk_category="LOW",
        recommendation="Trusted Repository",
        capabilities=["Filesystem"],
        hidden_capabilities=[]
    )

    is_valid, recomputed, msg = verify_attestation(payload, content_hash, sig_hex, pub_hex)
    assert is_valid is True
    assert recomputed == content_hash
