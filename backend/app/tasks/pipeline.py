import datetime
import traceback
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.entities import (
    Scan,
    Repository,
    Finding,
    ComparisonEntry,
    Vulnerability,
    SecretFinding,
    Policy,
    PolicyEvaluation,
    SecurityAttestation,
    Batch
)
from app.intake.tarball import fetch_repository_snapshot, parse_github_url
from app.analyzers.python.ast_visitor import PythonAstAnalyzer
from app.analyzers.javascript.js_visitor import JavaScriptAnalyzer
from app.analyzers.secrets.secret_scanner import SecretScanner
from app.analyzers.dependencies.dependency_scanner import DependencyScanner
from app.claims.claim_extractor import ClaimExtractor
from app.correlation.correlator import ClaimBehaviorCorrelator
from app.rules.threat_rules import ThreatRuleEngine
from app.scoring.risk_engine import WeightedRiskEngine
from app.explanations.ai_explainer import AIExplainer
from app.policies.policy_engine import PolicyEngine, DEFAULT_SECURITY_POLICY
from app.attestation.signer import create_signed_attestation
from app.schemas.finding import FindingSchema, SeverityEnum, FindingCategoryEnum

def execute_scan_pipeline(scan_id: str, db: Optional[Session] = None) -> Scan:
    """
    Executes the complete 12-stage security analysis pipeline for a scan.
    """
    own_db = False
    if db is None:
        db = SessionLocal()
        own_db = True

    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
        if not repo:
            raise ValueError(f"Repository for scan {scan_id} not found")

        # 1. FETCHING
        scan.status = "FETCHING"
        db.commit()

        snapshot = fetch_repository_snapshot(repo.url)
        if snapshot.files:
            # Detect primary language
            py_files = sum(1 for f in snapshot.files if f.language == "python")
            js_files = sum(1 for f in snapshot.files if f.language in ("javascript", "typescript"))
            if py_files >= js_files and py_files > 0:
                repo.primary_language = "Python"
            elif js_files > 0:
                repo.primary_language = "TypeScript" if any(f.language == "typescript" for f in snapshot.files) else "JavaScript"

        # 2. ANALYZING (Static, Secrets, Dependencies)
        scan.status = "ANALYZING"
        db.commit()

        all_findings: List[FindingSchema] = []
        observed_capabilities_set = set()

        # Python & JS Analyzers
        py_analyzer = PythonAstAnalyzer()
        js_analyzer = JavaScriptAnalyzer()

        for sf in snapshot.files:
            if sf.language == "python":
                f_list = py_analyzer.analyze_code(sf.content, sf.path)
                all_findings.extend(f_list)
                for f in f_list:
                    if f.capability_label:
                        observed_capabilities_set.add(f.capability_label)
            elif sf.language in ("javascript", "typescript"):
                f_list = js_analyzer.analyze_code(sf.content, sf.path)
                all_findings.extend(f_list)
                for f in f_list:
                    if f.capability_label:
                        observed_capabilities_set.add(f.capability_label)

        # Secrets Analyzer
        secret_scanner = SecretScanner()
        collected_secrets = []
        for sf in snapshot.files + snapshot.manifest_files:
            s_finds, s_models = secret_scanner.scan_content(sf.content, sf.path)
            all_findings.extend(s_finds)
            collected_secrets.extend(s_models)

        # Dependency Analyzer
        dep_scanner = DependencyScanner()
        dep_findings, collected_vulns = dep_scanner.scan_manifests(snapshot.manifest_files)
        all_findings.extend(dep_findings)

        # 3. CLAIM EXTRACTION
        claim_extractor = ClaimExtractor()
        extracted_claims = claim_extractor.extract(snapshot.readme_content)
        if not extracted_claims and not snapshot.readme_content:
            extracted_claims = ["Filesystem"] if snapshot.files else []

        # 4. CORRELATING
        scan.status = "CORRELATING"
        db.commit()

        correlator = ClaimBehaviorCorrelator()
        detected_behaviors_list = sorted(list(observed_capabilities_set))
        comparison_entries, hidden_behaviors = correlator.correlate(
            claims=extracted_claims,
            detected_behaviors=detected_behaviors_list
        )

        # 5. DETERMINISTIC THREAT RULES
        rule_engine = ThreatRuleEngine()
        threat_findings = rule_engine.evaluate_rules(
            findings=all_findings,
            claims=extracted_claims,
            hidden_behaviors=hidden_behaviors
        )
        all_findings.extend(threat_findings)

        # 6. SCORING
        scan.status = "SCORING"
        db.commit()

        risk_engine = WeightedRiskEngine()
        risk_score, trust_score, risk_cat, verdict, verdict_summary, dim_breakdown = risk_engine.calculate_score(
            findings=all_findings,
            comparisons=comparison_entries,
            vulnerabilities=collected_vulns,
            secrets=collected_secrets,
            hidden_behaviors=hidden_behaviors
        )

        # 7. AI EXPLANATION
        explainer = AIExplainer()
        explanation_text, remediation_text = explainer.explain(
            trust_score=trust_score,
            risk_category=risk_cat,
            claims=extracted_claims,
            behaviors=detected_behaviors_list,
            hidden_behaviors=hidden_behaviors,
            findings=all_findings,
            secrets=collected_secrets,
            vulnerabilities=collected_vulns,
            dimension_breakdown=dim_breakdown
        )

        # 8. POLICY EVALUATION
        scan.status = "POLICY_EVALUATION"
        db.commit()

        policy_engine = PolicyEngine()
        user_policies = db.query(Policy).filter(
            (Policy.user_id == scan.user_id) | (Policy.is_default == True)
        ).all()
        
        if not user_policies:
            # Create default policy in DB if missing
            default_pol = Policy(
                name="Default Zero-Trust Policy",
                description="Blocks undisclosed shells and credential exfiltration; restricts native code execution.",
                rules_json=DEFAULT_SECURITY_POLICY,
                is_default=True
            )
            db.add(default_pol)
            db.commit()
            db.refresh(default_pol)
            user_policies = [default_pol]

        for pol in user_policies:
            p_decision, triggered_rules = policy_engine.evaluate(
                policy_rules=pol.rules_json,
                findings=all_findings,
                hidden_behaviors=hidden_behaviors
            )
            pol_eval = PolicyEvaluation(
                scan_id=scan.id,
                policy_id=pol.id,
                decision=p_decision,
                triggered_rules_json=triggered_rules
            )
            db.add(pol_eval)

        # 9. ATTESTING (Ed25519 Signing)
        scan.status = "ATTESTING"
        db.commit()

        content_hash, signature_hex, pub_key_hex, canon_payload = create_signed_attestation(
            scan_id=scan.id,
            repository_url=repo.url,
            trust_score=trust_score,
            risk_category=risk_cat,
            recommendation=verdict,
            capabilities=detected_behaviors_list,
            hidden_capabilities=hidden_behaviors
        )

        attestation_record = SecurityAttestation(
            scan_id=scan.id,
            trust_score=trust_score,
            risk_category=risk_cat,
            recommendation=verdict,
            capabilities_json=detected_behaviors_list,
            hidden_capabilities_json=hidden_behaviors,
            content_hash=content_hash,
            signature=signature_hex,
            public_key=pub_key_hex
        )
        db.add(attestation_record)

        # 10. PERSIST ALL RELATIONS
        # Findings
        for f in all_findings:
            finding_row = Finding(
                scan_id=scan.id,
                category=f.category,
                capability_label=f.capability_label,
                severity=f.severity,
                confidence=f.confidence,
                file_path=f.file_path,
                line_number=f.line_number,
                snippet=f.snippet,
                description=f.description,
                source=f.source
            )
            db.add(finding_row)

        # Comparison entries
        for c in comparison_entries:
            comp_row = ComparisonEntry(
                scan_id=scan.id,
                claimed_capability=c.claimed_capability,
                detected_capability=c.detected_capability,
                match_state=c.match_state,
                severity=c.severity,
                notes=c.notes
            )
            db.add(comp_row)

        # Secrets
        for s in collected_secrets:
            sec_row = SecretFinding(
                scan_id=scan.id,
                secret_type=s.secret_type,
                file_path=s.file_path,
                line_number=s.line_number,
                redacted_value=s.redacted_value,
                confidence=s.confidence
            )
            db.add(sec_row)

        # Vulnerabilities
        for v in collected_vulns:
            vuln_row = Vulnerability(
                scan_id=scan.id,
                package_name=v.package_name,
                version=v.version,
                cve_id=v.cve_id,
                severity=v.severity,
                summary=v.summary,
                fixed_version=v.fixed_version,
                source=v.source
            )
            db.add(vuln_row)

        # 11. COMPLETED
        scan.status = "COMPLETED"
        scan.risk_score = risk_score
        scan.trust_score = trust_score
        scan.risk_category = risk_cat
        scan.verdict = verdict
        scan.verdict_summary = verdict_summary
        scan.explanation = explanation_text
        scan.remediation = remediation_text
        scan.claims_json = extracted_claims
        scan.behaviors_json = detected_behaviors_list
        scan.hidden_behaviors_json = hidden_behaviors
        scan.dimension_scores_json = [d.model_dump() for d in dim_breakdown]
        scan.completed_at = datetime.datetime.utcnow()

        # Update Batch if part of batch
        if scan.batch_id:
            batch = db.query(Batch).filter(Batch.id == scan.batch_id).first()
            if batch:
                batch.completed_repos = (batch.completed_repos or 0) + 1
                if batch.completed_repos >= batch.total_repos:
                    batch.status = "COMPLETED"
                    batch.completed_at = datetime.datetime.utcnow()
                else:
                    batch.status = "RUNNING"

        db.commit()
        db.refresh(scan)
        return scan

    except Exception as e:
        traceback.print_exc()
        if scan:
            scan.status = "FAILED"
            scan.error_message = str(e)
            scan.completed_at = datetime.datetime.utcnow()
            db.commit()
        raise e
    finally:
        if own_db:
            db.close()
