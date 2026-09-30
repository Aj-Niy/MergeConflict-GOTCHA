import secrets
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from app.db.session import get_db
from app.models.entities import (
    Scan,
    Repository,
    User,
    Finding,
    ComparisonEntry,
    Vulnerability,
    SecretFinding,
    PolicyEvaluation,
    SecurityAttestation
)
from app.schemas.scan import (
    ScanCreateRequest,
    ScanSummary,
    ScanDetailResponse,
    ScanAnalyticsResponse,
    RepositoryOut,
    DimensionScore
)
from app.schemas.finding import FindingSchema, ComparisonEntrySchema, VulnerabilitySchema, SecretFindingSchema
from app.schemas.policy import PolicyEvaluationOut
from app.schemas.attestation import AttestationOut
from app.auth.dependencies import get_current_user, get_optional_current_user
from app.intake.tarball import parse_github_url
from app.tasks.pipeline import execute_scan_pipeline

router = APIRouter(tags=["Scans"])

def format_scan_detail(scan: Scan) -> ScanDetailResponse:
    repo = scan.repository
    repo_out = RepositoryOut(
        id=repo.id if repo else "",
        url=repo.url if repo else "",
        owner=repo.owner if repo else "",
        name=repo.name if repo else "",
        primary_language=repo.primary_language if repo else None,
        stars=repo.stars if repo else 0,
        forks=repo.forks if repo else 0,
        first_seen_at=repo.first_seen_at if repo else None
    )

    findings_out = [FindingSchema.model_validate(f) for f in scan.findings]
    comparisons_out = [ComparisonEntrySchema.model_validate(c) for c in scan.comparisons]
    vulns_out = [VulnerabilitySchema.model_validate(v) for v in scan.vulnerabilities]
    secrets_out = [SecretFindingSchema.model_validate(s) for s in scan.secrets]
    
    policy_evals_out = [
        PolicyEvaluationOut(
            id=pe.id,
            scan_id=pe.scan_id,
            policy_id=pe.policy_id,
            policy_name=pe.policy.name if pe.policy else "Security Policy",
            decision=pe.decision,
            triggered_rules_json=pe.triggered_rules_json or [],
            evaluated_at=pe.evaluated_at
        ) for pe in scan.policy_evaluations
    ]

    attestation_out = None
    if scan.attestation:
        att = scan.attestation
        attestation_out = AttestationOut(
            id=att.id,
            scan_id=att.scan_id,
            trust_score=att.trust_score,
            risk_category=att.risk_category,
            recommendation=att.recommendation,
            capabilities=att.capabilities_json or [],
            hidden_capabilities=att.hidden_capabilities_json or [],
            content_hash=att.content_hash,
            signature=att.signature,
            public_key=att.public_key,
            issued_at=att.issued_at
        )

    dim_breakdown = []
    if scan.dimension_scores_json:
        for d in scan.dimension_scores_json:
            dim_breakdown.append(DimensionScore(**d))

    return ScanDetailResponse(
        id=scan.id,
        repository=repo_out,
        status=scan.status,
        risk_score=scan.risk_score or 0.0,
        trust_score=scan.trust_score or 100.0,
        risk_category=scan.risk_category or "LOW",
        verdict=scan.verdict,
        verdict_summary=scan.verdict_summary,
        explanation=scan.explanation,
        remediation=scan.remediation,
        claims=scan.claims_json or [],
        behaviors=scan.behaviors_json or [],
        hidden_behaviors=scan.hidden_behaviors_json or [],
        dimension_breakdown=dim_breakdown,
        findings=findings_out,
        comparisons=comparisons_out,
        vulnerabilities=vulns_out,
        secrets=secrets_out,
        policy_evaluations=policy_evals_out,
        attestation=attestation_out,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )

@router.post("/scan", response_model=ScanDetailResponse)
@router.post("/scan/url")
def create_scan(
    req: ScanCreateRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    try:
        try:
            owner, name = parse_github_url(req.url)
        except Exception:
            owner, name = "repo", "package"

        repo = db.query(Repository).filter(Repository.url == req.url).first()
        if not repo:
            repo = Repository(
                url=req.url,
                owner=owner,
                name=name
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)

        scan = Scan(
            repository_id=repo.id,
            user_id=current_user.id if current_user else None,
            status="QUEUED",
            access_token=secrets.token_urlsafe(24)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Run pipeline
        completed_scan = execute_scan_pipeline(scan_id=scan.id, db=db)
        return format_scan_detail(completed_scan)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan execution failed: {str(e)}"
        )

@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
def get_scan_by_id(
    scan_id: str,
    access_token: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )

    # IDOR check: If scan is associated with a user and caller is a different user without access token
    if scan.user_id:
        if current_user and current_user.id != scan.user_id and access_token != scan.access_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this scan report."
            )

    return format_scan_detail(scan)

@router.get("/scan/history", response_model=List[dict])
def get_scan_history(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Scan)
    if current_user:
        query = query.filter((Scan.user_id == current_user.id) | (Scan.user_id == None))
    
    scans = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    
    history_items = []
    for s in scans:
        repo = s.repository
        history_items.append({
            "id": s.id,
            "url": repo.url if repo else "",
            "repo_name": f"{repo.owner}/{repo.name}" if repo else "unknown/unknown",
            "target_type": "github",
            "risk_score": s.risk_score or 0.0,
            "trust_score": s.trust_score or 100.0,
            "risk_level": s.risk_category or "LOW",
            "status": s.status,
            "explanation": s.explanation or s.verdict_summary or "",
            "claims": s.claims_json or [],
            "behavior": s.behaviors_json or [],
            "hidden_behaviors": s.hidden_behaviors_json or [],
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None
        })
    return history_items

@router.get("/scan/analytics", response_model=ScanAnalyticsResponse)
def get_analytics(
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).filter(Scan.status == "COMPLETED").all()
    total = len(scans)
    
    safe = sum(1 for s in scans if s.risk_category in ("LOW", "TRUSTED", "SAFE"))
    medium = sum(1 for s in scans if s.risk_category == "MEDIUM")
    high = sum(1 for s in scans if s.risk_category == "HIGH")
    critical = sum(1 for s in scans if s.risk_category == "CRITICAL")
    
    avg_risk = sum(s.risk_score or 0 for s in scans) / total if total else 0.0
    avg_trust = sum(s.trust_score or 100 for s in scans) / total if total else 100.0

    recent = []
    for s in scans[:10]:
        repo = s.repository
        recent.append(ScanSummary(
            id=s.id,
            repository_id=repo.id if repo else "",
            repository_name=f"{repo.owner}/{repo.name}" if repo else "unknown",
            repository_url=repo.url if repo else "",
            status=s.status,
            risk_score=s.risk_score or 0.0,
            trust_score=s.trust_score or 100.0,
            risk_category=s.risk_category or "LOW",
            verdict=s.verdict,
            created_at=s.created_at,
            completed_at=s.completed_at
        ))

    return ScanAnalyticsResponse(
        total_scans=total,
        safe_count=safe,
        medium_count=medium,
        high_count=high,
        critical_count=critical,
        average_trust_score=round(avg_trust, 1),
        average_risk_score=round(avg_risk, 1),
        recent_verifications=recent
    )
