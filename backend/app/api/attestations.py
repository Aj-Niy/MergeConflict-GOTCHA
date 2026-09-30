from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.entities import SecurityAttestation, Scan
from app.schemas.attestation import AttestationOut, AttestationVerifyRequest, AttestationVerifyResponse
from app.attestation.verifier import verify_attestation
from app.config import settings

router = APIRouter(prefix="/attestation", tags=["Attestation"])

@router.get("/{attestation_id}/verify", response_model=AttestationVerifyResponse)
def verify_attestation_by_id(attestation_id: str, db: Session = Depends(get_db)):
    att = db.query(SecurityAttestation).filter(
        (SecurityAttestation.id == attestation_id) | (SecurityAttestation.scan_id == attestation_id)
    ).first()
    
    if not att:
        raise HTTPException(status_code=404, detail="Security attestation not found.")

    scan = db.query(Scan).filter(Scan.id == att.scan_id).first()
    repo_url = scan.repository.url if scan and scan.repository else ""

    payload = {
        "scan_id": str(att.scan_id),
        "repository_url": str(repo_url),
        "trust_score": round(float(att.trust_score), 2),
        "risk_category": str(att.risk_category).upper(),
        "recommendation": str(att.recommendation),
        "capabilities": sorted([str(c) for c in (att.capabilities_json or [])]),
        "hidden_capabilities": sorted([str(h) for h in (att.hidden_capabilities_json or [])]),
        "issuer": "GOTCHA-Trust-Engine-v2",
        "engine_version": settings.VERSION
    }

    is_valid, recomputed_hash, message = verify_attestation(
        payload=payload,
        content_hash=att.content_hash,
        signature_hex=att.signature,
        public_key_hex=att.public_key
    )

    return AttestationVerifyResponse(
        valid=is_valid,
        scan_id=att.scan_id,
        content_hash=att.content_hash,
        recomputed_hash=recomputed_hash,
        match=(recomputed_hash == att.content_hash),
        signature_valid=is_valid,
        issued_at=att.issued_at,
        message=message
    )

@router.post("/verify", response_model=AttestationVerifyResponse)
def verify_custom_attestation(req: AttestationVerifyRequest, db: Session = Depends(get_db)):
    if req.attestation_id or req.scan_id:
        target_id = req.attestation_id or req.scan_id
        return verify_attestation_by_id(target_id, db)
    
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide attestation_id or scan_id to verify."
    )
