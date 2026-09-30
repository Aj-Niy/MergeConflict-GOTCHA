from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

class AttestationOut(BaseModel):
    id: str
    scan_id: str
    trust_score: float
    risk_category: str
    recommendation: str
    capabilities: List[str]
    hidden_capabilities: List[str]
    content_hash: str
    signature: str
    public_key: str
    issued_at: datetime

    class Config:
        from_attributes = True

class AttestationVerifyRequest(BaseModel):
    attestation_id: Optional[str] = None
    scan_id: Optional[str] = None
    content_hash: Optional[str] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None

class AttestationVerifyResponse(BaseModel):
    valid: bool
    scan_id: str
    content_hash: str
    recomputed_hash: str
    match: bool
    signature_valid: bool
    issued_at: Optional[datetime] = None
    message: str
