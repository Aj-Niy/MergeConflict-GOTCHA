from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from app.schemas.finding import FindingSchema, ComparisonEntrySchema, VulnerabilitySchema, SecretFindingSchema
from app.schemas.policy import PolicyEvaluationOut
from app.schemas.attestation import AttestationOut

class RepositoryOut(BaseModel):
    id: str
    url: str
    owner: str
    name: str
    primary_language: Optional[str] = None
    default_branch: str = "main"
    stars: int = 0
    forks: int = 0
    first_seen_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class DimensionScore(BaseModel):
    dimension: str
    penalty: float
    weight: float
    weighted_penalty: float
    evidence: List[str] = Field(default_factory=list)

class ScanCreateRequest(BaseModel):
    url: str
    target_type: Optional[str] = "github"
    deep: bool = True
    include_dependencies: bool = True
    policy_id: Optional[str] = None

class BatchScanRequest(BaseModel):
    label: str
    urls: List[str]
    policy_id: Optional[str] = None

class ScanSummary(BaseModel):
    id: str
    repository_id: str
    repository_name: str
    repository_url: str
    status: str
    risk_score: float
    trust_score: float
    risk_category: str
    verdict: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ScanDetailResponse(BaseModel):
    id: str
    repository: RepositoryOut
    status: str
    risk_score: float
    trust_score: float
    risk_category: str
    verdict: Optional[str] = None
    verdict_summary: Optional[str] = None
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    claims: List[str] = Field(default_factory=list)
    behaviors: List[str] = Field(default_factory=list)
    hidden_behaviors: List[str] = Field(default_factory=list)
    dimension_breakdown: List[DimensionScore] = Field(default_factory=list)
    findings: List[FindingSchema] = Field(default_factory=list)
    comparisons: List[ComparisonEntrySchema] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilitySchema] = Field(default_factory=list)
    secrets: List[SecretFindingSchema] = Field(default_factory=list)
    policy_evaluations: List[PolicyEvaluationOut] = Field(default_factory=list)
    attestation: Optional[AttestationOut] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ScanAnalyticsResponse(BaseModel):
    total_scans: int
    safe_count: int
    medium_count: int
    high_count: int
    critical_count: int
    average_trust_score: float
    average_risk_score: float
    recent_verifications: List[ScanSummary] = Field(default_factory=list)
