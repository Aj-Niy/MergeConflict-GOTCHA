import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Text,
    DateTime,
    ForeignKey,
    Boolean,
    JSON,
    Enum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.base import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    policies = relationship("Policy", back_populates="user", cascade="all, delete-orphan")
    batches = relationship("Batch", back_populates="user", cascade="all, delete-orphan")

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    url = Column(String(512), unique=True, index=True, nullable=False)
    owner = Column(String(128), index=True, nullable=False)
    name = Column(String(128), index=True, nullable=False)
    primary_language = Column(String(64), nullable=True)
    default_branch = Column(String(64), default="main")
    stars = Column(Integer, default=0)
    forks = Column(Integer, default=0)
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")

class Batch(Base):
    __tablename__ = "batches"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    label = Column(String(255), nullable=False)
    repo_urls_json = Column(JSON, nullable=False)  # List[str]
    total_repos = Column(Integer, default=0)
    completed_repos = Column(Integer, default=0)
    status = Column(String(32), default="QUEUED", index=True) # QUEUED, RUNNING, COMPLETED, PARTIALLY_FAILED, FAILED
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    user = relationship("User", back_populates="batches")
    scans = relationship("Scan", back_populates="batch", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False, index=True)
    batch_id = Column(String(36), ForeignKey("batches.id"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    
    status = Column(String(32), default="QUEUED", index=True)  
    # Lifecycle: QUEUED -> FETCHING -> ANALYZING -> CORRELATING -> SCORING -> POLICY_EVALUATION -> ATTESTING -> COMPLETED / FAILED
    
    risk_score = Column(Float, default=0.0) # 0 to 100
    trust_score = Column(Float, default=100.0) # 100 - risk_score
    risk_category = Column(String(32), default="LOW") # CRITICAL, HIGH, MEDIUM, LOW, TRUSTED
    verdict = Column(String(255), nullable=True)
    verdict_summary = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    claims_json = Column(JSON, nullable=True) # List[str]
    behaviors_json = Column(JSON, nullable=True) # List[str]
    hidden_behaviors_json = Column(JSON, nullable=True) # List[str]
    dimension_scores_json = Column(JSON, nullable=True) # Breakdown of 5 dimensions
    
    access_token = Column(String(64), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    user = relationship("User", back_populates="scans")
    repository = relationship("Repository", back_populates="scans")
    batch = relationship("Batch", back_populates="scans")
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    comparisons = relationship("ComparisonEntry", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    secrets = relationship("SecretFinding", back_populates="scan", cascade="all, delete-orphan")
    policy_evaluations = relationship("PolicyEvaluation", back_populates="scan", cascade="all, delete-orphan")
    attestation = relationship("SecurityAttestation", back_populates="scan", uselist=False, cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    category = Column(String(32), nullable=False) # static, capability, secret, dependency, threat_rule
    capability_label = Column(String(64), nullable=True) # Filesystem, Network, Environment, Database, Shell, Subprocess, etc.
    severity = Column(String(32), nullable=False, index=True) # critical, high, medium, low, info, trusted
    confidence = Column(String(32), default="high") # high, medium, low
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    snippet = Column(Text, nullable=True)
    description = Column(Text, nullable=False)
    source = Column(String(32), default="behavior") # claim, behavior, secret, dependency, threat_rule
    metadata_json = Column(JSON, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")

class ComparisonEntry(Base):
    __tablename__ = "comparison_entries"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    claimed_capability = Column(String(128), nullable=False)
    detected_capability = Column(String(128), nullable=False)
    match_state = Column(String(32), nullable=False) # match, partial, mismatch, undisclosed
    severity = Column(String(32), nullable=False)
    notes = Column(Text, nullable=True)
    
    scan = relationship("Scan", back_populates="comparisons")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    package_name = Column(String(128), nullable=False)
    version = Column(String(64), nullable=False)
    cve_id = Column(String(64), nullable=False, index=True) # GHSA-... or CVE-...
    severity = Column(String(32), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    summary = Column(Text, nullable=True)
    fixed_version = Column(String(64), nullable=True)
    source = Column(String(64), default="osv.dev")
    
    scan = relationship("Scan", back_populates="vulnerabilities")

class SecretFinding(Base):
    __tablename__ = "secret_findings"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    secret_type = Column(String(64), nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=True)
    redacted_value = Column(String(128), nullable=False)
    confidence = Column(String(32), default="high")
    
    scan = relationship("Scan", back_populates="secrets")

class Policy(Base):
    __tablename__ = "policies"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    rules_json = Column(JSON, nullable=False) # dict mapping capability/rule -> ALLOW | WARN | RESTRICT | BLOCK
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    user = relationship("User", back_populates="policies")
    evaluations = relationship("PolicyEvaluation", back_populates="policy", cascade="all, delete-orphan")

class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    policy_id = Column(String(36), ForeignKey("policies.id"), nullable=False, index=True)
    decision = Column(String(32), nullable=False) # ALLOW, WARN, RESTRICT, BLOCK
    triggered_rules_json = Column(JSON, nullable=False) # list of triggered rules with reason
    evaluated_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scan = relationship("Scan", back_populates="policy_evaluations")
    policy = relationship("Policy", back_populates="evaluations")

class SecurityAttestation(Base):
    __tablename__ = "security_attestations"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, unique=True, index=True)
    trust_score = Column(Float, nullable=False)
    risk_category = Column(String(32), nullable=False)
    recommendation = Column(String(64), nullable=False)
    capabilities_json = Column(JSON, nullable=False)
    hidden_capabilities_json = Column(JSON, nullable=False)
    content_hash = Column(String(64), nullable=False) # SHA-256 canonical hash
    signature = Column(Text, nullable=False) # Hex or Base64 Ed25519 signature
    public_key = Column(Text, nullable=False) # PEM or Hex public key
    issued_at = Column(DateTime(timezone=True), server_default=func.now())
    
    scan = relationship("Scan", back_populates="attestation")
