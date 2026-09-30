from typing import Optional, Any, Dict
from pydantic import BaseModel
from enum import Enum

class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    TRUSTED = "trusted"

class FindingCategoryEnum(str, Enum):
    STATIC = "static"
    CAPABILITY = "capability"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    THREAT_RULE = "threat_rule"

class MatchStateEnum(str, Enum):
    MATCH = "match"
    PARTIAL = "partial"
    MISMATCH = "mismatch"
    UNDISCLOSED = "undisclosed"

class FindingSchema(BaseModel):
    id: Optional[str] = None
    category: str
    capability_label: Optional[str] = None
    severity: str
    confidence: str = "high"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    description: str
    source: str = "behavior"
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class ComparisonEntrySchema(BaseModel):
    id: Optional[str] = None
    claimed_capability: str
    detected_capability: str
    match_state: str
    severity: str
    notes: Optional[str] = None

    class Config:
        from_attributes = True

class VulnerabilitySchema(BaseModel):
    id: Optional[str] = None
    package_name: str
    version: str
    cve_id: str
    severity: str
    summary: Optional[str] = None
    fixed_version: Optional[str] = None
    source: str = "osv.dev"

    class Config:
        from_attributes = True

class SecretFindingSchema(BaseModel):
    id: Optional[str] = None
    secret_type: str
    file_path: str
    line_number: Optional[int] = None
    redacted_value: str
    confidence: str = "high"

    class Config:
        from_attributes = True
