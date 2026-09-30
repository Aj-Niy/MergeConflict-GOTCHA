from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from datetime import datetime

class PolicyBase(BaseModel):
    name: str
    description: Optional[str] = None
    rules_json: Dict[str, str] # e.g. {"Shell": "BLOCK", "Network": "WARN", "credential_exfil": "BLOCK"}
    is_default: bool = False

class PolicyCreate(PolicyBase):
    pass

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rules_json: Optional[Dict[str, str]] = None
    is_default: Optional[bool] = None

class PolicyOut(PolicyBase):
    id: str
    user_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class PolicyEvaluationOut(BaseModel):
    id: str
    scan_id: str
    policy_id: str
    policy_name: Optional[str] = None
    decision: str # ALLOW, WARN, RESTRICT, BLOCK
    triggered_rules_json: List[Dict[str, Any]]
    evaluated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
