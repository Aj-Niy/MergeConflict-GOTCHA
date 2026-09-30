from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from app.schemas.scan import ScanSummary

class BatchResponse(BaseModel):
    id: str
    label: str
    total_repos: int
    completed_repos: int
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    scans: List[ScanSummary] = []

    class Config:
        from_attributes = True
