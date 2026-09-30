from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.session import get_db
from app.models.entities import Batch, Scan, Repository, User
from app.schemas.batch import BatchResponse
from app.schemas.scan import BatchScanRequest, ScanSummary
from app.auth.dependencies import get_current_user, get_optional_current_user
from app.intake.tarball import parse_github_url
from app.tasks.pipeline import execute_scan_pipeline

router = APIRouter(prefix="/scan", tags=["Batches"])

def format_batch_response(batch: Batch, db: Session) -> BatchResponse:
    scans = db.query(Scan).filter(Scan.batch_id == batch.id).all()
    scan_summaries = []
    for s in scans:
        repo = s.repository
        scan_summaries.append(ScanSummary(
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

    return BatchResponse(
        id=batch.id,
        label=batch.label,
        total_repos=batch.total_repos,
        completed_repos=batch.completed_repos,
        status=batch.status,
        created_at=batch.created_at,
        completed_at=batch.completed_at,
        scans=scan_summaries
    )

@router.post("/batch", response_model=BatchResponse)
def create_batch_scan(
    req: BatchScanRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    if not req.urls:
        raise HTTPException(status_code=400, detail="Must provide at least one repository URL.")

    batch = Batch(
        user_id=current_user.id if current_user else None,
        label=req.label,
        repo_urls_json=req.urls,
        total_repos=len(req.urls),
        completed_repos=0,
        status="RUNNING"
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)

    # Process each repo in batch
    for url in req.urls:
        try:
            owner, name = parse_github_url(url)
        except Exception:
            owner, name = "repo", "package"

        repo = db.query(Repository).filter(Repository.url == url).first()
        if not repo:
            repo = Repository(url=url, owner=owner, name=name)
            db.add(repo)
            db.commit()
            db.refresh(repo)

        scan = Scan(
            repository_id=repo.id,
            batch_id=batch.id,
            user_id=current_user.id if current_user else None,
            status="QUEUED"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Run pipeline
        try:
            execute_scan_pipeline(scan_id=scan.id, db=db)
        except Exception as e:
            print(f"Batch item failed {url}: {e}")

    db.refresh(batch)
    return format_batch_response(batch, db)

@router.get("/batch/{batch_id}", response_model=BatchResponse)
def get_batch(batch_id: str, db: Session = Depends(get_db)):
    batch = db.query(Batch).filter(Batch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    return format_batch_response(batch, db)

@router.get("/batches", response_model=List[BatchResponse])
def list_batches(
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Batch)
    if current_user:
        query = query.filter((Batch.user_id == current_user.id) | (Batch.user_id == None))
    batches = query.order_by(Batch.created_at.desc()).all()
    return [format_batch_response(b, db) for b in batches]
