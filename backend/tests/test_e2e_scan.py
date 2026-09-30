import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.models.entities import Scan, Repository
from app.tasks.pipeline import execute_scan_pipeline

def test_full_pipeline_on_sample_skill():
    # Use in-memory SQLite for test
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()

    # Point to sample_skills directory
    sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_skills"))
    
    repo = Repository(
        url=sample_dir,
        owner="local",
        name="sample_skills"
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    scan = Scan(
        repository_id=repo.id,
        status="QUEUED"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    completed_scan = execute_scan_pipeline(scan.id, db=db)

    assert completed_scan.status == "COMPLETED"
    assert completed_scan.trust_score is not None
    assert len(completed_scan.findings) > 0
    assert completed_scan.attestation is not None
    assert len(completed_scan.attestation.signature) > 0
    assert len(completed_scan.policy_evaluations) > 0
    
    db.close()
