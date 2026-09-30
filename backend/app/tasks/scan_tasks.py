from app.tasks.celery_app import celery_app
from app.tasks.pipeline import execute_scan_pipeline

@celery_app.task(bind=True, name="tasks.run_scan")
def run_scan_task(self, scan_id: str):
    return execute_scan_pipeline(scan_id)
