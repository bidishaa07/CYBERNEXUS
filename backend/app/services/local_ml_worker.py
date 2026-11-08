"""Durable single-process fallback for development hosts without Redis/Celery."""
from concurrent.futures import ThreadPoolExecutor
from backend.app.db.session import SessionLocal
from backend.app.models.models import MLTrainingRun, BackgroundTaskRun
from backend.app.workers import tasks

_executor=ThreadPoolExecutor(max_workers=1, thread_name_prefix="ml-retraining")

def submit(task_id: str, training_run_id: int) -> None:
    _executor.submit(tasks.retrain_model, task_id, training_run_id)

def resume_pending() -> int:
    db=SessionLocal()
    try:
        rows=db.query(MLTrainingRun).filter(MLTrainingRun.status.in_(["PENDING","RUNNING"])).all()
        count=0
        for run in rows:
            task=db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_name == "retrain_model", BackgroundTaskRun.status.in_(["PENDING","RUNNING"])).first()
            if task:
                submit(task.task_id,run.id); count += 1
        return count
    finally: db.close()
