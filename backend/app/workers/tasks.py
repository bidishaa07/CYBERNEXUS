"""Optional Celery tasks. API operation remains usable without a worker in development."""
import json
from datetime import datetime, timezone
from backend.app.core.config import settings
from backend.app.db.session import SessionLocal
from backend.app.models.models import BackgroundTaskRun
from backend.app.engines.contact_intelligence import phone_analysis
from backend.app.engines.email_authentication_verification import verify
from backend.app.services.ml_training import run_training

try:
    from celery import Celery
except ImportError:  # pragma: no cover
    Celery = None

celery_app = Celery("digital-trust", broker=settings.celery_broker_url, backend=settings.celery_result_backend) if Celery and settings.celery_broker_url else None
if celery_app:
    celery_app.conf.update(task_acks_late=True, task_time_limit=settings.celery_task_timeout_seconds, result_expires=3600)
    if settings.ml_retraining_schedule and settings.ml_retraining_dataset_id:
        from celery.schedules import crontab
        celery_app.conf.beat_schedule={"scheduled-ml-retraining":{"task":"backend.app.workers.tasks.scheduled_retraining","schedule":crontab(*settings.ml_retraining_schedule.split())}}

def _record(task_id, name, result=None, error=None):
    db=SessionLocal(); row=db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id==task_id).first()
    if row: row.status="FAILED" if error else "COMPLETED"; row.result_json=json.dumps(result) if result is not None else None; row.error=error; row.completed_at=datetime.now(timezone.utc); db.commit()
    db.close()

def refresh_phone(task_id: str, number: str):
    db=SessionLocal(); row=db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id==task_id).first()
    if row: row.status="RUNNING"; row.started_at=datetime.now(timezone.utc); db.commit(); db.close()
    try: result=phone_analysis(number); _record(task_id, "refresh_phone", result=result); return result
    except Exception as exc: _record(task_id, "refresh_phone", error=type(exc).__name__); raise

def refresh_email_authentication(task_id: str, domain: str, selector: str | None = None):
    db=SessionLocal(); row=db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id==task_id).first()
    if row: row.status="RUNNING"; row.started_at=datetime.now(timezone.utc); db.commit(); db.close()
    try: result=verify(domain, selector); _record(task_id, "refresh_email_authentication", result=result); return result
    except Exception as exc: _record(task_id, "refresh_email_authentication", error=type(exc).__name__); raise

def retrain_model(task_id: str, training_run_id: int):
    db=SessionLocal(); row=db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id==task_id).first()
    if row: row.status="RUNNING"; row.started_at=datetime.now(timezone.utc); db.commit()
    db.close()
    try: result=run_training(training_run_id); _record(task_id,"retrain_model",result=result); return result
    except Exception as exc: _record(task_id,"retrain_model",error=type(exc).__name__); raise

def scheduled_retraining():
    from backend.app.models.models import MLDatasetVersion, MLTrainingRun
    db=SessionLocal()
    try:
        dataset=db.get(MLDatasetVersion,settings.ml_retraining_dataset_id)
        if not dataset or dataset.approval_status != "APPROVED": return {"status":"SKIPPED","reason":"dataset_not_approved"}
        run=MLTrainingRun(dataset_version_id=dataset.id,status="PENDING",created_by="celery-scheduler"); db.add(run); db.commit(); db.refresh(run)
        return run_training(run.id)
    finally: db.close()

if celery_app:
    refresh_phone = celery_app.task(bind=False, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)(refresh_phone)
    refresh_email_authentication = celery_app.task(bind=False, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)(refresh_email_authentication)
    retrain_model = celery_app.task(bind=False, autoretry_for=(Exception,), retry_backoff=True, max_retries=2, time_limit=settings.celery_task_timeout_seconds)(retrain_model)
    scheduled_retraining = celery_app.task(bind=False)(scheduled_retraining)
