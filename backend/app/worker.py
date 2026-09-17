"""Celery entry point for asynchronous platform jobs.

Workers are intentionally thin: durable state transitions belong to application
services and every task must be idempotent by workflow/event id.
"""
from celery import Celery

from app.settings import settings

celery_app = Celery("pnc-vuln-ai", broker=settings.rabbitmq_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def process_scan(self, scan_id: str) -> dict[str, str]:
    """Worker contract; scanner adapters publish normalized findings to this task."""
    return {"scan_id": scan_id, "status": "ACCEPTED_FOR_PROCESSING"}


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def execute_remediation(self, workflow_id: str) -> dict[str, str]:
    """Run only pre-approval planning/validation; merge remains an approval command."""
    return {"workflow_id": workflow_id, "status": "PLANNING_QUEUED"}