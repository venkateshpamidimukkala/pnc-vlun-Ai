"""Celery entry point for asynchronous platform jobs.

Workers are intentionally thin: durable state transitions belong to application
services and every task must be idempotent by workflow/event id.
"""
from celery import Celery
import logging
from app.performance import timed_function

from app.settings import settings

celery_app = Celery("pnc-vuln-ai", broker=settings.rabbitmq_url, backend=settings.redis_url)
logger = logging.getLogger("pnc.worker")
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
@timed_function("worker.process_scan")
def process_scan(self, scan_id: str) -> dict[str, str]:
    """Worker contract; scanner adapters publish normalized findings to this task."""
    logger.info("Worker scan job=%s status=RUNNING", scan_id)
    result = {"scan_id": scan_id, "status": "ACCEPTED_FOR_PROCESSING"}
    logger.info("Worker scan job=%s status=COMPLETED", scan_id)
    return result


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
@timed_function("worker.execute_remediation")
def execute_remediation(self, workflow_id: str) -> dict[str, str]:
    """Run only pre-approval planning/validation; merge remains an approval command."""
    logger.info("Worker remediation job=%s status=RUNNING", workflow_id)
    result = {"workflow_id": workflow_id, "status": "PLANNING_QUEUED"}
    logger.info("Worker remediation job=%s status=COMPLETED", workflow_id)
    return result