"""Small in-process background job registry.

This keeps long-running local scans and Git operations off the request thread.
For multi-worker production deployments, replace this adapter with Redis/Celery.
"""
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from uuid import UUID, uuid4


_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pnc-job")
_jobs: dict[UUID, dict] = {}
_lock = Lock()


def submit(kind: str, tenant_id: UUID, task, *args) -> UUID:
    job_id = uuid4()
    with _lock:
        _jobs[job_id] = {"job_id": str(job_id), "kind": kind, "tenant_id": tenant_id, "status": "QUEUED"}

    future = _executor.submit(task, *args)
    with _lock:
        _jobs[job_id]["status"] = "RUNNING"
        _jobs[job_id]["future"] = future

    def complete(done: Future) -> None:
        with _lock:
            job = _jobs[job_id]
            try:
                job["result"] = done.result()
                job["status"] = "COMPLETED"
            except Exception as exc:  # surfaced through the polling endpoint
                job["error"] = str(exc)
                job["status"] = "FAILED"

    future.add_done_callback(complete)
    return job_id


def get(job_id: UUID, tenant_id: UUID) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job["tenant_id"] != tenant_id:
            return None
        return {key: value for key, value in job.items() if key != "future" and key != "tenant_id"}