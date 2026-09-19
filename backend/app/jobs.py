"""Small in-process background job registry.

This keeps long-running local scans and Git operations off the request thread.
For multi-worker production deployments, replace this adapter with Redis/Celery.
"""
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Lock
from uuid import UUID, uuid4

from app.performance import TimingTimeline, activate_timeline, reset_timeline, timed


_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pnc-job")
_jobs: dict[UUID, dict] = {}
_lock = Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def submit(kind: str, tenant_id: UUID, task, *args, with_progress: bool = False) -> UUID:
    job_id = uuid4()
    timeline = TimingTimeline(str(job_id))
    with _lock:
        _jobs[job_id] = {
            "job_id": str(job_id),
            "kind": kind,
            "tenant_id": tenant_id,
            "status": "QUEUED",
            "queued_at": _now(),
            "timeline": timeline.payload(),
            "_timeline_object": timeline,
            "progress": {"phase": "QUEUED", "files_discovered": 0, "files_scanned": 0, "vulnerabilities_found": 0, "completion_percentage": 0.0},
        }

    def update_progress(**values) -> None:
        with _lock:
            progress = _jobs[job_id]["progress"]
            progress.update(values)
            if "phase" in values:
                progress["message"] = str(values["phase"])
            discovered = int(progress.get("files_discovered", 0))
            scanned = int(progress.get("files_scanned", 0))
            progress["completion_percentage"] = round((scanned / discovered) * 100, 1) if discovered else 0.0

    def run_task():
        token = activate_timeline(timeline)
        with _lock:
            _jobs[job_id]["status"] = "RUNNING"
            _jobs[job_id]["progress"]["phase"] = "Repository Loaded"
            _jobs[job_id]["started_at"] = _now()
        try:
            with timed(f"job.{kind}"):
                return task(*args, update_progress) if with_progress else task(*args)
        finally:
            reset_timeline(token)

    future = _executor.submit(run_task)
    with _lock:
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
            job["completed_at"] = _now()
            if job["status"] == "COMPLETED":
                job["progress"]["completion_percentage"] = 100.0
            job["timeline"] = timeline.payload()

    future.add_done_callback(complete)
    return job_id


def get(job_id: UUID, tenant_id: UUID) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job["tenant_id"] != tenant_id:
            return None
        if job["status"] == "RUNNING":
            job["timeline"] = job["_timeline_object"].payload()
        return {key: value for key, value in job.items() if key not in {"future", "tenant_id", "_timeline_object"}}