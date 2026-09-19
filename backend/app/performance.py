"""Lightweight timing instrumentation for request and background-job flows."""
from __future__ import annotations

import logging
import inspect
import sys
from collections import defaultdict
from functools import wraps
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from time import perf_counter
from typing import Iterator
from uuid import uuid4


logger = logging.getLogger("pnc.performance")
_current_timeline: ContextVar["TimingTimeline | None"] = ContextVar("pnc_timeline", default=None)
_aggregate_lock = __import__("threading").RLock()
_aggregate_totals: dict[str, dict[str, float | int]] = defaultdict(lambda: {"calls": 0, "total_ms": 0.0, "max_ms": 0.0})


class _StructuredFormatter(logging.Formatter):
    """Human-readable structured records shared by API and worker processes."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        message = record.getMessage()
        return f"{timestamp}\n[{record.threadName}]\n[{record.name}]\n{record.levelname}\n{message}"


def configure_logging() -> None:
    """Install the application logger once without replacing Uvicorn handlers."""
    root = logging.getLogger()
    if getattr(root, "_pnc_structured_logging", False):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_StructuredFormatter())
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    root._pnc_structured_logging = True  # type: ignore[attr-defined]


configure_logging()


class TimingTimeline:
    def __init__(self, correlation_id: str | None = None) -> None:
        self.correlation_id = correlation_id or str(uuid4())
        self.started_at = datetime.now(timezone.utc)
        self._started = perf_counter()
        self.events: list[dict[str, object]] = []

    @property
    def elapsed_ms(self) -> float:
        return round((perf_counter() - self._started) * 1000, 2)

    def mark(self, operation: str, duration_ms: float = 0, *, detail: str | None = None) -> None:
        event = {
            "operation": operation,
            "duration_ms": round(duration_ms, 2),
            "at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }
        if detail:
            event["detail"] = detail
        self.events.append(event)
        level = logging.WARNING if duration_ms >= 1000 else logging.INFO
        logger.log(level, "[%s] %s completed (%.2f ms)%s", self.correlation_id, operation, duration_ms, f" - {detail}" if detail else "")

    def report(self) -> dict[str, object]:
        """Return a compact report suitable for job polling and demo output."""
        totals: dict[str, float] = {}
        for event in self.events:
            operation = str(event["operation"])
            totals[operation] = round(totals.get(operation, 0.0) + float(event["duration_ms"]), 2)
        bottlenecks = sorted(totals.items(), key=lambda item: item[1], reverse=True)
        return {
            "stages": [{"operation": key, "duration_ms": value} for key, value in totals.items()],
            "top_bottlenecks": [
                {"rank": index, "operation": operation, "duration_ms": duration}
                for index, (operation, duration) in enumerate(bottlenecks[:5], 1)
            ],
            "total_ms": self.elapsed_ms,
        }

    def payload(self) -> dict[str, object]:
        return {
            "correlation_id": self.correlation_id,
            "started_at": self.started_at.isoformat(timespec="milliseconds"),
            "duration_ms": self.elapsed_ms,
            "events": self.events,
            "report": self.report(),
        }


@contextmanager
def timed(operation: str, *, detail: str | None = None, timeline: TimingTimeline | None = None) -> Iterator[None]:
    started = perf_counter()
    started_at = datetime.now().strftime("%H:%M:%S")
    logger.info("[START] %s%s", operation, f" - {detail}" if detail else "")
    try:
        yield
    finally:
        ended_at = datetime.now().strftime("%H:%M:%S")
        duration_ms = (perf_counter() - started) * 1000
        active = timeline or _current_timeline.get()
        if active:
            active.mark(operation, duration_ms, detail=detail)
        else:
            logger.info("%s completed (%.2f ms)%s", operation, duration_ms, f" - {detail}" if detail else "")
        with _aggregate_lock:
            aggregate = _aggregate_totals[operation]
            aggregate["calls"] = int(aggregate["calls"]) + 1
            aggregate["total_ms"] = float(aggregate["total_ms"]) + duration_ms
            aggregate["max_ms"] = max(float(aggregate["max_ms"]), duration_ms)
        logger.info("[END] %s at %s", operation, ended_at)
        logger.info("Duration: %.2f sec", duration_ms / 1000)


def timed_function(operation: str | None = None):
    """Decorate sync or async functions with the same timeline instrumentation."""
    def decorator(function):
        name = operation or function.__qualname__
        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def asynchronous(*args, **kwargs):
                with timed(name):
                    return await function(*args, **kwargs)
            return asynchronous

        @wraps(function)
        def synchronous(*args, **kwargs):
            with timed(name):
                return function(*args, **kwargs)
        return synchronous
    return decorator


# Public alias for callers that use the performance contract's decorator name.
measure_time = timed_function


def performance_report() -> dict[str, object]:
    """Return process-local totals for the demo and operational endpoints."""
    with _aggregate_lock:
        rows = [
            {"operation": name, "calls": int(values["calls"]),
             "total_ms": round(float(values["total_ms"]), 2),
             "max_ms": round(float(values["max_ms"]), 2)}
            for name, values in _aggregate_totals.items()
        ]
    return {"top_slowest_functions": sorted(rows, key=lambda row: row["total_ms"], reverse=True)[:10]}


def reset_performance_report() -> None:
    with _aggregate_lock:
        _aggregate_totals.clear()


def current_timeline() -> TimingTimeline | None:
    return _current_timeline.get()


def activate_timeline(timeline: TimingTimeline):
    return _current_timeline.set(timeline)


def reset_timeline(token) -> None:
    _current_timeline.reset(token)