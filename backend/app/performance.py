"""Lightweight timing instrumentation for request and background-job flows."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from time import perf_counter
from typing import Iterator
from uuid import uuid4


logger = logging.getLogger("pnc.performance")
_current_timeline: ContextVar["TimingTimeline | None"] = ContextVar("pnc_timeline", default=None)


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

    def payload(self) -> dict[str, object]:
        return {
            "correlation_id": self.correlation_id,
            "started_at": self.started_at.isoformat(timespec="milliseconds"),
            "duration_ms": self.elapsed_ms,
            "events": self.events,
        }


@contextmanager
def timed(operation: str, *, detail: str | None = None, timeline: TimingTimeline | None = None) -> Iterator[None]:
    started = perf_counter()
    try:
        yield
    finally:
        active = timeline or _current_timeline.get()
        if active:
            active.mark(operation, (perf_counter() - started) * 1000, detail=detail)
        else:
            logger.info("%s completed (%.2f ms)%s", operation, (perf_counter() - started) * 1000, f" - {detail}" if detail else "")


def current_timeline() -> TimingTimeline | None:
    return _current_timeline.get()


def activate_timeline(timeline: TimingTimeline):
    return _current_timeline.set(timeline)


def reset_timeline(token) -> None:
    _current_timeline.reset(token)