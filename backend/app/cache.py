"""Small bounded TTL cache for read models.

The local implementation is intentionally process-local for the demo profile.
Production deployments should replace this adapter with Redis so all workers
share invalidation and cached values.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from time import monotonic
from typing import Any, Callable


@dataclass
class _Entry:
    expires_at: float
    value: Any


class TtlCache:
    def __init__(self, max_entries: int = 256) -> None:
        self._entries: dict[str, _Entry] = {}
        self._max_entries = max_entries
        self._lock = RLock()
        self._miss_locks: dict[str, RLock] = {}

    def get_or_set(self, key: str, ttl_seconds: float, factory: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._entries.get(key)
            if entry and entry.expires_at > monotonic():
                return entry.value
            miss_lock = self._miss_locks.setdefault(key, RLock())
        # Prevent a burst of requests from running the same expensive factory
        # concurrently, while allowing unrelated keys to populate in parallel.
        with miss_lock:
            with self._lock:
                entry = self._entries.get(key)
                if entry and entry.expires_at > monotonic():
                    return entry.value
                self._entries.pop(key, None)
            value = factory()
            with self._lock:
                if len(self._entries) >= self._max_entries:
                    oldest = min(self._entries, key=lambda item: self._entries[item].expires_at)
                    self._entries.pop(oldest, None)
                self._entries[key] = _Entry(monotonic() + ttl_seconds, value)
            return value

    def invalidate(self, prefix: str = "", contains: str | None = None) -> None:
        with self._lock:
            for key in list(self._entries):
                if (not prefix or key.startswith(prefix)) and (contains is None or contains in key):
                    self._entries.pop(key, None)


read_cache = TtlCache()
