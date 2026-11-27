from __future__ import annotations

import copy
import threading
import time
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..diagnostics import log_exception


@dataclass
class _Entry:
    value: dict[str, Any]
    computed_at: float
    generated_at: datetime
    refreshing: bool = False


@dataclass
class _Flight:
    done: threading.Event = field(default_factory=threading.Event)
    value: _Entry | None = None
    error: BaseException | None = None


class SnapshotCache:
    """Serve expensive dashboard aggregates from a short-lived in-process snapshot.

    * one loader per key runs at a time, so a slow query cannot pile up behind
      repeated page loads or the "refresh" button;
    * a snapshot older than ``ttl_seconds`` is returned immediately and refreshed
      in the background (until ``max_stale_seconds``, after which callers wait);
    * every result carries ``snapshot`` metadata so the UI can show "updated at".
    """

    def __init__(
        self,
        *,
        name: str,
        ttl_seconds: float = 30.0,
        max_stale_seconds: float = 900.0,
        max_entries: int = 64,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.name = name
        self.ttl_seconds = ttl_seconds
        self.max_stale_seconds = max(max_stale_seconds, ttl_seconds)
        self.max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[Hashable, _Entry] = {}
        self._flights: dict[Hashable, _Flight] = {}

    def get(self, key: Hashable, loader: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                age = self._clock() - entry.computed_at
                if age < self.ttl_seconds:
                    return self._render(entry, stale=False)
                if age < self.max_stale_seconds:
                    if not entry.refreshing:
                        entry.refreshing = True
                        self._refresh_in_background(key, loader)
                    return self._render(entry, stale=True)
            flight = self._flights.get(key)
            leader = flight is None
            if flight is None:
                flight = self._flights[key] = _Flight()

        if leader:
            try:
                flight.value = self._store(key, loader())
            except BaseException as exc:
                flight.error = exc
                raise
            finally:
                with self._lock:
                    self._flights.pop(key, None)
                flight.done.set()
            return self._render(flight.value, stale=False)

        flight.done.wait()
        if flight.error is not None:
            raise flight.error
        assert flight.value is not None
        return self._render(flight.value, stale=False)

    def invalidate(self, key: Hashable | None = None) -> None:
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)

    def _store(self, key: Hashable, value: dict[str, Any]) -> _Entry:
        entry = _Entry(value=value, computed_at=self._clock(), generated_at=datetime.now(UTC))
        with self._lock:
            if len(self._entries) >= self.max_entries and key not in self._entries:
                oldest = min(self._entries, key=lambda item: self._entries[item].computed_at)
                self._entries.pop(oldest, None)
            self._entries[key] = entry
        return entry

    def _refresh_in_background(self, key: Hashable, loader: Callable[[], dict[str, Any]]) -> None:
        def run() -> None:
            try:
                self._store(key, loader())
            except Exception:
                log_exception("snapshot-cache", "snapshot.refresh.failed", cache=self.name)
                with self._lock:
                    current = self._entries.get(key)
                    if current is not None:
                        current.refreshing = False

        threading.Thread(target=run, name=f"snapshot-{self.name}", daemon=True).start()

    def _render(self, entry: _Entry, *, stale: bool) -> dict[str, Any]:
        result = copy.deepcopy(entry.value)
        result["snapshot"] = {
            "generated_at": entry.generated_at.isoformat(),
            "age_seconds": max(0, round(self._clock() - entry.computed_at)),
            "stale": stale,
        }
        return result
