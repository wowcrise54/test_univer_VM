from __future__ import annotations

import builtins
import threading
import time
from typing import Any

from .. import db

STALE_SWEEP_INTERVAL_SECONDS = 300


class OperationsRepository:
    def __init__(self) -> None:
        self._sweep_lock = threading.Lock()
        self._last_sweep = float("-inf")

    def _sweep_stale(self) -> None:
        """Close long-silent "active" rows, at most once per interval, before they are counted."""
        with self._sweep_lock:
            now = time.monotonic()
            if now - self._last_sweep < STALE_SWEEP_INTERVAL_SECONDS:
                return
            self._last_sweep = now
        db.interrupt_stale_operations()

    def list(self, **filters: Any) -> dict[str, Any]:
        self._sweep_stale()
        return db.list_operations(**filters, sync_sources=True)

    def summary(self) -> dict[str, Any]:
        self._sweep_stale()
        return db.get_operations_summary(sync_sources=True)

    def counters(self) -> dict[str, Any]:
        """Read-only counters for metrics scraping: no source sync, no writes."""
        return db.get_operations_summary(sync_sources=False)

    def get(self, operation_id: str) -> dict[str, Any] | None:
        return db.get_operation(operation_id, sync_sources=True)

    def saved_views(self, route: str) -> builtins.list[dict[str, Any]]:
        return db.list_saved_views(route)

    def clear_history(self, *, actor: str | None = None) -> dict[str, int]:
        """Hide finished operation rows while preserving records and active work."""
        db.sync_operations_from_sources()
        clearable_statuses = sorted(db.CLEARABLE_OPERATION_STATUSES)
        active_statuses = sorted(db.ACTIVE_OPERATION_STATUSES)
        with db.connect() as conn:
            archived_rows = conn.execute(
                """UPDATE operations
                   SET cleared_at = %s, cleared_by = %s
                   WHERE cleared_at IS NULL AND status = ANY(%s)
                   RETURNING operation_id""",
                (db.now_utc(), actor, clearable_statuses),
            ).fetchall()
            active_row = conn.execute(
                """SELECT COUNT(*) AS count FROM operations
                   WHERE cleared_at IS NULL AND status = ANY(%s)""",
                (active_statuses,),
            ).fetchone()
        assert active_row is not None
        return {
            "cleared_count": len(archived_rows),
            "active_preserved": int(active_row["count"] or 0),
        }
