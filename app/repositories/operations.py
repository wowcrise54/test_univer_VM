from __future__ import annotations

import builtins
from typing import Any

from .. import db


class OperationsRepository:
    def list(self, **filters: Any) -> dict[str, Any]:
        return db.list_operations(**filters, sync_sources=True)

    def summary(self) -> dict[str, Any]:
        return db.get_operations_summary(sync_sources=True)

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
            active_count = conn.execute(
                """SELECT COUNT(*) AS count FROM operations
                   WHERE cleared_at IS NULL AND status = ANY(%s)""",
                (active_statuses,),
            ).fetchone()["count"]
        return {
            "cleared_count": len(archived_rows),
            "active_preserved": int(active_count or 0),
        }
