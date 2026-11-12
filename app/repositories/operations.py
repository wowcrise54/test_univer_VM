"""Repository for operation lifecycle records: registration, idempotency keys, status transitions, source synchronisation, stale interruption, and row decoding."""

from __future__ import annotations

import builtins
import json
import threading
import time
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from ..diagnostics import log_event
from ..persistence import codecs, connection, schema
from ..persistence.codecs import clean_value, json_loads
from ..persistence.sql import validated_sort_sql
from .saved_views import list_saved_views

ACTIVE_OPERATION_STATUSES = {"queued", "running", "cancelling", "recovering"}


ATTENTION_OPERATION_STATUSES = {"failed", "interrupted", "completed_with_errors", "needs_attention"}


CLEARABLE_OPERATION_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "interrupted", "needs_attention"}


RETRYABLE_OPERATION_KINDS = {"asset_card_build", "passport_detail_sync", "automation_run"}


# A running operation reports progress through updated_at; silence this long means its worker is gone.
STALE_OPERATION_HOURS = 6


def register_operation(
    operation_id: str,
    *,
    kind: str,
    source_id: str,
    status: str = "queued",
    stage: str = "queued",
    progress_percent: int = 0,
    subject_type: str | None = None,
    subject_id: str | None = None,
    subject_label: str | None = None,
    message: str | None = None,
    error: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    trace_id: str | None = None,
    retry_of: str | None = None,
    idempotency_key: str | None = None,
    created_at: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    updated_at: str | None = None,
    _conn: psycopg.Connection[Any] | None = None,
) -> dict[str, Any]:
    """Create or refresh the normalized operation registry without replacing richer request data."""
    if _conn is None:
        schema.init_db()
    current = updated_at or codecs.now_utc()
    created = created_at or current
    clean_key = clean_value(idempotency_key)
    with (nullcontext(_conn) if _conn is not None else connection.connect()) as conn:
        row = conn.execute(
            """
            INSERT INTO operations (
                operation_id, kind, source_id, status, stage, progress_percent,
                subject_type, subject_id, subject_label, message, error_json,
                request_json, result_json, trace_id, retry_of, idempotency_key,
                created_at, started_at, finished_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(kind, source_id) DO UPDATE SET
                status = EXCLUDED.status,
                stage = EXCLUDED.stage,
                progress_percent = GREATEST(operations.progress_percent, EXCLUDED.progress_percent),
                subject_type = COALESCE(EXCLUDED.subject_type, operations.subject_type),
                subject_id = COALESCE(EXCLUDED.subject_id, operations.subject_id),
                subject_label = COALESCE(EXCLUDED.subject_label, operations.subject_label),
                message = COALESCE(EXCLUDED.message, operations.message),
                error_json = CASE WHEN EXCLUDED.error_json = '{}' THEN operations.error_json ELSE EXCLUDED.error_json END,
                request_json = CASE WHEN EXCLUDED.request_json = '{}' THEN operations.request_json ELSE EXCLUDED.request_json END,
                result_json = CASE WHEN EXCLUDED.result_json = '{}' THEN operations.result_json ELSE EXCLUDED.result_json END,
                trace_id = COALESCE(EXCLUDED.trace_id, operations.trace_id),
                retry_of = COALESCE(EXCLUDED.retry_of, operations.retry_of),
                idempotency_key = COALESCE(EXCLUDED.idempotency_key, operations.idempotency_key),
                cleared_at = CASE
                    WHEN EXCLUDED.status = ANY(ARRAY['queued', 'running', 'cancelling', 'recovering']) THEN NULL
                    ELSE operations.cleared_at
                END,
                cleared_by = CASE
                    WHEN EXCLUDED.status = ANY(ARRAY['queued', 'running', 'cancelling', 'recovering']) THEN NULL
                    ELSE operations.cleared_by
                END,
                started_at = COALESCE(EXCLUDED.started_at, operations.started_at),
                finished_at = COALESCE(EXCLUDED.finished_at, operations.finished_at),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (
                operation_id,
                kind,
                source_id,
                status,
                stage,
                max(0, min(100, int(progress_percent or 0))),
                subject_type,
                subject_id,
                subject_label,
                message,
                json.dumps(error or {}, ensure_ascii=False),
                json.dumps(request or {}, ensure_ascii=False),
                json.dumps(result or {}, ensure_ascii=False),
                trace_id,
                retry_of,
                clean_key,
                created,
                started_at,
                finished_at,
                current,
            ),
        ).fetchone()
        assert row is not None
        _append_operation_event(conn, dict(row))
    return decode_operation(dict(row))


def _append_operation_event(conn: psycopg.Connection[Any], row: dict[str, Any]) -> None:
    previous = conn.execute(
        """
        SELECT status, stage, message
        FROM operation_events
        WHERE operation_id = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (row["operation_id"],),
    ).fetchone()
    if previous and all(previous.get(key) == row.get(key) for key in ("status", "stage", "message")):
        return
    conn.execute(
        """
        INSERT INTO operation_events (operation_id, status, stage, message, details_json, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            row["operation_id"],
            row["status"],
            row["stage"],
            row.get("message"),
            json.dumps({"progress_percent": row.get("progress_percent", 0)}, ensure_ascii=False),
            row.get("updated_at") or codecs.now_utc(),
        ),
    )


def sync_operations_from_sources() -> None:
    """Refresh the registry from legacy job tables so old endpoints remain authoritative."""
    schema.init_db()
    with connection.connect() as conn:
        asset_jobs = conn.execute(
            """SELECT source.* FROM asset_card_build_jobs source
               LEFT JOIN operations op ON op.kind = 'asset_card_build' AND op.source_id = source.job_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        passport_jobs = conn.execute(
            """SELECT source.* FROM vulnerability_passport_detail_jobs source
               LEFT JOIN operations op ON op.kind = 'passport_detail_sync' AND op.source_id = source.job_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        postprocess_runs = conn.execute(
            """SELECT source.* FROM scan_postprocess_runs source
               LEFT JOIN operations op ON op.kind = 'scan_postprocess' AND op.source_id = source.run_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        import_runs = conn.execute(
            """SELECT source.* FROM import_runs source
               LEFT JOIN operations op ON op.kind = 'pdql_export' AND op.source_id = source.id::text
               WHERE op.operation_id IS NULL OR COALESCE(source.finished_at, source.started_at) > op.updated_at"""
        ).fetchall()
        removal_runs = conn.execute(
            """SELECT source.* FROM asset_removal_operations source
               LEFT JOIN operations op ON op.kind = 'asset_removal' AND op.source_id = source.id::text
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
    for raw in asset_jobs:
        row = dict(raw)
        register_operation(
            row["job_id"], kind="asset_card_build", source_id=row["job_id"],
            status=row["status"], stage=row.get("stage") or row["status"],
            progress_percent=row.get("progress_percent") or 0,
            subject_type="asset", subject_id=row.get("asset_id"), subject_label=row.get("asset_id"),
            message=row.get("message"), request=json_loads(row.get("request_json"), {}),
            result=json_loads(row.get("stats_json"), {}), trace_id=row.get("trace_id"),
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in passport_jobs:
        row = dict(raw)
        eligible = int(row.get("eligible_count") or 0)
        processed = int(row.get("processed_count") or 0)
        progress = 100 if not eligible else round(processed * 100 / eligible)
        register_operation(
            row["job_id"], kind="passport_detail_sync", source_id=row["job_id"],
            status=row["status"], stage=row["status"], progress_percent=progress,
            subject_type="vulnerability_passports", subject_label="Vulnerability passports",
            message=row.get("message"), error={"items": json_loads(row.get("errors_json"), [])},
            result={
                "requested_count": row.get("requested_count"), "eligible_count": eligible,
                "processed_count": processed, "loaded_count": row.get("loaded_count"),
                "failed_count": row.get("failed_count"), "skipped_fresh_count": row.get("skipped_fresh_count"),
            },
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in postprocess_runs:
        row = dict(raw)
        options = json_loads(row.get("options_json"), {})
        refresh_asset_id = options.get("refresh_asset_id") if isinstance(options, dict) else None
        refresh_label = options.get("refresh_asset_label") if isinstance(options, dict) else None
        total = max(int(row.get("target_count") or 0), int(row.get("total_job_count") or 0), 1)
        done = int(row.get("completed_count") or 0) + int(row.get("failed_count") or 0)
        progress = min(100, round(done * 100 / total))
        register_operation(
            row["run_id"], kind="scan_postprocess", source_id=row["run_id"],
            status=row["status"], stage=row.get("stage") or row["status"], progress_percent=progress,
            subject_type="asset_card" if refresh_asset_id else "scanner_task",
            subject_id=refresh_asset_id or row.get("mp_task_id"),
            subject_label=refresh_label or refresh_asset_id or row.get("mp_task_id"),
            message=row.get("message"), error={"message": row.get("error")} if row.get("error") else {},
            request=options,
            result={"mp_run_id": row.get("mp_run_id"), "completed_count": row.get("completed_count"), "failed_count": row.get("failed_count")},
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in import_runs:
        row = dict(raw)
        operation_id = f"import:{row['id']}"
        register_operation(
            operation_id, kind="pdql_export", source_id=str(row["id"]),
            status=row.get("status") or "completed", stage=row.get("status") or "completed",
            progress_percent=100 if row.get("finished_at") else 25,
            subject_type="export", subject_id=str(row["id"]), subject_label=row.get("csv_filename") or row.get("source"),
            message=row.get("error") or f"Imported {int(row.get('row_count') or 0)} rows",
            error={"message": row.get("error")} if row.get("error") else {},
            request={"pdql": row.get("pdql"), "delete_after_export": row.get("delete_after_export")},
            result={"row_count": row.get("row_count"), "asset_count": row.get("asset_count"), "finding_count": row.get("finding_count")},
            created_at=row.get("started_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("finished_at") or row.get("started_at"),
        )
    for raw in removal_runs:
        row = dict(raw)
        operation_id = f"removal:{row['id']}"
        status = row.get("status") or "queued"
        register_operation(
            operation_id, kind="asset_removal", source_id=str(row["id"]),
            status=status, stage=status, progress_percent=100 if status in {"completed", "success", "failed"} else 25,
            subject_type="assets", subject_id=row.get("operation_id"), subject_label="MP VM assets",
            message=row.get("message"), request={"asset_ids": json_loads(row.get("asset_ids_json"), [])},
            result=json_loads(row.get("raw_response_json"), {}),
            created_at=row.get("created_at"), started_at=row.get("created_at"),
            finished_at=row.get("updated_at") if status not in ACTIVE_OPERATION_STATUSES else None,
            updated_at=row.get("updated_at"),
        )


def interrupt_stale_operations(max_age_hours: float = STALE_OPERATION_HOURS) -> int:
    """Close operations that look active but have not been updated for ``max_age_hours``.

    Source rows that crashed mid-run (imports, removals, ad-hoc runner jobs) never reach a
    terminal status on their own and would otherwise stay "active" forever. A worker that is
    in fact still alive re-registers its real status on the next progress update.
    """
    schema.init_db()
    current = codecs.now_utc()
    cutoff = (datetime.now(UTC) - timedelta(hours=max_age_hours)).isoformat(timespec="seconds")
    message = f"Не обновлялась более {max_age_hours:g} ч; помечена прерванной автоматически."
    with connection.connect() as conn:
        rows = conn.execute(
            """
            UPDATE operations
            SET status = 'interrupted', stage = 'interrupted', message = %s,
                finished_at = COALESCE(finished_at, %s), updated_at = %s
            WHERE status = ANY(%s) AND updated_at < %s
            RETURNING *
            """,
            (message, current, current, sorted(ACTIVE_OPERATION_STATUSES), cutoff),
        ).fetchall()
        for row in rows:
            _append_operation_event(conn, dict(row))
    if rows:
        log_event("app", "operations.stale.interrupted", count=len(rows), max_age_hours=max_age_hours)
    return len(rows)


def list_operations(
    *,
    status: str | None = None,
    kind: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    sync_sources: bool = False,
) -> dict[str, Any]:
    if sync_sources:
        sync_operations_from_sources()
    clauses: list[str] = ["cleared_at IS NULL"]
    params: list[Any] = []
    if status:
        clauses.append("status = %s")
        params.append(status)
    if kind:
        clauses.append("kind = %s")
        params.append(kind)
    if q:
        clauses.append(
            "(LOWER(COALESCE(operation_id, '')) LIKE %s "
            "OR LOWER(COALESCE(subject_label, '')) LIKE %s "
            "OR LOWER(COALESCE(subject_id, '')) LIKE %s "
            "OR LOWER(COALESCE(message, '')) LIKE %s)"
        )
        needle = f"%{q.strip().lower()}%"
        params.extend([needle, needle, needle, needle])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    sort_expression, direction = validated_sort_sql(
        sort_by,
        sort_dir,
        {"created_at": "created_at", "updated_at": "updated_at", "status": "LOWER(status)", "kind": "LOWER(kind)", "subject": "LOWER(subject_label)", "progress": "progress_percent"},
        default="created_at",
    )
    if sort_by is None:
        direction = "DESC"
    with connection.connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM operations {where}", params).fetchone()
        assert total_row is not None
        total = total_row["count"]
        rows = conn.execute(
            f"SELECT * FROM operations {where} ORDER BY {sort_expression} {direction} NULLS LAST, operation_id ASC LIMIT %s OFFSET %s",
            [*params, limit, offset],
        ).fetchall()
    return {"total": int(total), "rows": [decode_operation(dict(row)) for row in rows], "limit": limit, "offset": offset}


def get_operations_summary(*, sync_sources: bool = False) -> dict[str, Any]:
    """Return unfiltered operation counters for navigation and overview widgets."""
    if sync_sources:
        sync_operations_from_sources()
    with connection.connect() as conn:
        totals = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = ANY(%s)) AS active,
                COUNT(*) FILTER (WHERE status = ANY(%s)) AS attention,
                MAX(updated_at) AS updated_at
            FROM operations
            WHERE cleared_at IS NULL
            """,
            (sorted(ACTIVE_OPERATION_STATUSES), sorted(ATTENTION_OPERATION_STATUSES)),
        ).fetchone()
        status_rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM operations WHERE cleared_at IS NULL GROUP BY status ORDER BY status"
        ).fetchall()
        kind_rows = conn.execute(
            "SELECT kind, COUNT(*) AS count FROM operations WHERE cleared_at IS NULL GROUP BY kind ORDER BY kind"
        ).fetchall()
    assert totals is not None
    return {
        "total": int(totals["total"] or 0),
        "active": int(totals["active"] or 0),
        "attention": int(totals["attention"] or 0),
        "by_status": {str(row["status"]): int(row["count"] or 0) for row in status_rows},
        "by_kind": {str(row["kind"]): int(row["count"] or 0) for row in kind_rows},
        "updated_at": totals.get("updated_at"),
    }


def get_operation(operation_id: str, *, include_events: bool = True, sync_sources: bool = False) -> dict[str, Any] | None:
    if sync_sources:
        sync_operations_from_sources()
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM operations WHERE operation_id = %s", (operation_id,)).fetchone()
        if not row:
            return None
        events = conn.execute(
            "SELECT * FROM operation_events WHERE operation_id = %s ORDER BY id DESC LIMIT 100",
            (operation_id,),
        ).fetchall() if include_events else []
    result = decode_operation(dict(row))
    if include_events:
        result["events"] = [decode_operation_event(dict(item)) for item in reversed(events)]
    return result


def get_operation_by_idempotency_key(idempotency_key: str | None) -> dict[str, Any] | None:
    clean_key = clean_value(idempotency_key)
    if not clean_key:
        return None
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM operations WHERE idempotency_key = %s", (clean_key,)).fetchone()
    return decode_operation(dict(row)) if row else None


def set_operation_retry(operation_id: str, retry_of: str, idempotency_key: str | None = None) -> dict[str, Any] | None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            "UPDATE operations SET retry_of = %s, idempotency_key = COALESCE(%s, idempotency_key), updated_at = %s WHERE operation_id = %s RETURNING *",
            (retry_of, clean_value(idempotency_key), current, operation_id),
        ).fetchone()
    return decode_operation(dict(row)) if row else None


def decode_operation(row: dict[str, Any]) -> dict[str, Any]:
    status = str(row.get("status") or "unknown")
    kind = str(row.get("kind") or "unknown")
    return {
        "operation_id": row.get("operation_id"),
        "kind": kind,
        "source_id": row.get("source_id"),
        "status": status,
        "stage": row.get("stage"),
        "progress_percent": max(0, min(100, int(row.get("progress_percent") or 0))),
        "subject": {
            "type": row.get("subject_type"),
            "id": row.get("subject_id"),
            "label": row.get("subject_label"),
        },
        "message": row.get("message"),
        "error": json_loads(row.get("error_json"), {}),
        "request": json_loads(row.get("request_json"), {}),
        "result": json_loads(row.get("result_json"), {}),
        "trace_id": row.get("trace_id"),
        "retry_of": row.get("retry_of"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
        "can_cancel": status in ACTIVE_OPERATION_STATUSES and kind in {
            "asset_card_build",
            "asset_card_bulk_refresh",
            "passport_detail_sync",
            "passport_catalog_refresh",
            "scan_postprocess",
            "automation_run",
        },
        "can_retry": status not in ACTIVE_OPERATION_STATUSES and kind in RETRYABLE_OPERATION_KINDS,
    }


def decode_operation_event(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "message": row.get("message"),
        "details": json_loads(row.get("details_json"), {}),
        "created_at": row.get("created_at"),
    }


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
        interrupt_stale_operations()

    def list(self, **filters: Any) -> dict[str, Any]:
        self._sweep_stale()
        return list_operations(**filters, sync_sources=True)

    def summary(self) -> dict[str, Any]:
        self._sweep_stale()
        return get_operations_summary(sync_sources=True)

    def counters(self) -> dict[str, Any]:
        """Read-only counters for metrics scraping: no source sync, no writes."""
        return get_operations_summary(sync_sources=False)

    def get(self, operation_id: str) -> dict[str, Any] | None:
        return get_operation(operation_id, sync_sources=True)

    def saved_views(self, route: str) -> builtins.list[dict[str, Any]]:
        return list_saved_views(route)

    def clear_history(self, *, actor: str | None = None) -> dict[str, int]:
        """Hide finished operation rows while preserving records and active work."""
        sync_operations_from_sources()
        clearable_statuses = sorted(CLEARABLE_OPERATION_STATUSES)
        active_statuses = sorted(ACTIVE_OPERATION_STATUSES)
        with connection.connect() as conn:
            archived_rows = conn.execute(
                """UPDATE operations
                   SET cleared_at = %s, cleared_by = %s
                   WHERE cleared_at IS NULL AND status = ANY(%s)
                   RETURNING operation_id""",
                (codecs.now_utc(), actor, clearable_statuses),
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
