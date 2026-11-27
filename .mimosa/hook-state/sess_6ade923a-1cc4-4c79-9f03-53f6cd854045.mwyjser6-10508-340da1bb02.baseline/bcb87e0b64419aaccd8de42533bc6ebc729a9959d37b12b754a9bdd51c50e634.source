"""Repository for asset card build jobs: creation under the build admission lock, leasing, cancellation, and decoding."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection, schema
from ...persistence.codecs import json_loads
from ...persistence.locks import _ASSET_CARD_BUILD_ADMISSION_LOCK, _AssetCardBuildAdmissionConflict
from ..operations import register_operation
from ..scan_tasks.postprocess import decode_scan_postprocess_run
from ..scan_tasks.tasks import _decode_scan_task

# Keep this equal to the worker semaphore limit in app/main.py.
ASSET_CARD_BUILD_JOB_LIMIT = 4


def get_asset_card_refresh_template(asset_id: str, template_task_id: str | None = None) -> dict[str, Any] | None:
    """Return an explicit task, the task that produced the card, or the latest usable local task."""
    with connection.connect() as conn:
        if template_task_id:
            row = conn.execute(
                "SELECT * FROM scan_tasks WHERE mp_task_id = %s AND deleted_at IS NULL",
                (template_task_id,),
            ).fetchone()
            return _decode_scan_task(dict(row)) if row else None

        row = conn.execute(
            """
            SELECT task.*
            FROM scan_postprocess_items item
            JOIN scan_postprocess_runs run ON run.run_id = item.postprocess_run_id
            JOIN scan_tasks task ON task.mp_task_id = run.mp_task_id
            WHERE item.asset_id = %s
              AND task.deleted_at IS NULL
            ORDER BY item.updated_at DESC, task.updated_at DESC
            LIMIT 1
            """,
            (asset_id,),
        ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT * FROM scan_tasks
                WHERE deleted_at IS NULL
                ORDER BY updated_at DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
    return _decode_scan_task(dict(row)) if row else None


def get_active_asset_card_refresh(asset_id: str) -> dict[str, Any] | None:
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
              AND options_json::jsonb ->> 'refresh_asset_id' = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id,),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def create_asset_card_build_job(
    job_id: str,
    *,
    trace_id: str | None,
    asset_id: str,
    operation: str,
    request: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any] | None:
    jobs = create_asset_card_build_jobs(
        [
            {
                "job_id": job_id,
                "trace_id": trace_id,
                "asset_id": asset_id,
                "operation": operation,
                "request": request,
                "idempotency_key": idempotency_key,
            }
        ]
    )
    return jobs[0] if jobs else None


def create_asset_card_build_jobs(
    jobs: list[dict[str, Any]],
    *,
    batch_operation: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | None:
    """Atomically admit and register up to ASSET_CARD_BUILD_JOB_LIMIT independent asset-card jobs."""
    if not 1 <= len(jobs) <= ASSET_CARD_BUILD_JOB_LIMIT:
        raise ValueError(f"jobs must contain between 1 and {ASSET_CARD_BUILD_JOB_LIMIT} items")

    normalized: list[dict[str, Any]] = []
    for item in jobs:
        job_id = str(item.get("job_id") or "").strip()
        asset_id = str(item.get("asset_id") or "").strip()
        operation = str(item.get("operation") or "").strip()
        request = item.get("request")
        if not job_id or not asset_id or not operation or not isinstance(request, dict):
            raise ValueError("each job requires non-empty job_id, asset_id, operation and a request object")
        normalized.append(
            {
                "job_id": job_id,
                "trace_id": item.get("trace_id"),
                "asset_id": asset_id,
                "operation": operation,
                "request": request,
                "idempotency_key": item.get("idempotency_key"),
            }
        )

    job_ids = [item["job_id"] for item in normalized]
    asset_ids = [item["asset_id"] for item in normalized]
    if len(set(job_ids)) != len(job_ids):
        raise ValueError("job_id values must be unique within the batch")
    if len(set(asset_ids)) != len(asset_ids):
        raise ValueError("asset_id values must be unique within the batch")

    schema.init_db()
    current = codecs.now_utc()
    admitted: list[dict[str, Any]] = []
    try:
        with connection.connect() as conn:
            conn.execute(
                "SELECT pg_advisory_xact_lock(%s, %s)",
                _ASSET_CARD_BUILD_ADMISSION_LOCK,
            )
            capacity = conn.execute(
                """
                SELECT
                    COUNT(*) AS active_count,
                    COUNT(*) FILTER (WHERE asset_id = ANY(%s::text[])) AS duplicate_asset_count
                FROM asset_card_build_jobs
                WHERE status IN ('queued', 'running', 'cancelling')
                """,
                (asset_ids,),
            ).fetchone()
            active_count = int((capacity or {}).get("active_count") or 0)
            duplicate_asset_count = int((capacity or {}).get("duplicate_asset_count") or 0)
            if duplicate_asset_count or active_count + len(normalized) > ASSET_CARD_BUILD_JOB_LIMIT:
                return None

            for item in normalized:
                row = conn.execute(
                    """
                    INSERT INTO asset_card_build_jobs (
                        job_id, trace_id, asset_id, operation, status, stage,
                        request_json, created_at, updated_at
                    )
                    VALUES (%s, %s, %s, %s, 'queued', 'queued', %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING *
                    """,
                    (
                        item["job_id"],
                        item["trace_id"],
                        item["asset_id"],
                        item["operation"],
                        json.dumps(item["request"], ensure_ascii=False),
                        current,
                        current,
                    ),
                ).fetchone()
                if not row:
                    raise _AssetCardBuildAdmissionConflict
                admitted.append(dict(row))
                register_operation(
                    item["job_id"],
                    kind="asset_card_build",
                    source_id=item["job_id"],
                    status="queued",
                    stage="queued",
                    subject_type="asset",
                    subject_id=item["asset_id"],
                    subject_label=item["asset_id"],
                    request=item["request"],
                    trace_id=item["trace_id"],
                    idempotency_key=item["idempotency_key"],
                    created_at=current,
                    updated_at=current,
                    _conn=conn,
                )
            if batch_operation:
                register_operation(
                    str(batch_operation["operation_id"]),
                    kind="asset_card_build_batch",
                    source_id=str(batch_operation["source_id"]),
                    status="completed",
                    stage="scheduled",
                    progress_percent=100,
                    subject_type="assets",
                    subject_label="Asset card batch build",
                    request=batch_operation.get("request"),
                    result={"job_ids": job_ids},
                    trace_id=batch_operation.get("trace_id"),
                    idempotency_key=batch_operation.get("idempotency_key"),
                    finished_at=current,
                    created_at=current,
                    updated_at=current,
                    _conn=conn,
                )
    except _AssetCardBuildAdmissionConflict:
        return None
    return [decode_asset_card_build_job(row) for row in admitted]


def get_asset_card_build_job(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM asset_card_build_jobs WHERE job_id = %s", (job_id,)).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def get_active_asset_card_build_job() -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM asset_card_build_jobs
            WHERE status IN ('queued', 'running', 'cancelling')
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def count_active_asset_card_build_jobs() -> int:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS active_count FROM asset_card_build_jobs
            WHERE status IN ('queued', 'running', 'cancelling')
            """
        ).fetchone()
    return int((row or {}).get("active_count") or 0)


def interrupt_active_asset_card_build_jobs() -> int:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        result = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = 'interrupted', stage = 'interrupted',
                message = 'Application restarted before the asset card build finished.',
                finished_at = %s, updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current, current),
        )
    return int(result.rowcount or 0)


def start_asset_card_build_job(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'running' END,
                stage = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'starting' END,
                progress_percent = GREATEST(progress_percent, 5),
                started_at = COALESCE(started_at, %s), updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, current, job_id),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def update_asset_card_build_job(
    job_id: str,
    *,
    stage: str,
    progress_percent: int,
    discovered_requests: int,
    completed_requests: int,
    node_count: int = 0,
    collection_count: int = 0,
    finding_count: int = 0,
    warning_count: int = 0,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET stage = %s,
                progress_percent = GREATEST(progress_percent, LEAST(100, GREATEST(0, %s))),
                discovered_requests = %s, completed_requests = %s,
                node_count = %s, collection_count = %s, finding_count = %s,
                warning_count = %s, stats_json = %s, updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                stage,
                progress_percent,
                discovered_requests,
                completed_requests,
                node_count,
                collection_count,
                finding_count,
                warning_count,
                json.dumps(stats or {}, ensure_ascii=False),
                current,
                job_id,
            ),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def request_asset_card_build_job_cancel(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET cancel_requested = TRUE, status = 'cancelling', stage = 'cancelling', updated_at = %s
            WHERE job_id = %s AND status IN ('queued', 'running', 'cancelling')
            RETURNING *
            """,
            (current, job_id),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def finish_asset_card_build_job(
    job_id: str,
    *,
    status: str,
    stage: str,
    message: str | None,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = %s, stage = %s, message = %s,
                progress_percent = CASE WHEN %s = 'completed' THEN 100 ELSE progress_percent END,
                stats_json = CASE WHEN %s::text IS NULL THEN stats_json ELSE %s END,
                finished_at = %s, updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                status,
                stage,
                message,
                status,
                None if stats is None else "present",
                json.dumps(stats or {}, ensure_ascii=False),
                current,
                current,
                job_id,
            ),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def decode_asset_card_build_job(row: dict[str, Any]) -> dict[str, Any]:
    request = json_loads(row.get("request_json"), {})
    stats = json_loads(row.get("stats_json"), {})
    return {
        "job_id": row.get("job_id"),
        "trace_id": row.get("trace_id"),
        "asset_id": row.get("asset_id"),
        "operation": row.get("operation"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "progress_percent": max(0, min(100, int(row.get("progress_percent") or 0))),
        "request": request if isinstance(request, dict) else {},
        "stats": stats if isinstance(stats, dict) else {},
        "discovered_requests": int(row.get("discovered_requests") or 0),
        "completed_requests": int(row.get("completed_requests") or 0),
        "node_count": int(row.get("node_count") or 0),
        "collection_count": int(row.get("collection_count") or 0),
        "finding_count": int(row.get("finding_count") or 0),
        "warning_count": int(row.get("warning_count") or 0),
        "cancel_requested": bool(row.get("cancel_requested")),
        "message": row.get("message"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }
