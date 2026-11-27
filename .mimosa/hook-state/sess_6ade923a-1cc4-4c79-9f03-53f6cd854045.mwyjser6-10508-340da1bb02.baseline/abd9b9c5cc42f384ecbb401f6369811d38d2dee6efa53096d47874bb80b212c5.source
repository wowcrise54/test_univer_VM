"""Repository for scan post-processing runs and per-asset items: leasing, progress, cancellation, and decoding."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection
from ...persistence.codecs import json_loads, text_parameter
from ..operations import register_operation

SCAN_POSTPROCESS_ACTIVE_STATUSES = {"monitoring", "resolving", "processing", "waiting", "cancelling"}


SCAN_POSTPROCESS_FAILED_ITEM_STATUSES = {"resolution_failed", "build_failed", "removal_failed"}


def create_scan_postprocess_run(
    run_id: str,
    *,
    mp_task_id: str,
    started_from: str,
    options: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    current = codecs.now_utc()
    refresh_asset_id = options.get("refresh_asset_id")
    refresh_label = options.get("refresh_asset_label")
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO scan_postprocess_runs (
                run_id, mp_task_id, status, stage, options_json, started_from,
                created_at, updated_at
            )
            VALUES (%s, %s, 'monitoring', 'waiting_for_run', %s, %s, %s, %s)
            RETURNING *
            """,
            (run_id, mp_task_id, json.dumps(options, ensure_ascii=False), started_from, current, current),
        ).fetchone()
        assert row is not None
        register_operation(
            run_id,
            kind="scan_postprocess",
            source_id=run_id,
            status="monitoring",
            stage="waiting_for_run",
            subject_type="asset_card" if refresh_asset_id else "scanner_task",
            subject_id=refresh_asset_id or mp_task_id,
            subject_label=refresh_label or refresh_asset_id or mp_task_id,
            request=options,
            idempotency_key=idempotency_key,
            created_at=current,
            updated_at=current,
            _conn=conn,
        )
    return decode_scan_postprocess_run(dict(row))


def get_scan_postprocess_run(run_id: str, *, include_items: bool = False) -> dict[str, Any] | None:
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM scan_postprocess_runs WHERE run_id = %s", (run_id,)).fetchone()
        items = (
            conn.execute(
                "SELECT * FROM scan_postprocess_items WHERE postprocess_run_id = %s ORDER BY id",
                (run_id,),
            ).fetchall()
            if row and include_items
            else []
        )
    if not row:
        return None
    result = decode_scan_postprocess_run(dict(row))
    if include_items:
        result["items"] = [decode_scan_postprocess_item(dict(item)) for item in items]
    return result


def get_latest_scan_postprocess_run(mp_task_id: str, *, include_items: bool = False) -> dict[str, Any] | None:
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE mp_task_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (mp_task_id,),
        ).fetchone()
    if not row:
        return None
    return get_scan_postprocess_run(str(row["run_id"]), include_items=include_items)


def list_resumable_scan_postprocess_runs() -> list[dict[str, Any]]:
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
              AND worker_id IS NULL
            ORDER BY created_at
            """
        ).fetchall()
    return [decode_scan_postprocess_run(dict(row)) for row in rows]


def claim_scan_postprocess_run(run_id: str, worker_id: str) -> dict[str, Any] | None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = %s, started_at = COALESCE(started_at, %s), updated_at = %s
            WHERE run_id = %s
              AND worker_id IS NULL
              AND status IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
            RETURNING *
            """,
            (worker_id, current, current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def release_scan_postprocess_leases() -> None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = NULL, updated_at = %s
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
            """,
            (current,),
        )
        conn.execute(
            """
            UPDATE scan_postprocess_items
            SET status = 'queued', stage = 'queued', updated_at = %s
            WHERE status IN ('building', 'card_saved')
            """,
            (current,),
        )


def update_scan_postprocess_run(run_id: str, **values: Any) -> dict[str, Any] | None:
    allowed = {
        "mp_run_id",
        "status",
        "stage",
        "run_started_at",
        "total_job_count",
        "successful_job_count",
        "target_count",
        "asset_count",
        "completed_count",
        "failed_count",
        "message",
        "error",
        "worker_id",
    }
    updates = [(key, value) for key, value in values.items() if key in allowed]
    if not updates:
        return get_scan_postprocess_run(run_id)
    current = codecs.now_utc()
    assignments = ", ".join(f"{key} = %s" for key, _ in updates)
    params = [value for _, value in updates]
    params.extend([current, run_id])
    with connection.connect() as conn:
        row = conn.execute(
            f"UPDATE scan_postprocess_runs SET {assignments}, updated_at = %s WHERE run_id = %s RETURNING *",
            params,
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def finish_scan_postprocess_run(
    run_id: str,
    *,
    status: str,
    stage: str,
    message: str | None = None,
    error: str | None = None,
) -> dict[str, Any] | None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET status = %s, stage = %s, message = %s, error = %s,
                worker_id = NULL, finished_at = %s, updated_at = %s
            WHERE run_id = %s
            RETURNING *
            """,
            (status, stage, message, error, current, current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def update_scan_postprocess_docker_group(run_id: str, **values: Any) -> dict[str, Any] | None:
    """Atomically merge durable lifecycle fields into ``options.docker_dynamic_group``."""
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            "SELECT options_json FROM scan_postprocess_runs WHERE run_id = %s FOR UPDATE",
            (run_id,),
        ).fetchone()
        if not row:
            return None
        options = json_loads(row.get("options_json"), {})
        if not isinstance(options, dict):
            options = {}
        group = options.get("docker_dynamic_group")
        if not isinstance(group, dict):
            group = {}
        group.update(values)
        options["docker_dynamic_group"] = group
        updated = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET options_json = %s, updated_at = %s
            WHERE run_id = %s
            RETURNING *
            """,
            (json.dumps(options, ensure_ascii=False), current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(updated)) if updated else None


def request_scan_postprocess_cancel(run_id: str) -> dict[str, Any] | None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET cancel_requested = TRUE,
                status = 'cancelling',
                stage = 'cancelling',
                message = 'Cancellation requested.',
                updated_at = %s
            WHERE run_id = %s
              AND status IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
            RETURNING *
            """,
            (current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def upsert_scan_postprocess_item(
    postprocess_run_id: str,
    *,
    item_key: str,
    mp_job_id: str | None,
    target: str | None,
    asset_id: str | None,
    display_name: str | None,
    status: str,
    stage: str,
) -> dict[str, Any]:
    current = codecs.now_utc()
    # PDQL fields are not guaranteed to be scalars (for example HostName may
    # be an object with displayName/objectId).  Keep the persistence boundary
    # defensive so one unexpected response shape cannot stall the whole scan
    # post-processing queue with psycopg's "cannot adapt type 'dict'" error.
    mp_job_id = text_parameter(mp_job_id)
    target = text_parameter(target)
    asset_id = text_parameter(asset_id)
    display_name = text_parameter(display_name)
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO scan_postprocess_items (
                postprocess_run_id, item_key, mp_job_id, target, asset_id,
                display_name, status, stage, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(postprocess_run_id, item_key) DO UPDATE SET
                mp_job_id = COALESCE(EXCLUDED.mp_job_id, scan_postprocess_items.mp_job_id),
                target = COALESCE(EXCLUDED.target, scan_postprocess_items.target),
                asset_id = COALESCE(EXCLUDED.asset_id, scan_postprocess_items.asset_id),
                display_name = COALESCE(EXCLUDED.display_name, scan_postprocess_items.display_name),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (
                postprocess_run_id,
                item_key,
                mp_job_id,
                target,
                asset_id,
                display_name,
                status,
                stage,
                current,
                current,
            ),
        ).fetchone()
    assert row is not None
    return decode_scan_postprocess_item(dict(row))


def update_scan_postprocess_item(item_id: int, **values: Any) -> dict[str, Any] | None:
    allowed = {
        "status",
        "stage",
        "build_job_id",
        "removal_operation_id",
        "message",
        "error",
        "started_at",
        "finished_at",
    }
    updates = [(key, value) for key, value in values.items() if key in allowed]
    if not updates:
        return None
    current = codecs.now_utc()
    assignments = ", ".join(f"{key} = %s" for key, _ in updates)
    params = [value for _, value in updates]
    params.extend([current, item_id])
    with connection.connect() as conn:
        row = conn.execute(
            f"UPDATE scan_postprocess_items SET {assignments}, updated_at = %s WHERE id = %s RETURNING *",
            params,
        ).fetchone()
    assert row is not None
    return decode_scan_postprocess_item(dict(row)) if row else None


def list_scan_postprocess_items(run_id: str) -> list[dict[str, Any]]:
    with connection.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_postprocess_items WHERE postprocess_run_id = %s ORDER BY id",
            (run_id,),
        ).fetchall()
    return [decode_scan_postprocess_item(dict(row)) for row in rows]


def refresh_scan_postprocess_counts(run_id: str) -> dict[str, Any] | None:
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE asset_id IS NOT NULL) AS asset_count,
                COUNT(*) FILTER (WHERE status = 'completed') AS completed_count,
                COUNT(*) FILTER (WHERE status IN ('resolution_failed', 'build_failed', 'removal_failed')) AS failed_count
            FROM scan_postprocess_items
            WHERE postprocess_run_id = %s
            """,
            (run_id,),
        ).fetchone()
    assert row is not None
    return update_scan_postprocess_run(
        run_id,
        asset_count=int(row["asset_count"] or 0),
        completed_count=int(row["completed_count"] or 0),
        failed_count=int(row["failed_count"] or 0),
    )


def decode_scan_postprocess_run(row: dict[str, Any]) -> dict[str, Any]:
    options = json_loads(row.get("options_json"), {})
    return {
        "run_id": row.get("run_id"),
        "mp_task_id": row.get("mp_task_id"),
        "mp_run_id": row.get("mp_run_id"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "options": options if isinstance(options, dict) else {},
        "started_from": row.get("started_from"),
        "run_started_at": row.get("run_started_at"),
        "total_job_count": int(row.get("total_job_count") or 0),
        "successful_job_count": int(row.get("successful_job_count") or 0),
        "target_count": int(row.get("target_count") or 0),
        "asset_count": int(row.get("asset_count") or 0),
        "completed_count": int(row.get("completed_count") or 0),
        "failed_count": int(row.get("failed_count") or 0),
        "message": row.get("message"),
        "error": row.get("error"),
        "cancel_requested": bool(row.get("cancel_requested")),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


def decode_scan_postprocess_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row.get("id") or 0),
        "postprocess_run_id": row.get("postprocess_run_id"),
        "item_key": row.get("item_key"),
        "mp_job_id": row.get("mp_job_id"),
        "target": row.get("target"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "build_job_id": row.get("build_job_id"),
        "removal_operation_id": row.get("removal_operation_id"),
        "message": row.get("message"),
        "error": row.get("error"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


def rebind_scan_postprocess_asset(build_job_id: str, canonical_asset_id: str) -> None:
    with connection.connect() as conn:
        conn.execute(
            "UPDATE scan_postprocess_items SET asset_id = %s, updated_at = %s WHERE build_job_id = %s",
            (canonical_asset_id, codecs.now_utc(), build_job_id),
        )
        conn.execute(
            "UPDATE asset_card_build_jobs SET asset_id = %s, updated_at = %s WHERE job_id = %s",
            (canonical_asset_id, codecs.now_utc(), build_job_id),
        )



def list_pending_asset_refresh_task_cleanups() -> list[dict[str, Any]]:
    """Terminal refresh runs keep their local task row until remote task deletion succeeds."""
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT ON (run.mp_task_id) run.*
            FROM scan_postprocess_runs run
            JOIN scan_tasks task ON task.mp_task_id = run.mp_task_id
            WHERE run.status NOT IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
              AND run.options_json::jsonb ->> 'auto_created_refresh_task' = 'true'
            ORDER BY run.mp_task_id, run.updated_at DESC
            """
        ).fetchall()
    return [decode_scan_postprocess_run(dict(row)) for row in rows]


def list_pending_docker_group_cleanups() -> list[dict[str, Any]]:
    """Return terminal scan runs whose managed Docker group still needs removal."""
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE status NOT IN ('monitoring', 'resolving', 'processing', 'waiting', 'cancelling')
              AND NULLIF(options_json::jsonb #>> '{docker_dynamic_group,name}', '') IS NOT NULL
              AND NULLIF(options_json::jsonb #>> '{docker_dynamic_group,cleanup_after}', '') IS NOT NULL
              AND NULLIF(options_json::jsonb #>> '{docker_dynamic_group,removed_at}', '') IS NULL
            ORDER BY options_json::jsonb #>> '{docker_dynamic_group,cleanup_after}', created_at
            """
        ).fetchall()
    return [decode_scan_postprocess_run(dict(row)) for row in rows]
