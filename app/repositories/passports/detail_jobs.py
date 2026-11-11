"""Repositories for passport detail refresh jobs: reservation, leasing, batched saves, cancellation, and interruption recovery."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection, schema
from ...persistence.codecs import json_loads
from ..asset_cards.passport_links import reconcile_asset_card_vulnerability_passport_links
from ..operations import register_operation
from .details import _upsert_vulnerability_passport_details
from .serializers import decode_vulnerability_passport_detail_job


def reconcile_vulnerability_passport_detail_job_links() -> int:
    """Rebuild finding links once after a bulk passport detail sync."""
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        return reconcile_asset_card_vulnerability_passport_links(conn, None, current)


def create_vulnerability_passport_detail_job(
    job_id: str,
    *,
    requested_count: int,
    eligible_count: int,
    skipped_fresh_count: int,
    request: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    schema.init_db()
    current = codecs.now_utc()
    status = "queued" if eligible_count else "completed"
    finished_at = None if eligible_count else current
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO vulnerability_passport_detail_jobs (
                job_id, status, requested_count, eligible_count, skipped_fresh_count,
                created_at, finished_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                job_id,
                status,
                requested_count,
                eligible_count,
                skipped_fresh_count,
                current,
                finished_at,
                current,
            ),
        ).fetchone()
        register_operation(
            job_id,
            kind="passport_detail_sync",
            source_id=job_id,
            status=status,
            stage=status,
            progress_percent=100 if not eligible_count else 0,
            subject_type="vulnerability_passports",
            subject_label="Vulnerability passports",
            request=request,
            result={"requested_count": requested_count, "eligible_count": eligible_count, "skipped_fresh_count": skipped_fresh_count},
            idempotency_key=idempotency_key,
            created_at=current,
            finished_at=finished_at,
            updated_at=current,
            _conn=conn,
        )
    assert row is not None
    return decode_vulnerability_passport_detail_job(dict(row))


def get_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerability_passport_detail_jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def get_active_vulnerability_passport_detail_job() -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM vulnerability_passport_detail_jobs
            WHERE status IN ('queued', 'running', 'cancelling')
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def interrupt_active_vulnerability_passport_detail_jobs() -> int:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        result = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = 'interrupted',
                message = 'Application restarted before the detail sync finished.',
                finished_at = %s,
                updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current, current),
        )
    return int(result.rowcount or 0)


def start_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'running' END,
                started_at = COALESCE(started_at, %s),
                updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def request_vulnerability_passport_detail_job_cancel(job_id: str) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET cancel_requested = TRUE,
                status = 'cancelling',
                updated_at = %s
            WHERE job_id = %s AND status IN ('queued', 'running', 'cancelling')
            RETURNING *
            """,
            (current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def save_vulnerability_passport_detail_job_batch(
    job_id: str,
    *,
    details: list[tuple[str, dict[str, Any]]],
    errors: list[dict[str, str]],
) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            "SELECT errors_json FROM vulnerability_passport_detail_jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if not row:
            return None
        # A detail job can contain thousands of passports. Rebuilding every
        # finding-to-passport link for each batch creates extreme WAL churn.
        # The worker performs one reconciliation after all batches are saved.
        loaded_count = _upsert_vulnerability_passport_details(
            conn,
            details,
            current,
            reconcile_links=False,
        )
        saved_errors = json_loads(row.get("errors_json"), [])
        if not isinstance(saved_errors, list):
            saved_errors = []
        saved_errors = [*saved_errors, *errors][:100]
        updated = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET processed_count = processed_count + %s,
                loaded_count = loaded_count + %s,
                failed_count = failed_count + %s,
                errors_json = %s,
                updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                loaded_count + len(errors),
                loaded_count,
                len(errors),
                json.dumps(saved_errors, ensure_ascii=False),
                current,
                job_id,
            ),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(updated)) if updated else None


def finish_vulnerability_passport_detail_job(
    job_id: str,
    *,
    status: str,
    message: str | None = None,
) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = %s,
                message = %s,
                finished_at = %s,
                updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (status, message, current, current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None
