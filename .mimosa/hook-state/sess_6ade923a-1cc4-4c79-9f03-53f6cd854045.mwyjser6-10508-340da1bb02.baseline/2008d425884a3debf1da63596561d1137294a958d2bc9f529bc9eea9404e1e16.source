"""Persist full passport refresh progress in the operation registry."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import psycopg

from ..persistence import codecs, connection, schema
from .operations import decode_operation, get_operation, register_operation

KIND = "passport_catalog_refresh"
ACTIVE = ("queued", "running", "cancelling")


def create(operation_id: str, request: dict[str, Any]) -> dict[str, Any]:
    return register_operation(
        operation_id, kind=KIND, source_id=operation_id,
        status="queued", stage="queued", progress_percent=0,
        subject_type="vulnerability_passports", subject_label="Паспорта уязвимостей",
        message="Обновление поставлено в очередь.", request=request,
    )


def get(operation_id: str) -> dict[str, Any] | None:
    operation = get_operation(operation_id, include_events=False)
    return operation if operation and operation["kind"] == KIND else None


def latest() -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """SELECT * FROM operations WHERE kind = %s
               ORDER BY CASE WHEN status = ANY(%s) THEN 0 ELSE 1 END,
                        created_at DESC, operation_id DESC LIMIT 1""",
            (KIND, list(ACTIVE)),
        ).fetchone()
    return decode_operation(dict(row)) if row else None


def reserve_periodic(
    request: dict[str, Any], *, now: datetime, interval_seconds: int,
) -> dict[str, Any] | None:
    """Reserve one due periodic refresh in a short transaction."""
    schema.init_db()
    try:
        with connection.connect() as conn:
            lock = conn.execute(
                "SELECT pg_try_advisory_xact_lock(hashtext(%s)) AS acquired",
                ("mpvm.passport-periodic-reservation",),
            ).fetchone()
            if not lock or not lock["acquired"]:
                return None
            if conn.execute(
                "SELECT 1 FROM operations WHERE kind = %s AND status = ANY(%s) LIMIT 1",
                (KIND, list(ACTIVE)),
            ).fetchone():
                return None
            if conn.execute(
                "SELECT 1 FROM vulnerability_passport_detail_jobs WHERE status = ANY(%s) LIMIT 1",
                (list(ACTIVE),),
            ).fetchone():
                return None
            previous = conn.execute(
                "SELECT status, finished_at, created_at FROM operations "
                "WHERE kind = %s AND request_json::jsonb ->> 'trigger' = %s "
                "ORDER BY created_at DESC, operation_id DESC LIMIT 1",
                (KIND, "periodic"),
            ).fetchone()
            if previous and previous["status"] != "interrupted":
                anchor = datetime.fromisoformat(str(previous["finished_at"] or previous["created_at"]))
                if now < anchor + timedelta(seconds=interval_seconds):
                    return None
            operation_id = str(uuid4())
            stamp = now.isoformat(timespec="seconds")
            return register_operation(
                operation_id, kind=KIND, source_id=operation_id,
                status="queued", stage="queued", progress_percent=0,
                subject_type="vulnerability_passports",
                subject_label="Паспорта уязвимостей",
                message="Плановая проверка паспортов поставлена в очередь.",
                request={**request, "trigger": "periodic"},
                created_at=stamp, updated_at=stamp, _conn=conn,
            )
    except psycopg.errors.UniqueViolation:
        return None


def update(operation_id: str, *, status: str, stage: str, percent: int,
           message: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    current = get(operation_id)
    if current is None:
        raise ValueError("Passport refresh operation is missing")
    if current["status"] in {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}:
        return current
    return register_operation(
        operation_id, kind=KIND, source_id=operation_id,
        status=status, stage=stage, progress_percent=percent, message=message,
        result=result, started_at=codecs.now_utc() if status == "running" else None,
        finished_at=codecs.now_utc() if status in {"completed", "completed_with_errors", "failed", "cancelled"} else None,
    )


def interrupt_active() -> int:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        rows = conn.execute(
            """UPDATE operations SET status = 'interrupted', stage = 'interrupted',
               message = 'Обновление прервано перезапуском приложения.',
               finished_at = %s, updated_at = %s
               WHERE kind = %s AND status = ANY(%s) RETURNING operation_id""",
            (current, current, KIND, list(ACTIVE)),
        ).fetchall()
    return len(rows)


def request_cancel(operation_id: str) -> dict[str, Any] | None:
    current = get(operation_id)
    if current is None or current["status"] not in ACTIVE:
        return current
    return update(operation_id, status="cancelling", stage="cancelling",
                  percent=current["progress_percent"], message="Остановка запрошена.")
