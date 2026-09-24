"""Persist full passport refresh progress in the operation registry."""

from __future__ import annotations

from typing import Any

from .. import db

KIND = "passport_catalog_refresh"
ACTIVE = ("queued", "running", "cancelling")


def create(operation_id: str, request: dict[str, Any]) -> dict[str, Any]:
    return db.register_operation(
        operation_id, kind=KIND, source_id=operation_id,
        status="queued", stage="queued", progress_percent=0,
        subject_type="vulnerability_passports", subject_label="Паспорта уязвимостей",
        message="Обновление поставлено в очередь.", request=request,
    )


def get(operation_id: str) -> dict[str, Any] | None:
    operation = db.get_operation(operation_id, include_events=False)
    return operation if operation and operation["kind"] == KIND else None


def latest() -> dict[str, Any] | None:
    db.init_db()
    with db.connect() as conn:
        row = conn.execute(
            """SELECT * FROM operations WHERE kind = %s
               ORDER BY CASE WHEN status = ANY(%s) THEN 0 ELSE 1 END,
                        created_at DESC, operation_id DESC LIMIT 1""",
            (KIND, list(ACTIVE)),
        ).fetchone()
    return db.decode_operation(dict(row)) if row else None


def update(operation_id: str, *, status: str, stage: str, percent: int,
           message: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    current = get(operation_id)
    if current is None:
        raise ValueError("Passport refresh operation is missing")
    if current["status"] in {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}:
        return current
    return db.register_operation(
        operation_id, kind=KIND, source_id=operation_id,
        status=status, stage=stage, progress_percent=percent, message=message,
        result=result, started_at=db.now_utc() if status == "running" else None,
        finished_at=db.now_utc() if status in {"completed", "completed_with_errors", "failed", "cancelled"} else None,
    )


def interrupt_active() -> int:
    db.init_db()
    current = db.now_utc()
    with db.connect() as conn:
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
