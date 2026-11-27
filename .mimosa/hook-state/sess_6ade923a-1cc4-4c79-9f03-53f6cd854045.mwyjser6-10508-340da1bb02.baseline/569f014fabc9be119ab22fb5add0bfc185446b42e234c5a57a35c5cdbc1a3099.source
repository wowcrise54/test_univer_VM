from __future__ import annotations

import json
import uuid
from typing import Any

from .. import db

ACTIVE_RUN_STATUSES = {"queued", "running", "cancelling"}


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _load(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, dict | list):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _rows(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


class AutomationRepository:
    def list_runbooks(self) -> list[dict[str, Any]]:
        db.init_db()
        with db.connect() as conn:
            rows = conn.execute("SELECT * FROM automation_runbooks ORDER BY name").fetchall()
        return [self._decode_runbook(row) for row in _rows(rows)]

    def get_runbook(self, runbook_id: str) -> dict[str, Any] | None:
        db.init_db()
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM automation_runbooks WHERE runbook_id = %s", (runbook_id,)).fetchone()
        return self._decode_runbook(dict(row)) if row else None

    def create_runbook(self, *, name: str, description: str, definition: dict[str, Any]) -> dict[str, Any]:
        now = db.now_utc()
        runbook_id = str(uuid.uuid4())
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO automation_runbooks
                   (runbook_id, name, description, draft_json, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING *""",
                (runbook_id, name, description, _dump(definition), now, now),
            ).fetchone()
        assert row is not None
        return self._decode_runbook(dict(row))

    def update_runbook(
        self, runbook_id: str, *, name: str, description: str, definition: dict[str, Any]
    ) -> dict[str, Any] | None:
        now = db.now_utc()
        with db.connect() as conn:
            row = conn.execute(
                """UPDATE automation_runbooks
                   SET name = %s, description = %s, draft_json = %s,
                       allow_destructive = FALSE, approved_hash = NULL, approved_at = NULL, updated_at = %s
                   WHERE runbook_id = %s RETURNING *""",
                (name, description, _dump(definition), now, runbook_id),
            ).fetchone()
        return self._decode_runbook(dict(row)) if row else None

    def delete_runbook(self, runbook_id: str) -> bool:
        with db.connect() as conn:
            row = conn.execute(
                "DELETE FROM automation_runbooks WHERE runbook_id = %s RETURNING runbook_id", (runbook_id,)
            ).fetchone()
        return row is not None

    def publish_runbook(
        self, runbook_id: str, *, definition: dict[str, Any], definition_hash: str, destructive_approved: bool
    ) -> dict[str, Any] | None:
        now = db.now_utc()
        with db.connect() as conn:
            current = conn.execute(
                "SELECT * FROM automation_runbooks WHERE runbook_id = %s FOR UPDATE", (runbook_id,)
            ).fetchone()
            if not current:
                return None
            version = int(current.get("published_version") or 0) + 1
            conn.execute(
                """INSERT INTO automation_runbook_versions
                   (runbook_id, version, definition_json, definition_hash, destructive_approved, published_at)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (runbook_id, version, _dump(definition), definition_hash, destructive_approved, now),
            )
            row = conn.execute(
                """UPDATE automation_runbooks SET published_version = %s, allow_destructive = %s,
                   approved_hash = %s, approved_at = %s, updated_at = %s
                   WHERE runbook_id = %s RETURNING *""",
                (
                    version,
                    destructive_approved,
                    definition_hash if destructive_approved else None,
                    now if destructive_approved else None,
                    now,
                    runbook_id,
                ),
            ).fetchone()
        assert row is not None
        return self._decode_runbook(dict(row))

    def get_version(self, runbook_id: str, version: int | None = None) -> dict[str, Any] | None:
        with db.connect() as conn:
            if version is None:
                row = conn.execute(
                    "SELECT * FROM automation_runbook_versions WHERE runbook_id = %s ORDER BY version DESC LIMIT 1",
                    (runbook_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM automation_runbook_versions WHERE runbook_id = %s AND version = %s",
                    (runbook_id, version),
                ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["definition"] = _load(result.pop("definition_json"), {})
        return result

    def list_schedules(self) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                """SELECT s.*, r.name AS runbook_name FROM automation_schedules s
                   JOIN automation_runbooks r ON r.runbook_id = s.runbook_id ORDER BY s.name"""
            ).fetchall()
        return _rows(rows)

    def create_schedule(
        self, *, runbook_id: str, name: str, cron_expression: str, timezone: str, enabled: bool, next_run_at: str
    ) -> dict[str, Any]:
        schedule_id = str(uuid.uuid4())
        now = db.now_utc()
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO automation_schedules
                   (schedule_id, runbook_id, name, cron_expression, timezone, enabled, next_run_at, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
                (schedule_id, runbook_id, name, cron_expression, timezone, enabled, next_run_at, now, now),
            ).fetchone()
        assert row is not None
        return dict(row)

    def update_schedule(
        self, schedule_id: str, *, name: str, cron_expression: str, timezone: str, enabled: bool, next_run_at: str
    ) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(
                """UPDATE automation_schedules SET name=%s, cron_expression=%s, timezone=%s,
                   enabled=%s, next_run_at=%s, updated_at=%s WHERE schedule_id=%s RETURNING *""",
                (name, cron_expression, timezone, enabled, next_run_at, db.now_utc(), schedule_id),
            ).fetchone()
        return dict(row) if row else None

    def delete_schedule(self, schedule_id: str) -> bool:
        with db.connect() as conn:
            row = conn.execute(
                "DELETE FROM automation_schedules WHERE schedule_id=%s RETURNING schedule_id", (schedule_id,)
            ).fetchone()
        return row is not None

    def due_schedules(self, now: str) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM automation_schedules WHERE enabled=TRUE AND next_run_at <= %s ORDER BY next_run_at LIMIT 20",
                (now,),
            ).fetchall()
        return _rows(rows)

    def advance_schedule(self, schedule_id: str, *, scheduled_at: str, next_run_at: str, status: str) -> None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE automation_schedules SET last_scheduled_at=%s, last_status=%s,
                   next_run_at=%s, updated_at=%s WHERE schedule_id=%s""",
                (scheduled_at, status, next_run_at, db.now_utc(), schedule_id),
            )

    def has_active_run(self, runbook_id: str) -> bool:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM automation_runs WHERE runbook_id=%s AND status = ANY(%s) LIMIT 1",
                (runbook_id, list(ACTIVE_RUN_STATUSES)),
            ).fetchone()
        return row is not None

    def create_run(
        self,
        *,
        runbook_id: str,
        version: int,
        definition: dict[str, Any],
        trigger_type: str,
        dry_run: bool,
        schedule_id: str | None = None,
        scheduled_for: str | None = None,
        idempotency_key: str | None = None,
        status: str = "queued",
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        now = db.now_utc()
        steps = definition.get("steps") or []
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO automation_runs
                   (run_id, runbook_id, version, schedule_id, trigger_type, scheduled_for, status, dry_run,
                    definition_json, idempotency_key, created_at, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (
                    run_id,
                    runbook_id,
                    version,
                    schedule_id,
                    trigger_type,
                    scheduled_for,
                    status,
                    dry_run,
                    _dump(definition),
                    idempotency_key,
                    now,
                    now,
                ),
            ).fetchone()
            for index, step in enumerate(steps):
                conn.execute(
                    """INSERT INTO automation_run_steps
                       (run_id, step_index, step_id, step_type, status, input_json, updated_at)
                       VALUES (%s,%s,%s,%s,'pending',%s,%s)""",
                    (run_id, index, step.get("step_id") or f"step-{index + 1}", step.get("type"), _dump(step), now),
                )
        assert row is not None
        return self._decode_run(dict(row))

    def get_run_by_idempotency_key(self, key: str | None) -> dict[str, Any] | None:
        if not key:
            return None
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM automation_runs WHERE idempotency_key=%s", (key,)).fetchone()
        return self._decode_run(dict(row)) if row else None

    def list_runs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                """SELECT a.*, r.name AS runbook_name FROM automation_runs a
                   JOIN automation_runbooks r ON r.runbook_id=a.runbook_id ORDER BY a.created_at DESC LIMIT %s""",
                (limit,),
            ).fetchall()
        return [self._decode_run(row) for row in _rows(rows)]

    def get_run(self, run_id: str, *, include_steps: bool = True) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM automation_runs WHERE run_id=%s", (run_id,)).fetchone()
            steps = (
                conn.execute(
                    "SELECT * FROM automation_run_steps WHERE run_id=%s ORDER BY step_index", (run_id,)
                ).fetchall()
                if row and include_steps
                else []
            )
        if not row:
            return None
        result = self._decode_run(dict(row))
        result["steps"] = [self._decode_step(item) for item in _rows(steps)]
        return result

    def resumable_runs(self) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT run_id FROM automation_runs WHERE status = ANY(%s) ORDER BY created_at",
                (["queued", "running", "cancelling"],),
            ).fetchall()
        result = []
        for row in rows:
            run = self.get_run(str(row["run_id"]))
            if run:
                result.append(run)
        return result

    def set_run_status(
        self,
        run_id: str,
        status: str,
        *,
        current_step: int | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        now = db.now_utc()
        terminal = status in {
            "completed",
            "completed_with_warnings",
            "failed",
            "cancelled",
            "skipped",
            "needs_attention",
        }
        with db.connect() as conn:
            conn.execute(
                """UPDATE automation_runs SET status=%s, current_step=COALESCE(%s,current_step),
                   result_json=COALESCE(%s,result_json), error=%s,
                   started_at=CASE WHEN %s='running' THEN COALESCE(started_at,%s) ELSE started_at END,
                   finished_at=CASE WHEN %s THEN %s ELSE finished_at END, updated_at=%s WHERE run_id=%s""",
                (
                    status,
                    current_step,
                    _dump(result) if result is not None else None,
                    error,
                    status,
                    now,
                    terminal,
                    now,
                    now,
                    run_id,
                ),
            )

    def request_cancel(self, run_id: str) -> bool:
        with db.connect() as conn:
            row = conn.execute(
                """UPDATE automation_runs SET cancel_requested=TRUE, status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'cancelling' END,
                   updated_at=%s WHERE run_id=%s AND status = ANY(%s) RETURNING run_id""",
                (db.now_utc(), run_id, list(ACTIVE_RUN_STATUSES)),
            ).fetchone()
        return row is not None

    def set_step_status(
        self,
        run_id: str,
        index: int,
        status: str,
        *,
        attempts: int | None = None,
        output: dict[str, Any] | None = None,
        error: str | None = None,
        child_operation_id: str | None = None,
    ) -> None:
        now = db.now_utc()
        terminal = status in {"completed", "failed", "skipped", "warning", "cancelled"}
        with db.connect() as conn:
            conn.execute(
                """UPDATE automation_run_steps SET status=%s, attempts=COALESCE(%s,attempts),
                   output_json=COALESCE(%s,output_json), error=%s,
                   child_operation_id=COALESCE(%s,child_operation_id),
                   started_at=CASE WHEN %s='running' THEN COALESCE(started_at,%s) ELSE started_at END,
                   finished_at=CASE WHEN %s THEN %s ELSE finished_at END, updated_at=%s
                   WHERE run_id=%s AND step_index=%s""",
                (
                    status,
                    attempts,
                    _dump(output) if output is not None else None,
                    error,
                    child_operation_id,
                    status,
                    now,
                    terminal,
                    now,
                    now,
                    run_id,
                    index,
                ),
            )

    def audit(
        self,
        event_type: str,
        *,
        runbook_id: str | None = None,
        run_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO automation_audit_events VALUES (%s,%s,%s,%s,%s,%s)",
                (str(uuid.uuid4()), runbook_id, run_id, event_type, _dump(details or {}), db.now_utc()),
            )

    def create_notification(
        self,
        *,
        level: str,
        title: str,
        message: str,
        event_type: str,
        runbook_id: str | None = None,
        run_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        notification_id = str(uuid.uuid4())
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO notifications
                   (notification_id,level,title,message,event_type,runbook_id,run_id,details_json,created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (
                    notification_id,
                    level,
                    title,
                    message,
                    event_type,
                    runbook_id,
                    run_id,
                    _dump(details or {}),
                    db.now_utc(),
                ),
            ).fetchone()
        assert row is not None
        return self._decode_notification(dict(row))

    def list_notifications(self, *, unread_only: bool = False, limit: int = 100) -> dict[str, Any]:
        where = "WHERE is_read=FALSE" if unread_only else ""
        with db.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT %s", (limit,)
            ).fetchall()
            unread = conn.execute("SELECT COUNT(*) AS count FROM notifications WHERE is_read=FALSE").fetchone()
        assert unread is not None
        return {"rows": [self._decode_notification(row) for row in _rows(rows)], "unread": int(unread["count"])}

    def mark_notification_read(self, notification_id: str) -> bool:
        with db.connect() as conn:
            row = conn.execute(
                "UPDATE notifications SET is_read=TRUE, read_at=%s WHERE notification_id=%s RETURNING notification_id",
                (db.now_utc(), notification_id),
            ).fetchone()
        return row is not None

    def queue_webhook(self, notification_id: str) -> None:
        now = db.now_utc()
        with db.connect() as conn:
            conn.execute(
                """INSERT INTO webhook_deliveries
                   (delivery_id,notification_id,attempt,status,next_attempt_at,created_at,updated_at)
                   VALUES (%s,%s,0,'pending',%s,%s,%s)""",
                (str(uuid.uuid4()), notification_id, now, now, now),
            )

    def due_webhooks(self, now: str) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                """SELECT d.*, n.level, n.title, n.message, n.event_type, n.runbook_id, n.run_id,
                          n.details_json, n.created_at AS notification_created_at
                   FROM webhook_deliveries d JOIN notifications n ON n.notification_id=d.notification_id
                   WHERE d.status='pending' AND d.next_attempt_at <= %s ORDER BY d.next_attempt_at LIMIT 20""",
                (now,),
            ).fetchall()
        result = _rows(rows)
        for row in result:
            row["details"] = _load(row.pop("details_json", None), {})
        return result

    def finish_webhook_attempt(
        self,
        delivery_id: str,
        *,
        attempt: int,
        status: str,
        next_attempt_at: str | None = None,
        response_status: int | None = None,
        error: str | None = None,
    ) -> None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE webhook_deliveries SET attempt=%s,status=%s,next_attempt_at=%s,
                   response_status=%s,error=%s,updated_at=%s WHERE delivery_id=%s""",
                (attempt, status, next_attempt_at, response_status, error, db.now_utc(), delivery_id),
            )

    @staticmethod
    def _decode_runbook(row: dict[str, Any]) -> dict[str, Any]:
        row["draft"] = _load(row.pop("draft_json", None), {})
        return row

    @staticmethod
    def _decode_run(row: dict[str, Any]) -> dict[str, Any]:
        row["definition"] = _load(row.pop("definition_json", None), {})
        row["result"] = _load(row.pop("result_json", None), {})
        return row

    @staticmethod
    def _decode_step(row: dict[str, Any]) -> dict[str, Any]:
        row["input"] = _load(row.pop("input_json", None), {})
        row["output"] = _load(row.pop("output_json", None), {})
        return row

    @staticmethod
    def _decode_notification(row: dict[str, Any]) -> dict[str, Any]:
        row["details"] = _load(row.pop("details_json", None), {})
        return row
