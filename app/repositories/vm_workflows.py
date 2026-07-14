from __future__ import annotations

import builtins
import json
import uuid
from typing import Any

from .. import db

ACTIVE = {"queued", "running", "cancelling"}
TERMINAL = {"completed", "completed_with_errors", "failed", "cancelled"}
STEP_KEYS = {
    "scan": ("validation", "scan", "postprocess", "reconcile"),
    "verification": ("targets", "scan", "postprocess", "reconcile"),
}


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in ("created_at", "started_at", "finished_at", "updated_at"):
        result[key] = _iso(result.get(key))
    for source, target in (("request_json", "request"), ("result_json", "result"), ("error_json", "error")):
        result[target] = result.pop(source, {}) or {}
    result["cancel_requested"] = bool(result.get("cancel_requested"))
    return result


class VmWorkflowRepository:
    def create(
        self, *, kind: str, request: dict[str, Any], requested_by: str | None,
        idempotency_key: str | None = None, retry_of: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        if idempotency_key:
            replay = self.by_idempotency_key(idempotency_key)
            if replay:
                if replay["kind"] != kind:
                    raise ValueError("Idempotency key belongs to another workflow kind.")
                return replay, True
        workflow_id = str(uuid.uuid4())
        with db.connect() as conn:
            conn.execute(
                """INSERT INTO vm_workflow_runs(workflow_id,kind,requested_by,idempotency_key,retry_of,request_json)
                   VALUES(%s,%s,%s,%s,%s,%s)""",
                (workflow_id, kind, requested_by, idempotency_key, retry_of, json.dumps(request)),
            )
            for position, key in enumerate(STEP_KEYS[kind], 1):
                conn.execute(
                    "INSERT INTO vm_workflow_steps(workflow_id,step_key,position) VALUES(%s,%s,%s)",
                    (workflow_id, key, position),
                )
        return self.get(workflow_id) or {}, False

    def by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM vm_workflow_runs WHERE idempotency_key=%s", (key,)).fetchone()
        return self.get(str(row["workflow_id"])) if row else None

    def by_operation(self, operation_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(
                "SELECT workflow_id FROM vm_workflow_runs WHERE operation_id=%s ORDER BY created_at DESC LIMIT 1",
                (operation_id,),
            ).fetchone()
        return self.get(str(row["workflow_id"])) if row else None

    def list(self, *, status: str | None = None, kind: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        clauses, params = [], []
        if status:
            clauses.append("status=%s")
            params.append(status)
        if kind:
            clauses.append("kind=%s")
            params.append(kind)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
        with db.connect() as conn:
            total_row = conn.execute(f"SELECT COUNT(*) count FROM vm_workflow_runs {where}", params).fetchone()
            rows = conn.execute(
                f"SELECT * FROM vm_workflow_runs {where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
        return {"rows": [_decode(dict(row)) for row in rows], "total": int(total_row["count"] if total_row else 0), "limit": limit, "offset": offset}

    def get(self, workflow_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM vm_workflow_runs WHERE workflow_id=%s", (workflow_id,)).fetchone()
            steps = conn.execute(
                "SELECT * FROM vm_workflow_steps WHERE workflow_id=%s ORDER BY position", (workflow_id,)
            ).fetchall() if row else []
        if not row:
            return None
        result = _decode(dict(row))
        result["steps"] = [_decode(dict(step)) for step in steps]
        result["can_cancel"] = result["status"] in ACTIVE
        result["can_retry"] = result["status"] in {"failed", "completed_with_errors", "cancelled"}
        return result

    def active(self) -> builtins.list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT workflow_id FROM vm_workflow_runs WHERE status IN ('queued','running','cancelling') ORDER BY created_at"
            ).fetchall()
        return [item for row in rows if (item := self.get(str(row["workflow_id"]))) is not None]

    def active_for_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(
                """SELECT workflow_id FROM vm_workflow_runs WHERE campaign_id=%s
                   AND status IN ('queued','running','cancelling') ORDER BY created_at DESC LIMIT 1""",
                (campaign_id,),
            ).fetchone()
        return self.get(str(row["workflow_id"])) if row else None

    def update_run(self, workflow_id: str, **values: Any) -> dict[str, Any] | None:
        allowed = {"status", "stage", "progress_percent", "task_id", "campaign_id", "operation_id", "result", "error", "cancel_requested"}
        clean = {key: value for key, value in values.items() if key in allowed}
        if not clean:
            return self.get(workflow_id)
        assignments, params = [], []
        for key, value in clean.items():
            column = f"{key}_json" if key in {"result", "error"} else key
            assignments.append(f"{column}=%s")
            params.append(json.dumps(value) if key in {"result", "error"} else value)
        status = clean.get("status")
        if status == "running":
            assignments.append("started_at=COALESCE(started_at,NOW())")
        if status in TERMINAL:
            assignments.append("finished_at=COALESCE(finished_at,NOW())")
        assignments.append("updated_at=NOW()")
        with db.connect() as conn:
            conn.execute(f"UPDATE vm_workflow_runs SET {','.join(assignments)} WHERE workflow_id=%s", (*params, workflow_id))
        return self.get(workflow_id)

    def update_step(self, workflow_id: str, step_key: str, **values: Any) -> None:
        allowed = {"status", "progress_percent", "operation_id", "message", "result", "error"}
        clean = {key: value for key, value in values.items() if key in allowed}
        assignments, params = [], []
        for key, value in clean.items():
            column = f"{key}_json" if key in {"result", "error"} else key
            assignments.append(f"{column}=%s")
            params.append(json.dumps(value) if key in {"result", "error"} else value)
        if clean.get("status") == "running":
            assignments.append("started_at=COALESCE(started_at,NOW())")
        if clean.get("status") in {"completed", "failed", "cancelled", "skipped"}:
            assignments.append("finished_at=NOW()")
        assignments.append("updated_at=NOW()")
        with db.connect() as conn:
            conn.execute(
                f"UPDATE vm_workflow_steps SET {','.join(assignments)} WHERE workflow_id=%s AND step_key=%s",
                (*params, workflow_id, step_key),
            )

    def request_cancel(self, workflow_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE vm_workflow_runs SET cancel_requested=TRUE,status='cancelling',updated_at=NOW()
                   WHERE workflow_id=%s AND status IN ('queued','running','cancelling')""", (workflow_id,)
            )
        return self.get(workflow_id)

    def campaign_targets(self, campaign_id: str) -> builtins.list[str] | None:
        with db.connect() as conn:
            exists = conn.execute("SELECT 1 FROM remediation_campaigns WHERE campaign_id=%s", (campaign_id,)).fetchone()
            if not exists:
                return None
            rows = conn.execute(
                """SELECT DISTINCT rc.asset_id FROM remediation_campaign_cases cc
                   JOIN remediation_cases rc ON rc.case_id=cc.case_id
                   WHERE cc.campaign_id=%s AND rc.status IN ('open','in_progress') ORDER BY rc.asset_id""", (campaign_id,)
            ).fetchall()
        return [str(row["asset_id"]) for row in rows]

    def set_campaign_verification(self, campaign_id: str, workflow_id: str, status: str, message: str | None = None) -> None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE remediation_cases rc SET verification_status=%s,verification_workflow_id=%s,
                   verification_message=%s,version=version+1,updated_at=NOW()
                   FROM remediation_campaign_cases cc WHERE cc.campaign_id=%s AND cc.case_id=rc.case_id
                   AND rc.status IN ('open','in_progress')""", (status, workflow_id, message, campaign_id)
            )
            conn.execute(
                """INSERT INTO remediation_campaign_events(campaign_id,event_type,changes_json)
                   VALUES(%s,'verification_status',%s)""",
                (campaign_id, json.dumps({"workflow_id": workflow_id, "status": status, "message": message})),
            )

    def finalize_campaign_verification(self, campaign_id: str, workflow_id: str, failed_assets: builtins.list[str]) -> None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE remediation_cases rc SET verification_status=CASE WHEN rc.status='resolved' THEN 'passed' ELSE 'failed' END,
                   verification_message=CASE WHEN rc.status='resolved' THEN 'Отсутствие находки подтверждено свежей полной карточкой.'
                     ELSE 'Находка сохранилась или результат проверки неполон.' END,version=version+1,updated_at=NOW()
                   FROM remediation_campaign_cases cc WHERE cc.campaign_id=%s AND cc.case_id=rc.case_id
                   AND rc.verification_workflow_id=%s""", (campaign_id, workflow_id)
            )
            if failed_assets:
                conn.execute(
                    """UPDATE remediation_cases rc SET verification_status='failed',verification_message='Сканирование актива завершилось с ошибкой.',
                       version=version+1,updated_at=NOW() FROM remediation_campaign_cases cc
                       WHERE cc.campaign_id=%s AND cc.case_id=rc.case_id AND rc.asset_id=ANY(%s)""",
                    (campaign_id, failed_assets),
                )

    def overview(self) -> dict[str, Any]:
        with db.connect() as conn:
            row = conn.execute("""SELECT
              (SELECT COUNT(*) FROM vm_workflow_runs WHERE status IN ('queued','running','cancelling')) active_workflows,
              (SELECT COUNT(*) FROM operations WHERE status IN ('queued','running','cancelling','recovering')) active_operations,
              (SELECT COUNT(*) FROM remediation_cases WHERE status IN ('open','in_progress') AND due_at<NOW()) overdue_cases,
              (SELECT COUNT(*) FROM remediation_cases WHERE verification_status IN ('queued','running')) awaiting_verification,
              (SELECT COUNT(*) FROM remediation_cases WHERE status IN ('open','in_progress')) open_cases,
              (SELECT COUNT(*) FROM asset_cards) asset_count""").fetchone()
            attention = conn.execute("""SELECT case_id,asset_id,title,cve,severity,status,due_at,verification_status
              FROM remediation_cases WHERE status IN ('open','in_progress')
              ORDER BY CASE WHEN due_at<NOW() THEN 0 ELSE 1 END,
              CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,due_at NULLS LAST LIMIT 10""").fetchall()
        totals = dict(row) if row else {}
        return {**totals, "attention": [{**dict(item), "due_at": _iso(item.get("due_at"))} for item in attention]}
