from __future__ import annotations

import base64
import json
from typing import Any

from .. import db

_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RETRYABLE_OPERATION_KINDS = {"asset_card_build", "passport_detail_sync", "automation_run"}


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value is not None else None)


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"offset": max(0, offset)}).encode()).decode().rstrip("=")


def decode_cursor(value: str | None) -> int:
    if not value:
        return 0
    try:
        raw = value + "=" * (-len(value) % 4)
        parsed = json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
        if not isinstance(parsed, dict) or not isinstance(parsed.get("offset"), int) or parsed["offset"] < 0:
            raise ValueError("Invalid cursor.")
        return max(0, int(parsed.get("offset", 0)))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid cursor.") from exc


class AttentionRepository:
    def __init__(self, *, stale_days: int = 14) -> None:
        self.stale_days = max(1, int(stale_days))

    def _rows(self, *, permissions: set[str], owner: str | None = None) -> list[dict[str, Any]]:
        db.init_db()
        result: list[dict[str, Any]] = []
        with db.connect() as conn:
            if "remediation.read" in permissions:
                clauses = ["c.status IN ('open','in_progress')"]
                params: list[Any] = []
                if owner:
                    clauses.append("LOWER(COALESCE(c.assignee,''))=LOWER(%s)")
                    params.append(owner)
                rows = conn.execute(
                    f"""SELECT c.case_id,c.title,c.severity,c.assignee,c.due_at,c.updated_at,c.asset_id,
                               card.display_name,(c.due_at IS NOT NULL AND c.due_at < NOW()) AS overdue
                        FROM remediation_cases c LEFT JOIN asset_cards card ON card.asset_id=c.asset_id
                        WHERE {' AND '.join(clauses)}""", params,
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    severity = str(item.get("severity") or "unknown").lower()
                    priority = "critical" if severity == "critical" else ("high" if severity == "high" else "medium")
                    if item.get("overdue"):
                        priority = "critical" if severity in {"critical", "high"} else "high"
                    result.append({
                        "id": str(item["case_id"]), "type": "case", "priority": priority,
                        "title": item.get("title") or f"Remediation case {item['case_id']}",
                        "reason": "SLA просрочен" if item.get("overdue") else "Открытый remediation-кейс",
                        "owner": item.get("assignee"), "due_at": _iso(item.get("due_at")),
                        "action": "open_case", "href": f"/remediation?case={item['case_id']}",
                        "updated_at": _iso(item.get("updated_at")),
                    })
            if "operations.read" in permissions:
                clauses = ["status IN ('failed','interrupted','completed_with_errors')"]
                params = []
                rows = conn.execute(
                    f"SELECT operation_id,kind,status,subject_label,updated_at,created_at,message FROM operations WHERE {' AND '.join(clauses)}",
                    params,
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    result.append({
                        "id": str(item["operation_id"]), "type": "operation", "priority": "high",
                        "title": item.get("subject_label") or item.get("kind") or str(item["operation_id"]),
                        "reason": item.get("message") or f"Операция завершилась со статусом {item.get('status')}",
                        "owner": None, "due_at": None,
                        "action": "retry" if item.get("kind") in _RETRYABLE_OPERATION_KINDS else "open_operation",
                        "can_retry": item.get("kind") in _RETRYABLE_OPERATION_KINDS,
                        "href": f"/operations?operation={item['operation_id']}",
                        "updated_at": _iso(item.get("updated_at") or item.get("created_at")),
                    })
            if {"assets.read", "asset_cards.read"}.issubset(permissions):
                rows = conn.execute(
                    f"""WITH latest AS (SELECT DISTINCT ON (subject_id) subject_id,status,updated_at
                       FROM operations WHERE kind='asset_card_build' ORDER BY subject_id,created_at DESC)
                       SELECT COALESCE(card.asset_id,asset.mp_asset_id,asset.asset_key) AS asset_id,
                         COALESCE(card.display_name,asset.fqdn,asset.ip_address,asset.asset_key) AS display_name,
                         card.last_seen, card.asset_id IS NULL AS missing_card,
                         card.asset_id IS NOT NULL AND NULLIF(card.last_seen,'')::timestamptz < NOW()-INTERVAL '{self.stale_days} days' AS stale,
                         COALESCE(latest.status IN ('failed','interrupted','completed_with_errors'),FALSE) AS failed,
                         latest.updated_at
                       FROM assets asset FULL OUTER JOIN asset_cards card
                         ON card.asset_id=COALESCE(NULLIF(asset.mp_asset_id,''),asset.asset_key)
                       LEFT JOIN latest ON latest.subject_id=COALESCE(card.asset_id,asset.mp_asset_id,asset.asset_key)
                       WHERE card.asset_id IS NULL OR card.last_seen IS NULL OR
                         NULLIF(card.last_seen,'')::timestamptz < NOW()-INTERVAL '{self.stale_days} days' OR
                         latest.status IN ('failed','interrupted','completed_with_errors')"""
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    reason = "Карточка отсутствует" if item.get("missing_card") else ("Карточка устарела" if item.get("stale") else "Последнее обновление завершилось ошибкой")
                    result.append({
                        "id": str(item.get("asset_id")), "type": "coverage", "priority": "medium",
                        "title": item.get("display_name") or str(item.get("asset_id")), "reason": reason,
                        "owner": None, "due_at": None, "action": "open_asset",
                        "href": f"/asset-cards/{item.get('asset_id')}", "updated_at": _iso(item.get("updated_at") or item.get("last_seen")),
                    })
            if "automations.read" in permissions:
                rows = conn.execute(
                    "SELECT a.run_id,r.name AS runbook_name,a.status,a.updated_at,a.created_at FROM automation_runs a LEFT JOIN automation_runbooks r ON r.runbook_id=a.runbook_id WHERE a.status IN ('failed','warning','completed_with_warnings')"
                ).fetchall()
                for row in rows:
                    item = dict(row)
                    result.append({
                        "id": str(item["run_id"]), "type": "automation", "priority": "high",
                        "title": item.get("runbook_name") or str(item["run_id"]), "reason": f"Автоматизация: {item.get('status')}",
                        "owner": None, "due_at": None, "action": "open_automation",
                        "href": f"/automations/runs/{item['run_id']}", "updated_at": _iso(item.get("updated_at") or item.get("created_at")),
                    })
        result.sort(key=lambda item: (_PRIORITY.get(item["priority"], 9), item.get("due_at") is None, item.get("due_at") or "", item.get("updated_at") or "", item["id"]))
        return result

    def attention(self, *, permissions: set[str], limit: int, cursor: str | None, owner: str | None = None, kind: str | None = None, priority: str | None = None) -> dict[str, Any]:
        offset = decode_cursor(cursor)
        rows = self._rows(permissions=permissions, owner=owner)
        if kind:
            rows = [item for item in rows if item["type"] == kind]
        if priority:
            rows = [item for item in rows if item["priority"] == priority]
        page = rows[offset:offset + limit]
        return {"items": page, "total": len(rows), "next_cursor": encode_cursor(offset + limit) if offset + limit < len(rows) else None}

    def search(self, *, query: str, kind: str | None, permissions: set[str], limit: int, cursor: str | None) -> dict[str, Any]:
        db.init_db()
        q = query.strip()
        if len(q) < 2:
            raise ValueError("Search query must contain at least two characters.")
        pattern = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        requested = {kind} if kind else {"asset", "vulnerability", "task", "case", "operation"}
        items: list[dict[str, Any]] = []
        with db.connect() as conn:
            if "asset" in requested and "asset_cards.read" in permissions:
                rows = conn.execute("""SELECT asset_id,display_name,ip_address,fqdn,vulnerability_level FROM asset_cards
                    WHERE asset_id ILIKE %s OR display_name ILIKE %s OR ip_address ILIKE %s OR fqdn ILIKE %s
                    ORDER BY display_name,asset_id LIMIT 100""", (pattern,) * 4).fetchall()
                items += [{"type":"asset","id":str(r["asset_id"]),"title":r.get("display_name") or str(r["asset_id"]),"subtitle":r.get("ip_address") or r.get("fqdn"),"status":r.get("vulnerability_level"),"href":f"/asset-cards/{r['asset_id']}"} for r in map(dict, rows)]
            if "vulnerability" in requested and "assets.read" in permissions:
                rows = conn.execute("""SELECT DISTINCT finding.id,finding.cve_name,finding.name,finding.severity,finding.asset_id
                    FROM asset_card_vulnerabilities finding JOIN asset_cards card ON card.asset_id=finding.asset_id
                    WHERE finding.cve_name ILIKE %s OR finding.name ILIKE %s ORDER BY finding.cve_name,finding.id LIMIT 100""", (pattern, pattern)).fetchall()
                items += [{"type":"vulnerability","id":str(r["id"]),"title":r.get("cve_name") or r.get("name") or str(r["id"]),"subtitle":r.get("name"),"status":r.get("severity"),"href":f"/vulnerabilities?asset_id={r['asset_id']}&finding={r['id']}"} for r in map(dict, rows)]
            if "task" in requested and "tasks.read" in permissions:
                rows = conn.execute("SELECT mp_task_id,name,status FROM scan_tasks WHERE deleted_at IS NULL AND (mp_task_id ILIKE %s OR name ILIKE %s) ORDER BY name,mp_task_id LIMIT 100", (pattern, pattern)).fetchall()
                items += [{"type":"task","id":str(r["mp_task_id"]),"title":r.get("name") or str(r["mp_task_id"]),"subtitle":r.get("status"),"status":r.get("status"),"href":f"/scanner-tasks?task={r['mp_task_id']}"} for r in map(dict, rows)]
            if "case" in requested and "remediation.read" in permissions:
                rows = conn.execute("SELECT case_id,title,status,severity FROM remediation_cases WHERE status <> 'resolved' AND (case_id ILIKE %s OR title ILIKE %s) ORDER BY title,case_id LIMIT 100", (pattern, pattern)).fetchall()
                items += [{"type":"case","id":str(r["case_id"]),"title":r.get("title") or str(r["case_id"]),"subtitle":r.get("severity"),"status":r.get("status"),"href":f"/remediation?case={r['case_id']}"} for r in map(dict, rows)]
            if "operation" in requested and "operations.read" in permissions:
                rows = conn.execute("SELECT operation_id,subject_label,status,kind FROM operations WHERE operation_id ILIKE %s OR trace_id ILIKE %s OR subject_label ILIKE %s ORDER BY updated_at DESC,operation_id LIMIT 100", (pattern, pattern, pattern)).fetchall()
                items += [{"type":"operation","id":str(r["operation_id"]),"title":r.get("subject_label") or str(r["operation_id"]),"subtitle":r.get("kind"),"status":r.get("status"),"href":f"/operations?operation={r['operation_id']}"} for r in map(dict, rows)]
        items.sort(key=lambda item: (item["type"], item["title"].lower(), item["id"]))
        offset = decode_cursor(cursor)
        page = items[offset:offset + limit]
        return {"items": page, "next_cursor": encode_cursor(offset + limit) if offset + limit < len(items) else None}
