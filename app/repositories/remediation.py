from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .. import db
from .vulnerabilities import VULNERABILITY_SELECTOR_SQL

STATUSES = {"open", "in_progress", "risk_accepted", "false_positive", "resolved"}
SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _case(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in (
        "due_at",
        "risk_expires_at",
        "first_seen_at",
        "last_seen_at",
        "resolved_at",
        "reopened_at",
        "created_at",
        "updated_at",
    ):
        result[key] = _iso(result.get(key))
    if result.get("cvss_score") is not None:
        result["cvss_score"] = float(result["cvss_score"])
    result["overdue"] = bool(result.get("overdue"))
    result["near_due"] = bool(result.get("near_due"))
    return result


class RemediationRepository:
    def asset_ids(self) -> list[str]:
        with db.connect() as conn:
            rows = conn.execute("SELECT asset_id FROM asset_cards ORDER BY asset_id").fetchall()
        return [str(row["asset_id"]) for row in rows]

    def ensure_daily_digest(self, *, webhook_enabled: bool, summary: dict[str, Any] | None = None) -> bool:
        summary = summary or self.summary()
        if not summary.get("overdue") and not summary.get("near_due"):
            return False
        day = datetime.now(UTC).date().isoformat()
        notification_id = f"remediation-digest:{day}"
        details = {key: summary.get(key) for key in ("open", "overdue", "near_due")}
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO notifications(notification_id,level,title,message,event_type,details_json,created_at)
                   VALUES (%s,'warning','Контроль сроков устранения',%s,'remediation.daily_digest',%s,NOW())
                   ON CONFLICT(notification_id) DO NOTHING RETURNING notification_id""",
                (
                    notification_id,
                    f"Открыто: {summary.get('open', 0)}, просрочено: {summary.get('overdue', 0)}, скоро срок: {summary.get('near_due', 0)}.",
                    json.dumps(details),
                ),
            ).fetchone()
            if row and webhook_enabled:
                conn.execute(
                    """INSERT INTO webhook_deliveries(delivery_id,notification_id,attempt,status,next_attempt_at,created_at,updated_at)
                       VALUES (%s,%s,0,'pending',%s,%s,%s)""",
                    (str(uuid.uuid4()), notification_id, db.now_utc(), db.now_utc(), db.now_utc()),
                )
        return row is not None

    def policy(self) -> dict[str, Any]:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM remediation_sla_policy WHERE policy_id=1").fetchone()
        assert row is not None
        result = dict(row)
        result["updated_at"] = _iso(result.get("updated_at"))
        return result

    def update_policy(self, values: dict[str, int], *, apply_to_open: bool) -> dict[str, Any]:
        columns = ("critical_days", "high_days", "medium_days", "low_days", "near_due_days")
        with db.connect() as conn:
            current = conn.execute("SELECT * FROM remediation_sla_policy WHERE policy_id=1 FOR UPDATE").fetchone()
            assert current is not None
            merged = {key: int(values.get(key, current[key])) for key in columns}
            row = conn.execute(
                """UPDATE remediation_sla_policy SET critical_days=%s,high_days=%s,medium_days=%s,
                   low_days=%s,near_due_days=%s,updated_at=NOW() WHERE policy_id=1 RETURNING *""",
                tuple(merged[key] for key in columns),
            ).fetchone()
            if apply_to_open:
                conn.execute(
                    """WITH updated AS (UPDATE remediation_cases SET due_at = first_seen_at +
                       CASE severity WHEN 'critical' THEN (%s || ' days')::interval
                       WHEN 'high' THEN (%s || ' days')::interval
                       WHEN 'medium' THEN (%s || ' days')::interval
                       WHEN 'low' THEN (%s || ' days')::interval END,
                       version=version+1, updated_at=NOW()
                       WHERE status IN ('open','in_progress') AND manual_due=FALSE
                       RETURNING case_id,status)
                       INSERT INTO remediation_case_events(case_id,event_type,old_status,new_status,changes_json)
                       SELECT case_id,'policy_recalculated',status,status,'{"due_at":"recalculated"}'::jsonb FROM updated""",
                    (merged["critical_days"], merged["high_days"], merged["medium_days"], merged["low_days"]),
                )
        assert row is not None
        result = dict(row)
        result["updated_at"] = _iso(result["updated_at"])
        return result

    def expire_risk_acceptances(self) -> int:
        with db.connect() as conn:
            rows = conn.execute(
                """UPDATE remediation_cases c SET status='open', risk_reason=NULL, risk_expires_at=NULL,
                   reopened_at=NOW(), resolved_at=NULL, due_at=NOW() + CASE c.severity
                     WHEN 'critical' THEN (p.critical_days || ' days')::interval
                     WHEN 'high' THEN (p.high_days || ' days')::interval
                     WHEN 'medium' THEN (p.medium_days || ' days')::interval
                     WHEN 'low' THEN (p.low_days || ' days')::interval END,
                   manual_due=FALSE, version=version+1, updated_at=NOW()
                   FROM remediation_sla_policy p
                   WHERE p.policy_id=1 AND c.status='risk_accepted' AND c.risk_expires_at <= NOW()
                   RETURNING c.case_id"""
            ).fetchall()
            for item in rows:
                conn.execute(
                    """INSERT INTO remediation_case_events(case_id,event_type,old_status,new_status,changes_json)
                       VALUES (%s,'risk_expired','risk_accepted','open','{}')""",
                    (item["case_id"],),
                )
        return len(rows)

    def list(self, **filters: Any) -> dict[str, Any]:
        self.expire_risk_acceptances()
        clauses: list[str] = []
        params: list[Any] = []
        status = filters.get("status")
        severity = filters.get("severity")
        if status:
            clauses.append("c.status=%s")
            params.append(status)
        if severity:
            clauses.append("c.severity=%s")
            params.append(severity)
        if filters.get("assignee"):
            clauses.append("LOWER(COALESCE(c.assignee,''))=LOWER(%s)")
            params.append(filters["assignee"])
        if filters.get("overdue"):
            clauses.append("c.status IN ('open','in_progress') AND c.due_at < NOW()")
        if filters.get("q"):
            clauses.append("(c.title ILIKE %s OR c.cve ILIKE %s OR c.asset_id ILIKE %s)")
            needle = f"%{filters['q']}%"
            params.extend((needle, needle, needle))
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        limit = max(1, min(int(filters.get("limit", 50)), 500))
        offset = max(0, int(filters.get("offset", 0)))
        with db.connect() as conn:
            total_row = conn.execute(f"SELECT COUNT(*) AS count FROM remediation_cases c {where}", params).fetchone()
            rows = conn.execute(
                f"""SELECT c.*, card.display_name, card.ip_address, card.fqdn,
                    (c.status IN ('open','in_progress') AND c.due_at < NOW()) AS overdue,
                    (c.status IN ('open','in_progress') AND c.due_at >= NOW()
                     AND c.due_at <= NOW() + (policy.near_due_days || ' days')::interval) AS near_due
                    FROM remediation_cases c JOIN asset_cards card ON card.asset_id=c.asset_id
                    CROSS JOIN remediation_sla_policy policy {where}
                    ORDER BY CASE WHEN c.status IN ('open','in_progress') AND c.due_at < NOW() THEN 0 ELSE 1 END,
                     CASE c.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                     WHEN 'low' THEN 4 ELSE 5 END, c.cvss_score DESC NULLS LAST, c.first_seen_at, c.case_id
                    LIMIT %s OFFSET %s""",
                (*params, limit, offset),
            ).fetchall()
        return {"rows": [_case(dict(row)) for row in rows], "total": int(total_row["count"] if total_row else 0)}

    def get(self, case_id: str) -> dict[str, Any] | None:
        self.expire_risk_acceptances()
        with db.connect() as conn:
            row = conn.execute(
                """SELECT c.*, card.display_name, card.ip_address, card.fqdn,
                   (c.status IN ('open','in_progress') AND c.due_at < NOW()) AS overdue,
                   FALSE AS near_due FROM remediation_cases c JOIN asset_cards card ON card.asset_id=c.asset_id
                   WHERE c.case_id=%s""",
                (case_id,),
            ).fetchone()
            if not row:
                return None
            events = conn.execute(
                "SELECT * FROM remediation_case_events WHERE case_id=%s ORDER BY created_at DESC,event_id DESC",
                (case_id,),
            ).fetchall()
        result = _case(dict(row))
        result["events"] = [
            {**dict(event), "created_at": _iso(event["created_at"]), "changes": event["changes_json"]}
            for event in events
        ]
        return result

    def update(
        self, case_id: str, changes: dict[str, Any], *, expected_version: int, comment: str | None
    ) -> dict[str, Any] | None:
        allowed = {"status", "assignee", "due_at", "risk_reason", "risk_expires_at"}
        clean = {key: value for key, value in changes.items() if key in allowed}
        assignments: list[str] = []
        params: list[Any] = []
        for key, value in clean.items():
            assignments.append(f"{key}=%s")
            params.append(value or None)
        if "due_at" in clean:
            assignments.append("manual_due=TRUE")
        if not assignments and not comment:
            return self.get(case_id)
        with db.connect() as conn:
            old = conn.execute("SELECT * FROM remediation_cases WHERE case_id=%s FOR UPDATE", (case_id,)).fetchone()
            if not old:
                return None
            if int(old["version"]) != expected_version:
                raise RuntimeError("VERSION_CONFLICT")
            if assignments:
                row = conn.execute(
                    f"UPDATE remediation_cases SET {','.join(assignments)},version=version+1,updated_at=NOW() "
                    "WHERE case_id=%s RETURNING *",
                    (*params, case_id),
                ).fetchone()
            else:
                row = old
            assert row is not None
            conn.execute(
                """INSERT INTO remediation_case_events(case_id,event_type,old_status,new_status,changes_json,comment)
                   VALUES (%s,'operator_update',%s,%s,%s::jsonb,%s)""",
                (case_id, old["status"], row["status"], json.dumps(clean, default=str), comment),
            )
        return self.get(case_id)

    def summary(self) -> dict[str, Any]:
        self.expire_risk_acceptances()
        with db.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) FILTER (WHERE status IN ('open','in_progress')) AS open,
                   COUNT(*) FILTER (WHERE status IN ('open','in_progress') AND due_at < NOW()) AS overdue,
                   COUNT(*) FILTER (WHERE status IN ('open','in_progress') AND due_at >= NOW()
                     AND due_at <= NOW() + (p.near_due_days || ' days')::interval) AS near_due,
                   COUNT(*) FILTER (WHERE status='risk_accepted') AS risk_accepted,
                   COUNT(*) FILTER (WHERE status='resolved' AND resolved_at >= NOW()-INTERVAL '30 days') AS resolved_30d,
                   ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at-first_seen_at))/86400)
                     FILTER (WHERE resolved_at IS NOT NULL),1) AS mean_time_to_resolve_days
                   FROM remediation_cases CROSS JOIN remediation_sla_policy p GROUP BY p.near_due_days"""
            ).fetchone()
        return (
            dict(row)
            if row
            else {
                "open": 0,
                "overdue": 0,
                "near_due": 0,
                "risk_accepted": 0,
                "resolved_30d": 0,
                "mean_time_to_resolve_days": None,
            }
        )

    def reconcile_asset(self, asset_id: str, *, stale_days: int) -> dict[str, int]:
        now = datetime.now(UTC)
        selector = VULNERABILITY_SELECTOR_SQL
        with db.connect() as conn:
            policy = conn.execute("SELECT * FROM remediation_sla_policy WHERE policy_id=1").fetchone()
            card = conn.execute("SELECT * FROM asset_cards WHERE asset_id=%s", (asset_id,)).fetchone()
            if not card or not policy:
                return {"created": 0, "reopened": 0, "resolved": 0}
            rows = conn.execute(
                f"""SELECT DISTINCT ON ({selector}) {selector} AS vulnerability_key, finding.name AS title,
                   finding.cve_name AS cve, CASE WHEN LOWER(TRIM(COALESCE(finding.severity,''))) IN
                   ('critical','high','medium','low') THEN LOWER(TRIM(finding.severity)) ELSE 'unknown' END severity,
                   finding.cvss_score, link.passport_internal_id
                   FROM asset_card_vulnerabilities finding
                   JOIN asset_card_vulnerability_groups vulnerability_group ON vulnerability_group.id=finding.group_id
                   LEFT JOIN asset_card_vulnerability_passports link ON link.asset_vulnerability_id=finding.id
                   WHERE finding.asset_id=%s ORDER BY {selector}, finding.cvss_score DESC NULLS LAST, link.passport_internal_id""",
                (asset_id,),
            ).fetchall()
            existing_rows = conn.execute(
                "SELECT * FROM remediation_cases WHERE asset_id=%s FOR UPDATE", (asset_id,)
            ).fetchall()
            existing = {row["vulnerability_key"]: row for row in existing_rows}
            current_keys: set[str] = set()
            created = reopened = resolved = 0
            for finding in rows:
                key = finding["vulnerability_key"]
                current_keys.add(key)
                old = existing.get(key)
                if old:
                    reopen = old["status"] == "resolved"
                    conn.execute(
                        """UPDATE remediation_cases SET title=%s,cve=%s,severity=%s,cvss_score=%s,
                           passport_internal_id=%s,last_seen_at=NOW(),status=CASE WHEN status='resolved' THEN 'open' ELSE status END,
                           resolved_at=CASE WHEN status='resolved' THEN NULL ELSE resolved_at END,
                           reopened_at=CASE WHEN status='resolved' THEN NOW() ELSE reopened_at END,
                           due_at=CASE WHEN status='resolved' THEN NOW()+CASE %s WHEN 'critical' THEN (%s||' days')::interval
                             WHEN 'high' THEN (%s||' days')::interval WHEN 'medium' THEN (%s||' days')::interval
                             WHEN 'low' THEN (%s||' days')::interval END ELSE due_at END,
                           version=version+1,updated_at=NOW() WHERE case_id=%s""",
                        (
                            finding["title"],
                            finding["cve"],
                            finding["severity"],
                            finding["cvss_score"],
                            finding["passport_internal_id"],
                            finding["severity"],
                            policy["critical_days"],
                            policy["high_days"],
                            policy["medium_days"],
                            policy["low_days"],
                            old["case_id"],
                        ),
                    )
                    if reopen:
                        reopened += 1
                        conn.execute(
                            "INSERT INTO remediation_case_events(case_id,event_type,old_status,new_status) VALUES (%s,'finding_reappeared','resolved','open')",
                            (old["case_id"],),
                        )
                    continue
                severity = finding["severity"]
                raw_days = policy.get(f"{severity}_days") if severity != "unknown" else None
                days = int(raw_days) if raw_days is not None else None
                due_at = now.replace(microsecond=0) if days is not None else None
                if due_at is not None:
                    from datetime import timedelta

                    assert days is not None
                    due_at += timedelta(days=days)
                case_id = __import__("hashlib").md5(f"{asset_id}\x1f{key}".encode(), usedforsecurity=False).hexdigest()
                conn.execute(
                    """INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,title,cve,severity,cvss_score,
                       passport_internal_id,due_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        case_id,
                        asset_id,
                        key,
                        finding["title"],
                        finding["cve"],
                        severity,
                        finding["cvss_score"],
                        finding["passport_internal_id"],
                        due_at,
                    ),
                )
                conn.execute(
                    "INSERT INTO remediation_case_events(case_id,event_type,new_status) VALUES (%s,'finding_created','open')",
                    (case_id,),
                )
                created += 1
            truncated = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM asset_card_vulnerability_groups WHERE asset_id=%s AND truncated) AS value",
                (asset_id,),
            ).fetchone()
            last_seen = datetime.fromisoformat(str(card["last_seen"]).replace("Z", "+00:00"))
            complete = (
                not bool(truncated["value"] if truncated else True)
                and (now - last_seen.astimezone(UTC)).days < stale_days
            )
            if complete:
                for key, old in existing.items():
                    if key not in current_keys and old["status"] not in {"resolved", "false_positive"}:
                        conn.execute(
                            "UPDATE remediation_cases SET status='resolved',resolved_at=NOW(),version=version+1,updated_at=NOW() WHERE case_id=%s",
                            (old["case_id"],),
                        )
                        conn.execute(
                            "INSERT INTO remediation_case_events(case_id,event_type,old_status,new_status) VALUES (%s,'finding_absent',%s,'resolved')",
                            (old["case_id"], old["status"]),
                        )
                        resolved += 1
        return {"created": created, "reopened": reopened, "resolved": resolved}


class CoverageRepository:
    def list_assets(
        self, *, stale_days: int, q: str | None, issue: str | None, limit: int, offset: int
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = [stale_days]
        if q:
            clauses.append("(display_name ILIKE %s OR ip_address ILIKE %s OR fqdn ILIKE %s OR asset_id ILIKE %s)")
            params.extend([f"%{q}%"] * 4)
        issue_map = {
            "missing": "missing_card",
            "stale": "stale",
            "truncated": "truncated",
            "failed": "last_refresh_failed",
        }
        if issue in issue_map:
            clauses.append(issue_map[issue])
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"""WITH latest_operation AS (
            SELECT DISTINCT ON (subject_id) subject_id,status,operation_id FROM operations
            WHERE kind='asset_card_build' ORDER BY subject_id,created_at DESC
        ), base AS (
            SELECT COALESCE(card.asset_id,NULLIF(asset.mp_asset_id,''),asset.asset_key) asset_id,
              COALESCE(card.display_name,asset.fqdn,asset.ip_address,asset.asset_key) display_name,
              COALESCE(card.ip_address,asset.ip_address) ip_address,COALESCE(card.fqdn,asset.fqdn) fqdn,
              card.last_seen,card.asset_id IS NULL missing_card,
              card.asset_id IS NOT NULL AND NULLIF(card.last_seen,'')::timestamptz < NOW()-(%s||' days')::interval stale,
              COALESCE(EXISTS(SELECT 1 FROM asset_card_vulnerability_groups g WHERE g.asset_id=card.asset_id AND g.truncated),FALSE) truncated,
              COALESCE(op.status IN ('failed','interrupted','completed_with_errors'),FALSE) last_refresh_failed,
              op.operation_id
            FROM assets asset FULL OUTER JOIN asset_cards card
              ON card.asset_id=COALESCE(NULLIF(asset.mp_asset_id,''),asset.asset_key)
            LEFT JOIN latest_operation op ON op.subject_id=COALESCE(card.asset_id,NULLIF(asset.mp_asset_id,''),asset.asset_key)
        ) SELECT *, COUNT(*) OVER() total FROM base {where}
          ORDER BY (missing_card OR stale OR truncated OR last_refresh_failed) DESC,display_name,asset_id LIMIT %s OFFSET %s"""
        with db.connect() as conn:
            rows = conn.execute(sql, (*params, limit, offset)).fetchall()
        total = int(rows[0]["total"]) if rows else 0
        return {"rows": [dict(row) for row in rows], "total": total, "stale_days": stale_days}

    def summary(self, *, stale_days: int) -> dict[str, Any]:
        result = self.list_assets(stale_days=stale_days, q=None, issue=None, limit=50000, offset=0)
        rows = result["rows"]
        total = len(rows)
        healthy = sum(
            not any(row[key] for key in ("missing_card", "stale", "truncated", "last_refresh_failed")) for row in rows
        )
        return {
            "total_assets": total,
            "healthy_assets": healthy,
            "coverage_percent": round(healthy * 100 / total, 1) if total else 100.0,
            "missing_card": sum(bool(row["missing_card"]) for row in rows),
            "stale": sum(bool(row["stale"]) for row in rows),
            "truncated": sum(bool(row["truncated"]) for row in rows),
            "last_refresh_failed": sum(bool(row["last_refresh_failed"]) for row in rows),
            "stale_days": stale_days,
        }
