from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

from .. import db

MODEL_VERSION = "local-risk-v1"
CONTEXT_VALUES = {
    "criticality": {"critical", "high", "medium", "low"},
    "environment": {"production", "test", "development"},
    "exposure": {"external", "internal", "isolated"},
}


def _risk_sql(alias: str = "x") -> str:
    return f"""LEAST(100, GREATEST(0,
      CASE c.severity WHEN 'critical' THEN 40 WHEN 'high' THEN 30 WHEN 'medium' THEN 20 WHEN 'low' THEN 10 ELSE 5 END
      + LEAST(10, COALESCE(c.cvss_score,0))
      + CASE COALESCE({alias}.criticality,'medium') WHEN 'critical' THEN 20 WHEN 'high' THEN 14 WHEN 'medium' THEN 8 ELSE 3 END
      + CASE COALESCE({alias}.exposure,'internal') WHEN 'external' THEN 15 WHEN 'internal' THEN 7 ELSE 2 END
      + CASE WHEN c.status IN ('open','in_progress') AND c.due_at<NOW() THEN 10 ELSE 0 END
      + CASE WHEN c.first_seen_at<NOW()-INTERVAL '90 days' THEN 5 WHEN c.first_seen_at<NOW()-INTERVAL '30 days' THEN 3 ELSE 0 END
      + CASE WHEN EXISTS(SELECT 1 FROM vulnerability_passports vp WHERE vp.internal_id=c.passport_internal_id
          AND LOWER(COALESCE(vp.raw_detail_json,'') || COALESCE(vp.metrics_json,'') || COALESCE(vp.raw_record_json,''))
          SIMILAR TO '%(exploit|exploited|эксплуат)%') THEN 5 ELSE 0 END
      + LEAST(5,(SELECT COUNT(*) FROM remediation_cases spread WHERE spread.vulnerability_key=c.vulnerability_key)-1)
    ))::integer"""


class RiskRepository:
    def _validate(self, values: dict[str, Any]) -> dict[str, Any]:
        clean = {k: v for k, v in values.items() if k in {*CONTEXT_VALUES, "owner", "tags"}}
        for key, allowed in CONTEXT_VALUES.items():
            if key in clean and clean[key] not in allowed:
                raise ValueError(f"Unsupported {key}.")
        if "tags" in clean:
            clean["tags"] = sorted({str(v).strip() for v in clean["tags"] if str(v).strip()})[:50]
        if "owner" in clean:
            clean["owner"] = str(clean["owner"] or "").strip()[:200] or None
        return clean

    def set_contexts(self, asset_ids: list[str], values: dict[str, Any], actor: str | None) -> dict[str, Any]:
        clean = self._validate(values)
        if not clean:
            raise ValueError("No context fields supplied.")
        updated: list[str] = []
        with db.connect() as conn:
            for asset_id in dict.fromkeys(asset_ids):
                if not conn.execute("SELECT 1 FROM asset_cards WHERE asset_id=%s", (asset_id,)).fetchone():
                    continue
                current = conn.execute("SELECT * FROM asset_contexts WHERE asset_id=%s", (asset_id,)).fetchone()
                merged: dict[str, Any] = {
                    "criticality": "medium",
                    "environment": "production",
                    "exposure": "internal",
                    "owner": None,
                    "tags": [],
                }
                if current:
                    merged.update(dict(current))
                    merged["tags"] = current.get("tags") or []
                merged.update(clean)
                conn.execute(
                    """INSERT INTO asset_contexts(asset_id,criticality,environment,exposure,owner,tags,updated_by)
                    VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(asset_id) DO UPDATE SET criticality=EXCLUDED.criticality,
                    environment=EXCLUDED.environment,exposure=EXCLUDED.exposure,owner=EXCLUDED.owner,tags=EXCLUDED.tags,
                    version=asset_contexts.version+1,updated_by=EXCLUDED.updated_by,updated_at=NOW()""",
                    (
                        asset_id,
                        merged["criticality"],
                        merged["environment"],
                        merged["exposure"],
                        merged["owner"],
                        json.dumps(merged["tags"]),
                        actor,
                    ),
                )
                conn.execute(
                    "INSERT INTO asset_context_events(asset_id,actor_username,changes_json) VALUES(%s,%s,%s)",
                    (asset_id, actor, json.dumps(clean)),
                )
                updated.append(asset_id)
        return {"updated_count": len(updated), "asset_ids": updated}

    def import_csv(self, text: str, actor: str | None) -> dict[str, Any]:
        reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
        matched = 0
        unmatched: list[str] = []
        errors: list[dict[str, Any]] = []
        with db.connect() as conn:
            cards = conn.execute("SELECT asset_id,ip_address,fqdn FROM asset_cards").fetchall()
        by_id = {str(r["asset_id"]).lower(): r["asset_id"] for r in cards}
        by_ip = {str(r["ip_address"]).lower(): r["asset_id"] for r in cards if r.get("ip_address")}
        by_fqdn = {str(r["fqdn"]).lower(): r["asset_id"] for r in cards if r.get("fqdn")}
        for line, row in enumerate(reader, 2):
            key = str(row.get("asset_id") or row.get("ip") or row.get("fqdn") or "").strip().lower()
            asset_id = by_id.get(key) or by_ip.get(key) or by_fqdn.get(key)
            if not asset_id:
                unmatched.append(key)
                continue
            try:
                values = {k: row[k].strip() for k in CONTEXT_VALUES if row.get(k)}
                if row.get("owner"):
                    values["owner"] = row["owner"]
                if row.get("tags") is not None:
                    values["tags"] = [v.strip() for v in row["tags"].split(",")]
                self.set_contexts([asset_id], values, actor)
                matched += 1
            except ValueError as exc:
                errors.append({"line": line, "message": str(exc)})
        return {"matched": matched, "unmatched": unmatched, "errors": errors}

    def queue(self, **filters: Any) -> dict[str, Any]:
        score = _risk_sql()
        clauses = ["c.status<>'resolved'"]
        params: list[Any] = []
        for key in ("owner", "environment", "criticality", "exposure"):
            if filters.get(key):
                clauses.append(f"COALESCE(x.{key},%s)=%s")
                params.extend(
                    (
                        {"owner": "", "environment": "production", "criticality": "medium", "exposure": "internal"}[
                            key
                        ],
                        filters[key],
                    )
                )
        if filters.get("tag"):
            clauses.append("COALESCE(x.tags,'[]'::jsonb) ? %s")
            params.append(filters["tag"])
        level = filters.get("level")
        if level:
            bounds = {"urgent": (80, 101), "high": (60, 80), "medium": (35, 60), "low": (0, 35)}[level]
            clauses.append(f"({score}) >= %s AND ({score}) < %s")
            params.extend(bounds)
        where = " AND ".join(clauses)
        limit = min(max(int(filters.get("limit", 50)), 1), 500)
        offset = max(int(filters.get("offset", 0)), 0)
        with db.connect() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) count FROM remediation_cases c LEFT JOIN asset_contexts x ON x.asset_id=c.asset_id WHERE {where}",
                params,
            ).fetchone()
            rows = conn.execute(
                f"""SELECT c.*,card.display_name,card.ip_address,card.fqdn,
                COALESCE(x.criticality,'medium') criticality,COALESCE(x.environment,'production') environment,
                COALESCE(x.exposure,'internal') exposure,x.owner,COALESCE(x.tags,'[]'::jsonb) tags,{score} risk_score
                ,EXISTS(SELECT 1 FROM vulnerability_passports vp WHERE vp.internal_id=c.passport_internal_id
                  AND LOWER(COALESCE(vp.raw_detail_json,'') || COALESCE(vp.metrics_json,'') || COALESCE(vp.raw_record_json,''))
                  SIMILAR TO '%(exploit|exploited|эксплуат)%') exploitation_evidence
                ,(SELECT COUNT(*) FROM remediation_cases spread WHERE spread.vulnerability_key=c.vulnerability_key)::int affected_hosts
                FROM remediation_cases c JOIN asset_cards card ON card.asset_id=c.asset_id LEFT JOIN asset_contexts x ON x.asset_id=c.asset_id
                WHERE {where} ORDER BY risk_score DESC,c.due_at NULLS LAST,c.case_id LIMIT %s OFFSET %s""",
                (*params, limit, offset),
            ).fetchall()
        result = []
        for raw in rows:
            row = dict(raw)
            value = row["risk_score"]
            row["risk_level"] = (
                "urgent" if value >= 80 else "high" if value >= 60 else "medium" if value >= 35 else "low"
            )
            factors = [
                f"criticality:{row['criticality']}",
                f"exposure:{row['exposure']}",
                f"severity:{row['severity']}",
            ]
            if row.get("exploitation_evidence"):
                factors.append("exploitation:local-passport")
            if int(row.get("affected_hosts") or 0) > 1:
                factors.append(f"affected_hosts:{row['affected_hosts']}")
            if row.get("due_at") and str(row["status"]) in {"open", "in_progress"}:
                factors.append("sla:tracked")
            row.update(risk_factors=factors, risk_model_version=MODEL_VERSION, risk_explanation=", ".join(factors))
            for key in ("due_at", "first_seen_at", "last_seen_at", "created_at", "updated_at"):
                row[key] = row[key].isoformat() if hasattr(row.get(key), "isoformat") else row.get(key)
            if row.get("cvss_score") is not None:
                row["cvss_score"] = float(row["cvss_score"])
            result.append(row)
        return {
            "rows": result,
            "total": int(total_row["count"] if total_row else 0),
            "limit": limit,
            "offset": offset,
            "risk_model_version": MODEL_VERSION,
        }

    def summary(self) -> dict[str, Any]:
        rows = self.queue(limit=500, offset=0)["rows"]
        counts = {k: sum(r["risk_level"] == k for r in rows) for k in ("urgent", "high", "medium", "low")}
        return {**counts, "total": sum(counts.values()), "risk_model_version": MODEL_VERSION}

    def create_campaign(self, values: dict[str, Any], actor: str | None) -> dict[str, Any]:
        campaign_id = str(uuid.uuid4())
        case_ids = list(dict.fromkeys(values["case_ids"]))
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO remediation_campaigns(campaign_id,name,assignee,due_at,comment,created_by)
                VALUES(%s,%s,%s,%s,%s,%s) RETURNING *""",
                (
                    campaign_id,
                    values["name"],
                    values.get("assignee"),
                    values.get("due_at"),
                    values.get("comment"),
                    actor,
                ),
            ).fetchone()
            for case_id in case_ids:
                conn.execute(
                    "INSERT INTO remediation_campaign_cases(campaign_id,case_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",
                    (campaign_id, case_id),
                )
            conn.execute(
                "INSERT INTO remediation_campaign_events(campaign_id,actor_username,event_type,changes_json) VALUES(%s,%s,'created',%s)",
                (campaign_id, actor, json.dumps({"case_ids": case_ids})),
            )
            if values.get("assignee") or values.get("due_at"):
                conn.execute(
                    """UPDATE remediation_cases c SET assignee=COALESCE(%s,c.assignee),due_at=COALESCE(%s,c.due_at),manual_due=CASE WHEN %s IS NULL THEN manual_due ELSE TRUE END,version=version+1,updated_at=NOW()
                    FROM remediation_campaign_cases cc WHERE cc.campaign_id=%s AND cc.case_id=c.case_id""",
                    (values.get("assignee"), values.get("due_at"), values.get("due_at"), campaign_id),
                )
        assert row is not None
        return self.get_campaign(campaign_id) or dict(row)

    def list_campaigns(self) -> dict[str, Any]:
        with db.connect() as conn:
            rows = conn.execute(self._campaign_sql() + " GROUP BY c.campaign_id ORDER BY c.created_at DESC").fetchall()
        return {"rows": [self._campaign(dict(r)) for r in rows], "total": len(rows)}

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(
                self._campaign_sql() + " WHERE c.campaign_id=%s GROUP BY c.campaign_id", (campaign_id,)
            ).fetchone()
            cases = (
                conn.execute(
                    "SELECT rc.* FROM remediation_campaign_cases cc JOIN remediation_cases rc ON rc.case_id=cc.case_id WHERE cc.campaign_id=%s ORDER BY rc.due_at NULLS LAST",
                    (campaign_id,),
                ).fetchall()
                if row
                else []
            )
            events = (
                conn.execute(
                    "SELECT * FROM remediation_campaign_events WHERE campaign_id=%s ORDER BY created_at DESC,event_id DESC",
                    (campaign_id,),
                ).fetchall()
                if row else []
            )
        if not row:
            return None
        result = self._campaign(dict(row))
        result["cases"] = [
            {**dict(value), **{key: value[key].isoformat() for key in (
                "due_at", "first_seen_at", "last_seen_at", "resolved_at", "created_at", "updated_at"
            ) if hasattr(value.get(key), "isoformat")}}
            for value in cases
        ]
        result["events"] = [
            {**dict(value), "created_at": value["created_at"].isoformat() if hasattr(value.get("created_at"), "isoformat") else value.get("created_at"),
             "changes": value.get("changes_json") or {}}
            for value in events
        ]
        return result

    def update_campaign(self, campaign_id: str, values: dict[str, Any], actor: str | None) -> dict[str, Any] | None:
        allowed = {"name", "assignee", "due_at", "comment", "status"}
        clean = {k: v for k, v in values.items() if k in allowed}
        if not clean:
            return self.get_campaign(campaign_id)
        assignments = []
        params = []
        for key, value in clean.items():
            assignments.append(f"{key}=%s")
            params.append(value)
        with db.connect() as conn:
            row = conn.execute(
                f"UPDATE remediation_campaigns SET {','.join(assignments)},version=version+1,updated_at=NOW() WHERE campaign_id=%s RETURNING campaign_id",
                (*params, campaign_id),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "INSERT INTO remediation_campaign_events(campaign_id,actor_username,event_type,changes_json) VALUES(%s,%s,'updated',%s)",
                (campaign_id, actor, json.dumps(clean)),
            )
        return self.get_campaign(campaign_id)

    def verification_targets(self, campaign_id: str, actor: str | None) -> dict[str, Any] | None:
        with db.connect() as conn:
            exists = conn.execute("SELECT 1 FROM remediation_campaigns WHERE campaign_id=%s", (campaign_id,)).fetchone()
            if not exists:
                return None
            rows = conn.execute(
                """SELECT DISTINCT rc.asset_id FROM remediation_campaign_cases cc JOIN remediation_cases rc ON rc.case_id=cc.case_id
                WHERE cc.campaign_id=%s AND rc.status IN ('open','in_progress') ORDER BY rc.asset_id""",
                (campaign_id,),
            ).fetchall()
            conn.execute(
                "INSERT INTO remediation_campaign_events(campaign_id,actor_username,event_type,changes_json) VALUES(%s,%s,'verification_requested',%s)",
                (campaign_id, actor, json.dumps({"asset_ids": [r["asset_id"] for r in rows]})),
            )
        return {
            "campaign_id": campaign_id,
            "asset_ids": [r["asset_id"] for r in rows],
            "next": "Start refresh scans with POST /api/asset-cards/{asset_id}/refresh-scan",
        }

    def _campaign_sql(self) -> str:
        return """SELECT c.*,COUNT(cc.case_id)::int total,
          COUNT(*) FILTER(WHERE rc.status='in_progress')::int in_progress,
          COUNT(*) FILTER(WHERE rc.status IN ('open','in_progress') AND rc.due_at<NOW())::int overdue,
          COUNT(*) FILTER(WHERE rc.status='risk_accepted')::int risk_accepted,
          COUNT(*) FILTER(WHERE rc.status IN ('open','in_progress'))::int awaiting_verification,
          COUNT(*) FILTER(WHERE rc.status='resolved')::int resolved
          FROM remediation_campaigns c LEFT JOIN remediation_campaign_cases cc ON cc.campaign_id=c.campaign_id
          LEFT JOIN remediation_cases rc ON rc.case_id=cc.case_id"""

    def _campaign(self, row: dict[str, Any]) -> dict[str, Any]:
        for key in ("due_at", "created_at", "updated_at"):
            row[key] = row[key].isoformat() if hasattr(row.get(key), "isoformat") else row.get(key)
        return row
