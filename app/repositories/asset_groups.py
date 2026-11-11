from __future__ import annotations

import builtins
import json
import uuid
from typing import Any

from ..persistence import codecs, connection, schema
from ..persistence.codecs import json_loads
from .asset_cards.cards import decode_asset_card_summary
from .asset_cards.queries import query_asset_cards_by_fields, validate_asset_query_tree


class AssetGroupRepository:
    def list(self) -> list[dict[str, Any]]:
        return list_asset_groups()

    def get(self, group_id: str) -> dict[str, Any] | None:
        return get_asset_group(group_id)

    def create(self, **values: Any) -> dict[str, Any]:
        return create_local_asset_group(**values)

    def update(self, group_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        return update_local_asset_group(group_id, changes)

    def archive(self, group_id: str) -> bool:
        return archive_local_asset_group(group_id)

    def preview(self, query: dict[str, Any], *, limit: int) -> dict[str, Any]:
        return preview_local_asset_group(query, limit=limit)

    def evaluate(self, group_id: str) -> dict[str, Any]:
        return evaluate_local_asset_group(group_id)

    def members(self, group_id: str, **pagination: Any) -> dict[str, Any]:
        return list_local_asset_group_members(group_id, **pagination)

    def member_ids(self, group_id: str) -> builtins.list[str]:
        return list_local_asset_group_member_ids(group_id)

    def set_override(self, group_id: str, asset_id: str, action: str, *, actor: str | None) -> dict[str, Any]:
        return set_local_asset_group_override(group_id, asset_id, action, actor=actor)

    def delete_override(self, group_id: str, asset_id: str) -> bool:
        return delete_local_asset_group_override(group_id, asset_id)

    def precheck_stats(self) -> dict[str, int]:
        return get_precheck_statistics()

    def precheck_runs(self, *, limit: int) -> dict[str, Any]:
        return list_precheck_false_runs(limit=limit)


def decode_asset_group(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["group_id"] = str(result["group_id"])
    if result.get("parent_id") is not None:
        result["parent_id"] = str(result["parent_id"])
    result["query"] = json_loads(result.pop("query_json", "{}"), {})
    return result


def list_asset_groups(*, include_archived: bool = False) -> list[dict[str, Any]]:
    schema.init_db()
    where = "" if include_archived else "WHERE archived_at IS NULL"
    with connection.connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM asset_groups {where} ORDER BY LOWER(name), group_id"
        ).fetchall()
    return [decode_asset_group(dict(row)) for row in rows]


def get_asset_group(group_id: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM asset_groups WHERE group_id = %s", (group_id,)).fetchone()
    return decode_asset_group(dict(row)) if row else None


def create_local_asset_group(
    *, name: str, description: str, parent_id: str | None, query: dict[str, Any], created_by: str | None,
) -> dict[str, Any]:
    validate_asset_query_tree(query)
    current = codecs.now_utc()
    group_id = str(uuid.uuid4())
    with connection.connect() as conn:
        candidate_parent = parent_id
        visited = {str(group_id)}
        while candidate_parent is not None:
            candidate_key = str(candidate_parent)
            if candidate_key in visited:
                raise ValueError("An asset group hierarchy cannot contain a cycle.")
            visited.add(candidate_key)
            parent = conn.execute(
                "SELECT parent_id FROM asset_groups WHERE group_id = %s AND archived_at IS NULL",
                (candidate_parent,),
            ).fetchone()
            if not parent:
                raise ValueError("Parent asset group not found.")
            candidate_parent = parent["parent_id"]
        row = conn.execute(
            """
            INSERT INTO asset_groups (
                group_id, parent_id, name, description, query_json, created_by, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (group_id, parent_id, name.strip(), description.strip(), json.dumps(query, ensure_ascii=False), created_by, current, current),
        ).fetchone()
    assert row is not None
    return decode_asset_group(dict(row))


def update_local_asset_group(group_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
    current = codecs.now_utc()
    updates: dict[str, Any] = {}
    if "name" in changes and changes["name"] is not None:
        updates["name"] = str(changes["name"]).strip()
    if "description" in changes and changes["description"] is not None:
        updates["description"] = str(changes["description"]).strip()
    if "parent_id" in changes:
        if changes["parent_id"] == group_id:
            raise ValueError("An asset group cannot be its own parent.")
        updates["parent_id"] = changes["parent_id"]
    if changes.get("query") is not None:
        validate_asset_query_tree(changes["query"])
        updates["query_json"] = json.dumps(changes["query"], ensure_ascii=False)
        updates["definition_version"] = "definition_version + 1"
        updates["status"] = "stale"
    if not updates:
        return get_asset_group(group_id)
    assignments = []
    values: list[Any] = []
    for key, value in updates.items():
        if key == "definition_version":
            assignments.append("definition_version = definition_version + 1")
        else:
            assignments.append(f"{key} = %s")
            values.append(value)
    assignments.append("updated_at = %s")
    values.extend([current, group_id])
    with connection.connect() as conn:
        candidate_parent = updates.get("parent_id")
        visited = {str(group_id)}
        while candidate_parent is not None:
            candidate_key = str(candidate_parent)
            if candidate_key in visited:
                raise ValueError("An asset group hierarchy cannot contain a cycle.")
            visited.add(candidate_key)
            parent = conn.execute(
                "SELECT parent_id FROM asset_groups WHERE group_id = %s AND archived_at IS NULL",
                (candidate_parent,),
            ).fetchone()
            if not parent:
                raise ValueError("Parent asset group not found.")
            candidate_parent = parent["parent_id"]
        row = conn.execute(
            f"UPDATE asset_groups SET {', '.join(assignments)} WHERE group_id = %s AND archived_at IS NULL RETURNING *",
            values,
        ).fetchone()
    return decode_asset_group(dict(row)) if row else None


def archive_local_asset_group(group_id: str) -> bool:
    current = codecs.now_utc()
    with connection.connect() as conn:
        result = conn.execute(
            "UPDATE asset_groups SET archived_at = %s, updated_at = %s WHERE group_id = %s AND archived_at IS NULL",
            (current, current, group_id),
        )
    return bool(result.rowcount)


def preview_local_asset_group(query: dict[str, Any], *, limit: int = 50) -> dict[str, Any]:
    return query_asset_cards_by_fields(query, limit=limit, offset=0)


def evaluate_local_asset_group(group_id: str) -> dict[str, Any]:
    group = get_asset_group(group_id)
    if not group or group.get("archived_at"):
        raise LookupError("Asset group not found.")
    evaluation_id = str(uuid.uuid4())
    started_at = codecs.now_utc()
    with connection.connect() as conn:
        conn.execute(
            """
            INSERT INTO asset_group_evaluations (
                evaluation_id, group_id, definition_version, status, started_at
            ) VALUES (%s, %s, %s, 'running', %s)
            """,
            (evaluation_id, group_id, group["definition_version"], started_at),
        )
        conn.execute(
            "UPDATE asset_groups SET status = 'evaluating', last_error = NULL, updated_at = %s WHERE group_id = %s",
            (started_at, group_id),
        )
    try:
        result = query_asset_cards_by_fields(group["query"], limit=50000, offset=0)
        rule_rows = {str(row["asset_id"]): row for row in result["rows"]}
        with connection.connect() as conn:
            overrides = conn.execute(
                "SELECT asset_id, action FROM asset_group_overrides WHERE group_id = %s",
                (group_id,),
            ).fetchall()
            for override in overrides:
                asset_id = str(override["asset_id"])
                if override["action"] == "exclude":
                    rule_rows.pop(asset_id, None)
                elif asset_id not in rule_rows:
                    card = conn.execute(
                        "SELECT * FROM asset_cards WHERE asset_id = %s",
                        (asset_id,),
                    ).fetchone()
                    if card:
                        rule_rows[asset_id] = {**decode_asset_card_summary(dict(card)), "matches": [], "membership_source": "manual_include"}
            current = codecs.now_utc()
            conn.execute("DELETE FROM asset_group_members WHERE group_id = %s", (group_id,))
            if rule_rows:
                with conn.cursor() as cursor:
                    cursor.executemany(
                        """
                        INSERT INTO asset_group_members (
                            group_id, asset_id, evaluation_id, membership_source, evidence_json, evaluated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        [
                            (
                                group_id,
                                asset_id,
                                evaluation_id,
                                row.get("membership_source") or "rule",
                                json.dumps(row.get("matches") or [], ensure_ascii=False, default=str),
                                current,
                            )
                            for asset_id, row in rule_rows.items()
                        ],
                    )
            counts = (len(rule_rows), int(result["indexed_cards"]), int(result["total_cards"]))
            conn.execute(
                """
                UPDATE asset_group_evaluations SET status = 'completed', matched_count = %s,
                    indexed_cards = %s, total_cards = %s, finished_at = %s
                WHERE evaluation_id = %s
                """,
                (*counts, current, evaluation_id),
            )
            conn.execute(
                """
                UPDATE asset_groups SET status = 'ready', member_count = %s, indexed_cards = %s,
                    total_cards = %s, last_evaluated_at = %s, last_error = NULL, updated_at = %s
                WHERE group_id = %s
                """,
                (*counts, current, current, group_id),
            )
        return {"evaluation_id": evaluation_id, "status": "completed", "member_count": counts[0], "indexed_cards": counts[1], "total_cards": counts[2]}
    except Exception as exc:
        current = codecs.now_utc()
        with connection.connect() as conn:
            conn.execute(
                "UPDATE asset_group_evaluations SET status = 'failed', error = %s, finished_at = %s WHERE evaluation_id = %s",
                (str(exc)[:2000], current, evaluation_id),
            )
            conn.execute(
                "UPDATE asset_groups SET status = 'error', last_error = %s, updated_at = %s WHERE group_id = %s",
                (str(exc)[:2000], current, group_id),
            )
        raise


def list_local_asset_group_members(group_id: str, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    with connection.connect() as conn:
        total_row = conn.execute("SELECT COUNT(*) AS count FROM asset_group_members WHERE group_id = %s", (group_id,)).fetchone()
        assert total_row is not None
        total = total_row["count"]
        rows = conn.execute(
            """
            SELECT card.asset_id, card.display_name, card.ip_address, card.fqdn, card.hostname,
                   card.os_name, card.vulnerability_level, card.last_seen, member.membership_source,
                   member.evidence_json, override.action AS override_action
            FROM asset_group_members member
            JOIN asset_cards card ON card.asset_id = member.asset_id
            LEFT JOIN asset_group_overrides override ON override.group_id = member.group_id AND override.asset_id = member.asset_id
            WHERE member.group_id = %s
            ORDER BY LOWER(card.display_name) NULLS LAST, card.asset_id
            LIMIT %s OFFSET %s
            """,
            (group_id, limit, offset),
        ).fetchall()
    decoded = []
    for row in rows:
        item = dict(row)
        item["matches"] = json_loads(item.pop("evidence_json", "[]"), [])
        decoded.append(item)
    return {"rows": decoded, "total": int(total or 0), "limit": limit, "offset": offset}


def list_local_asset_group_member_ids(group_id: str) -> list[str]:
    schema.init_db()
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT member.asset_id
            FROM asset_group_members member
            JOIN asset_cards card ON card.asset_id = member.asset_id
            WHERE member.group_id = %s
            ORDER BY LOWER(card.display_name) NULLS LAST, member.asset_id
            """,
            (group_id,),
        ).fetchall()
    return [str(row["asset_id"]) for row in rows]


def set_local_asset_group_override(group_id: str, asset_id: str, action: str, *, actor: str | None) -> dict[str, Any]:
    if action not in {"include", "exclude"}:
        raise ValueError("Unsupported asset group override action.")
    with connection.connect() as conn:
        asset = conn.execute("SELECT asset_id FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
        if not asset:
            raise LookupError("Asset card not found.")
        row = conn.execute(
            """
            INSERT INTO asset_group_overrides (group_id, asset_id, action, created_by)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (group_id, asset_id) DO UPDATE SET action = EXCLUDED.action,
                created_by = EXCLUDED.created_by, created_at = NOW()
            RETURNING *
            """,
            (group_id, asset_id, action, actor),
        ).fetchone()
        conn.execute("UPDATE asset_groups SET status = 'stale', updated_at = NOW() WHERE group_id = %s", (group_id,))
    assert row is not None
    return dict(row)


def delete_local_asset_group_override(group_id: str, asset_id: str) -> bool:
    with connection.connect() as conn:
        result = conn.execute("DELETE FROM asset_group_overrides WHERE group_id = %s AND asset_id = %s", (group_id, asset_id))
        conn.execute("UPDATE asset_groups SET status = 'stale', updated_at = NOW() WHERE group_id = %s", (group_id,))
    return bool(result.rowcount)


def get_precheck_statistics() -> dict[str, int]:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS runs,
              COALESCE(SUM(CASE WHEN last_remote_response_json::jsonb ? 'successful_target_count'
                THEN (last_remote_response_json::jsonb ->> 'successful_target_count')::int ELSE 0 END), 0) AS success,
              COALESCE(SUM(CASE WHEN last_remote_response_json::jsonb ? 'false_target_count'
                THEN (last_remote_response_json::jsonb ->> 'false_target_count')::int ELSE 0 END), 0) AS false,
              COUNT(*) FILTER (WHERE NOT (last_remote_response_json::jsonb ? 'successful_target_count')) AS unknown
            FROM scan_tasks
            WHERE status IN ('precheck_finished', 'precheck_failed', 'precheck_validation_failed')
            """
        ).fetchone()
    return {key: int((row or {}).get(key) or 0) for key in ("runs", "success", "false", "unknown")}


def list_precheck_false_runs(*, limit: int = 20) -> dict[str, Any]:
    schema.init_db()
    limit = max(1, min(100, int(limit)))
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT mp_task_id, name, status, updated_at, last_remote_response_json
            FROM scan_tasks
            WHERE status IN ('precheck_finished', 'precheck_failed')
              AND last_remote_response_json::jsonb ? 'false_targets'
              AND jsonb_array_length(last_remote_response_json::jsonb -> 'false_targets') > 0
            ORDER BY updated_at DESC, id DESC
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    decoded = []
    for raw in rows:
        row = dict(raw)
        result = json_loads(row.pop("last_remote_response_json", "{}"), {})
        false_targets = result.get("false_targets") if isinstance(result, dict) else []
        decoded.append({
            **row,
            "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else row.get("updated_at"),
            "false_targets": false_targets if isinstance(false_targets, list) else [],
            "false_target_count": int(result.get("false_target_count") or len(false_targets or [])),
            "audit_task_id": result.get("audit_task_id"),
            "retryable": bool(result.get("audit_task_id") and false_targets),
        })
    return {"rows": decoded, "total": len(decoded)}
