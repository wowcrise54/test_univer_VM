"""Repository for scan task rows: registration, status transitions, deletion, and listing."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection
from .postprocess import decode_scan_postprocess_run


def record_scan_task(
    *,
    mp_task_id: str,
    payload: dict[str, Any],
    status: str,
    remote_response: dict[str, Any] | None = None,
    parent_task_id: str | None = None,
) -> dict[str, Any]:
    current = codecs.now_utc()
    include = payload.get("include")
    if not isinstance(include, dict):
        include = {}
    exclude = payload.get("exclude")
    if not isinstance(exclude, dict):
        exclude = {}
    agents = payload.get("agents")
    if not isinstance(agents, dict):
        agents = {}
    host_discovery = payload.get("hostDiscovery")
    if not isinstance(host_discovery, dict):
        host_discovery = {}
    with connection.connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_tasks (
                mp_task_id, name, description, scope_id, profile_id, agent_ids_json, credential_id,
                include_targets_json, exclude_targets_json, host_discovery_enabled,
                host_discovery_profile_id, payload_json, status, last_remote_response_json,
                created_at, updated_at, parent_task_id
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(mp_task_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                scope_id = EXCLUDED.scope_id,
                profile_id = EXCLUDED.profile_id,
                agent_ids_json = EXCLUDED.agent_ids_json,
                credential_id = EXCLUDED.credential_id,
                include_targets_json = EXCLUDED.include_targets_json,
                exclude_targets_json = EXCLUDED.exclude_targets_json,
                host_discovery_enabled = EXCLUDED.host_discovery_enabled,
                host_discovery_profile_id = EXCLUDED.host_discovery_profile_id,
                payload_json = EXCLUDED.payload_json,
                status = EXCLUDED.status,
                last_remote_response_json = EXCLUDED.last_remote_response_json,
                updated_at = EXCLUDED.updated_at,
                parent_task_id = COALESCE(EXCLUDED.parent_task_id, scan_tasks.parent_task_id),
                deleted_at = NULL
            """,
            (
                mp_task_id,
                payload.get("name", mp_task_id),
                payload.get("description", ""),
                payload.get("scope"),
                payload.get("profile"),
                json.dumps(agents.get("agentIds", []), ensure_ascii=False),
                _credential_id_from_payload(payload),
                json.dumps(include.get("targets", []), ensure_ascii=False),
                json.dumps(exclude.get("targets", []), ensure_ascii=False),
                bool(host_discovery.get("enabled")),
                host_discovery.get("profile"),
                json.dumps(payload, ensure_ascii=False),
                status,
                json.dumps(remote_response or {}, ensure_ascii=False),
                current,
                current,
                parent_task_id,
            ),
        )
    return get_scan_task(mp_task_id) or {}


def update_scan_task_status(mp_task_id: str, status: str, remote_response: dict[str, Any] | None = None) -> None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        conn.execute(
            """
            UPDATE scan_tasks
            SET status = %s, last_remote_response_json = %s, updated_at = %s
            WHERE mp_task_id = %s
            """,
            (status, json.dumps(remote_response or {}, ensure_ascii=False), current, mp_task_id),
        )


def mark_scan_task_deleted(mp_task_id: str, remote_response: dict[str, Any] | None = None) -> None:
    current = codecs.now_utc()
    with connection.connect() as conn:
        conn.execute(
            """
            UPDATE scan_tasks
            SET status = 'deleted', deleted_at = %s, updated_at = %s, last_remote_response_json = %s
            WHERE mp_task_id = %s
            """,
            (current, current, json.dumps(remote_response or {}, ensure_ascii=False), mp_task_id),
        )


def delete_scan_task(mp_task_id: str) -> None:
    with connection.connect() as conn:
        conn.execute("DELETE FROM scan_tasks WHERE mp_task_id = %s", (mp_task_id,))


def list_child_scan_task_ids(parent_task_id: str) -> list[str]:
    """Precheck tasks created for an audit task that still exist in MP VM."""
    with connection.connect() as conn:
        rows = conn.execute(
            "SELECT mp_task_id FROM scan_tasks WHERE parent_task_id = %s AND deleted_at IS NULL ORDER BY id",
            (parent_task_id,),
        ).fetchall()
    return [str(row["mp_task_id"]) for row in rows]


def mark_scan_task_removed(mp_task_id: str) -> None:
    """The task is gone from MP VM; keep its local result (e.g. failed targets for a retry)."""
    with connection.connect() as conn:
        conn.execute(
            "UPDATE scan_tasks SET deleted_at = %s WHERE mp_task_id = %s AND deleted_at IS NULL",
            (codecs.now_utc(), mp_task_id),
        )


def delete_child_scan_tasks(parent_task_id: str) -> None:
    with connection.connect() as conn:
        conn.execute("DELETE FROM scan_tasks WHERE parent_task_id = %s", (parent_task_id,))


def list_scan_tasks() -> list[dict[str, Any]]:
    with connection.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_tasks WHERE deleted_at IS NULL ORDER BY updated_at DESC, id DESC"
        ).fetchall()
        postprocess_rows = conn.execute(
            """
            SELECT DISTINCT ON (mp_task_id) *
            FROM scan_postprocess_runs
            ORDER BY mp_task_id, created_at DESC
            """
        ).fetchall()
    latest = {str(row["mp_task_id"]): decode_scan_postprocess_run(dict(row)) for row in postprocess_rows}
    result = [_decode_scan_task(dict(row)) for row in rows]
    for task in result:
        task["postprocess"] = latest.get(str(task.get("mp_task_id")))
    return result


def get_scan_task(mp_task_id: str) -> dict[str, Any] | None:
    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM scan_tasks WHERE mp_task_id = %s", (mp_task_id,)).fetchone()
    return _decode_scan_task(dict(row)) if row else None


def _decode_scan_task(row: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "agent_ids_json",
        "include_targets_json",
        "exclude_targets_json",
        "payload_json",
        "last_remote_response_json",
    ):
        decoded_key = key.replace("_json", "")
        try:
            row[decoded_key] = json.loads(row.get(key) or "{}")
        except json.JSONDecodeError:
            row[decoded_key] = None
    return row


def _credential_id_from_payload(payload: dict[str, Any]) -> str | None:
    transports = payload.get("overrides", {}).get("transports", {})
    credential_paths = (
        ("windows", "wmi_and_rpc_and_re"),
        ("terminal", "ssh"),
    )
    for transport, protocol in credential_paths:
        try:
            return transports[transport][protocol]["connection"]["auth"]["ref_value"]
        except (KeyError, TypeError):
            continue
    return None
