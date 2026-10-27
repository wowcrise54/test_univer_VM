from __future__ import annotations

import builtins
import json
import uuid
from datetime import datetime
from typing import Any

from .. import db
from ..domain.errors import DomainError

PRESET_SCALAR_FIELDS = (
    "name", "description", "os_family", "scope_id", "profile_id", "credential_id",
    "credential_transport", "host_discovery_enabled", "host_discovery_profile_id",
    "is_fqdn_priority", "time_zone", "max_groups_per_task", "max_active_tasks", "name_prefix",
)
PRESET_JSON_FIELDS = (
    "agent_ids", "trigger_parameters", "denied_scan_settings", "start_options", "allowed_asset_groups",
)

_PRESET_SELECT = """
    SELECT p.preset_id::text AS preset_id, p.name, p.description, p.os_family, p.scope_id, p.profile_id,
           p.credential_id, p.credential_transport, p.agent_ids, p.host_discovery_enabled,
           p.host_discovery_profile_id, p.is_fqdn_priority, p.time_zone, p.trigger_parameters,
           p.denied_scan_settings, p.start_options, p.allowed_asset_groups, p.max_groups_per_task,
           p.max_active_tasks, p.name_prefix, p.is_active, p.version, p.created_by, p.updated_by,
           p.created_at, p.updated_at,
           COALESCE(array_agg(r.role_id ORDER BY r.role_id) FILTER (WHERE r.role_id IS NOT NULL),
                    ARRAY[]::bigint[]) AS role_ids
    FROM scan_task_presets p
    LEFT JOIN scan_task_preset_roles r ON r.preset_id = p.preset_id
"""
_PRESET_GROUP_BY = " GROUP BY p.preset_id"


def _serialize(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["role_ids"] = [int(value) for value in result.get("role_ids") or []]
    for key in ("created_at", "updated_at"):
        value = result.get(key)
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result


def _json_param(value: Any) -> str | None:
    return None if value is None else json.dumps(value, ensure_ascii=False)


class TaskPresetRepository:
    def list(self, *, role_ids: builtins.list[int] | None, include_archived: bool = False) -> builtins.list[dict[str, Any]]:
        """Return presets visible to ``role_ids``; ``None`` means every preset."""
        clauses: builtins.list[str] = []
        params: builtins.list[Any] = []
        if not include_archived:
            clauses.append("p.is_active")
        if role_ids is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM scan_task_preset_roles access "
                "WHERE access.preset_id = p.preset_id AND access.role_id = ANY(%s))"
            )
            params.append(role_ids)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with db.connect() as conn:
            rows = conn.execute(
                f"{_PRESET_SELECT}{where}{_PRESET_GROUP_BY} ORDER BY p.os_family, lower(p.name), p.preset_id",
                params,
            ).fetchall()
        return [_serialize(row) for row in rows]

    def get(self, preset_id: str) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(f"{_PRESET_SELECT} WHERE p.preset_id = %s{_PRESET_GROUP_BY}", (preset_id,)).fetchone()
        return _serialize(row) if row else None

    def existing_role_ids(self, role_ids: builtins.list[int]) -> set[int]:
        if not role_ids:
            return set()
        with db.connect() as conn:
            rows = conn.execute("SELECT id FROM app_roles WHERE id = ANY(%s)", (role_ids,)).fetchall()
        return {int(row["id"]) for row in rows}

    def role_ids_by_keys(self, role_keys: builtins.list[str]) -> builtins.list[int]:
        if not role_keys:
            return []
        with db.connect() as conn:
            rows = conn.execute("SELECT id FROM app_roles WHERE role_key = ANY(%s) ORDER BY id", (role_keys,)).fetchall()
        return [int(row["id"]) for row in rows]

    def create(self, values: dict[str, Any], role_ids: builtins.list[int], *, actor: str | None) -> dict[str, Any]:
        preset_id = str(uuid.uuid4())
        columns = ["preset_id", *PRESET_SCALAR_FIELDS, *PRESET_JSON_FIELDS, "created_by", "updated_by"]
        placeholders = ["%s"] * (1 + len(PRESET_SCALAR_FIELDS)) + ["%s::jsonb"] * len(PRESET_JSON_FIELDS) + ["%s", "%s"]
        params = [
            preset_id,
            *(values.get(key) for key in PRESET_SCALAR_FIELDS),
            *(_json_param(values.get(key)) for key in PRESET_JSON_FIELDS),
            actor,
            actor,
        ]
        with db.connect() as conn:
            conn.execute(
                f"INSERT INTO scan_task_presets ({', '.join(columns)}) VALUES ({', '.join(placeholders)})",
                params,
            )
            self._replace_roles(conn, preset_id, role_ids)
        created = self.get(preset_id)
        assert created is not None
        return created

    def update(
        self, preset_id: str, values: dict[str, Any], role_ids: builtins.list[int], *,
        expected_version: int, actor: str | None,
    ) -> dict[str, Any] | None:
        assignments = [f"{key}=%s" for key in PRESET_SCALAR_FIELDS] + [f"{key}=%s::jsonb" for key in PRESET_JSON_FIELDS]
        params = [
            *(values.get(key) for key in PRESET_SCALAR_FIELDS),
            *(_json_param(values.get(key)) for key in PRESET_JSON_FIELDS),
        ]
        with db.connect() as conn:
            self._lock_version(conn, preset_id, expected_version)
            conn.execute(
                f"UPDATE scan_task_presets SET {', '.join(assignments)}, version=version+1, "
                "updated_by=%s, updated_at=NOW() WHERE preset_id=%s",
                (*params, actor, preset_id),
            )
            self._replace_roles(conn, preset_id, role_ids)
        return self.get(preset_id)

    def archive(self, preset_id: str, *, expected_version: int, actor: str | None) -> dict[str, Any] | None:
        with db.connect() as conn:
            self._lock_version(conn, preset_id, expected_version)
            conn.execute(
                "UPDATE scan_task_presets SET is_active=FALSE, version=version+1, updated_by=%s, updated_at=NOW() "
                "WHERE preset_id=%s",
                (actor, preset_id),
            )
        return self.get(preset_id)

    @staticmethod
    def _lock_version(conn: Any, preset_id: str, expected_version: int) -> None:
        current = conn.execute(
            "SELECT version, is_active FROM scan_task_presets WHERE preset_id=%s FOR UPDATE", (preset_id,),
        ).fetchone()
        if not current:
            raise LookupError("Task preset not found.")
        if not current["is_active"]:
            raise DomainError("PRESET_INACTIVE", "Пресет в архиве и не может быть изменён.", status_code=409,
                              context={"preset_id": preset_id})
        if int(current["version"]) != expected_version:
            raise DomainError(
                "VERSION_CONFLICT", "Пресет изменён другим пользователем. Обновите данные и повторите.",
                status_code=409, context={"preset_id": preset_id, "current_version": int(current["version"])},
            )

    @staticmethod
    def _replace_roles(conn: Any, preset_id: str, role_ids: builtins.list[int]) -> None:
        conn.execute("DELETE FROM scan_task_preset_roles WHERE preset_id=%s", (preset_id,))
        if role_ids:
            conn.execute(
                "INSERT INTO scan_task_preset_roles (preset_id, role_id) "
                "SELECT %s, role_id FROM unnest(%s::bigint[]) AS role_id ON CONFLICT DO NOTHING",
                (preset_id, role_ids),
            )

    # Team tasks: scanner tasks created from presets, scoped by the preset roles.

    def list_team_tasks(self, *, role_ids: builtins.list[int] | None) -> builtins.list[dict[str, Any]]:
        params: builtins.list[Any] = []
        access = ""
        if role_ids is not None:
            access = (
                " AND EXISTS (SELECT 1 FROM scan_task_preset_roles access "
                "WHERE access.preset_id = t.preset_id AND access.role_id = ANY(%s))"
            )
            params.append(role_ids)
        with db.connect() as conn:
            rows = conn.execute(
                f"""SELECT t.*, t.preset_id::text AS preset_id, p.name AS preset_name, p.os_family,
                           p.is_active AS preset_is_active, p.allowed_asset_groups
                    FROM scan_tasks t
                    JOIN scan_task_presets p ON p.preset_id = t.preset_id
                    WHERE t.deleted_at IS NULL{access}
                    ORDER BY t.updated_at DESC, t.id DESC""",
                params,
            ).fetchall()
            task_ids = [str(row["mp_task_id"]) for row in rows]
            runs = conn.execute(
                """SELECT DISTINCT ON (mp_task_id) mp_task_id, run_id, status, stage, message, error,
                          created_at, finished_at
                   FROM scan_postprocess_runs WHERE mp_task_id = ANY(%s)
                   ORDER BY mp_task_id, created_at DESC""",
                (task_ids,),
            ).fetchall() if task_ids else []
        latest = {str(run["mp_task_id"]): dict(run) for run in runs}
        result = []
        for row in rows:
            task = db._decode_scan_task(dict(row))
            task["postprocess"] = latest.get(str(task["mp_task_id"]))
            result.append(task)
        return result

    def get_team_task(self, task_id: str, *, role_ids: builtins.list[int] | None) -> dict[str, Any] | None:
        params: builtins.list[Any] = [task_id]
        access = ""
        if role_ids is not None:
            access = (
                " AND EXISTS (SELECT 1 FROM scan_task_preset_roles access "
                "WHERE access.preset_id = t.preset_id AND access.role_id = ANY(%s))"
            )
            params.append(role_ids)
        with db.connect() as conn:
            row = conn.execute(
                f"""SELECT t.*, t.preset_id::text AS preset_id, p.name AS preset_name, p.os_family,
                           p.is_active AS preset_is_active
                    FROM scan_tasks t
                    JOIN scan_task_presets p ON p.preset_id = t.preset_id
                    WHERE t.mp_task_id = %s AND t.deleted_at IS NULL{access}""",
                params,
            ).fetchone()
        return db._decode_scan_task(dict(row)) if row else None

    def operation_by_key(self, idempotency_key: str) -> dict[str, Any] | None:
        return db.get_operation_by_idempotency_key(idempotency_key)

    def register_operation(self, operation_id: str, **values: Any) -> dict[str, Any]:
        return db.register_operation(operation_id, **values)

    def record_task(
        self, task_id: str, payload: dict[str, Any], *, status: str, remote_response: dict[str, Any] | None,
    ) -> dict[str, Any]:
        return db.record_scan_task(mp_task_id=task_id, payload=payload, status=status, remote_response=remote_response)

    def attach_task(
        self, task_id: str, *, preset_id: str, preset_version: int,
        asset_groups: builtins.list[dict[str, Any]], actor: str | None, targets: builtins.list[str] | None = None,
    ) -> None:
        with db.connect() as conn:
            conn.execute(
                """UPDATE scan_tasks SET preset_id=%s, preset_version=%s, preset_asset_groups=%s::jsonb,
                          preset_targets=%s::jsonb, created_by=COALESCE(created_by, %s)
                   WHERE mp_task_id=%s""",
                (preset_id, preset_version, _json_param(asset_groups), _json_param(targets or []), actor, task_id),
            )

    def count_active_tasks(self, preset_id: str, *, exclude_task_id: str | None = None) -> int:
        with db.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(DISTINCT t.mp_task_id) AS count
                   FROM scan_tasks t
                   JOIN scan_postprocess_runs run ON run.mp_task_id = t.mp_task_id
                   WHERE t.preset_id = %s AND t.deleted_at IS NULL AND run.status = ANY(%s)
                     AND t.mp_task_id IS DISTINCT FROM %s""",
                (preset_id, sorted(db.SCAN_POSTPROCESS_ACTIVE_STATUSES), exclude_task_id),
            ).fetchone()
        return int(row["count"]) if row else 0
