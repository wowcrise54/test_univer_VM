from __future__ import annotations

import psycopg
import pytest

from app import db
from app.domain.errors import DomainError
from app.mpvm_client import build_scanner_task_payload
from app.repositories.task_presets import TaskPresetRepository
from app.services.task_presets import TaskPresetService
from app.services.team_tasks import TeamTasksService


def _role_id(key: str) -> int:
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (key,)).fetchone()
    assert row is not None
    return int(row["id"])


def _values(name: str, os_family: str = "windows", **overrides):
    values = {
        "name": name, "description": "", "os_family": os_family, "scope_id": "scope-1",
        "profile_id": "profile-audit", "credential_id": None,
        "credential_transport": "ssh" if os_family == "linux" else "windows", "agent_ids": ["agent-1"],
        "host_discovery_enabled": False, "host_discovery_profile_id": None, "is_fqdn_priority": True,
        "time_zone": "+05:00", "trigger_parameters": None, "denied_scan_settings": None,
        "start_options": {"precheck_enabled": True}, "allowed_asset_groups": [{"id": f"{name}-group", "name": name}],
        "max_groups_per_task": 3, "max_active_tasks": 2, "name_prefix": "",
    }
    values.update(overrides)
    return values


def _engineer(key: str) -> dict:
    return {"username": f"{key}.user", "roles": [{"id": _role_id(key), "key": key}]}


def test_engineer_roles_are_seeded_with_team_permissions(test_db):
    with db.connect() as conn:
        rows = conn.execute(
            """SELECT r.role_key, r.is_system, array_agg(rp.permission_key ORDER BY rp.permission_key) AS perms
               FROM app_roles r JOIN app_role_permissions rp ON rp.role_id=r.id
               WHERE r.role_key IN ('engineer_windows', 'engineer_linux') GROUP BY r.role_key, r.is_system"""
        ).fetchall()
    assert {row["role_key"] for row in rows} == {"engineer_windows", "engineer_linux"}
    for row in rows:
        assert row["is_system"] is True
        assert "tasks.team" in row["perms"] and "tasks.execute" not in row["perms"]


def test_preset_crud_versioning_and_role_scoping(test_db):
    repository = TaskPresetRepository()
    service = TaskPresetService(repository)
    windows, linux = _role_id("engineer_windows"), _role_id("engineer_linux")

    win = service.create(_values("Windows audit"), [windows], actor="admin")
    lin = service.create(_values("Linux audit", "linux"), [linux], actor="admin")
    assert win["version"] == 1 and win["role_ids"] == [windows]
    assert win["agent_ids"] == ["agent-1"] and win["start_options"] == {"precheck_enabled": True}
    assert win["trigger_parameters"] is None and win["created_by"] == "admin"

    with pytest.raises(psycopg.errors.UniqueViolation):
        service.create(_values("windows AUDIT"), [windows], actor="admin")

    assert [row["name"] for row in repository.list(role_ids=[windows])] == ["Windows audit"]
    assert {row["name"] for row in repository.list(role_ids=None)} == {"Windows audit", "Linux audit"}

    updated = service.update(win["preset_id"], _values("Windows audit", max_active_tasks=None), [windows, linux],
                             expected_version=1, actor="admin2")
    assert updated["version"] == 2 and updated["max_active_tasks"] is None
    assert updated["role_ids"] == sorted([windows, linux]) and updated["updated_by"] == "admin2"
    with pytest.raises(DomainError) as conflict:
        service.update(win["preset_id"], _values("Windows audit"), [windows], expected_version=1, actor="admin")
    assert conflict.value.code == "VERSION_CONFLICT" and conflict.value.context["current_version"] == 2

    archived = service.archive(lin["preset_id"], expected_version=1, actor="admin")
    assert archived["is_active"] is False
    assert [row["name"] for row in repository.list(role_ids=[linux])] == ["Windows audit"]
    assert len(repository.list(role_ids=None, include_archived=True)) == 2
    with pytest.raises(DomainError) as inactive:
        service.archive(lin["preset_id"], expected_version=2, actor="admin")
    assert inactive.value.code == "PRESET_INACTIVE"
    # The archived name is free again.
    service.create(_values("Linux audit", "linux"), [linux], actor="admin")
    with pytest.raises(LookupError):
        service.archive("00000000-0000-0000-0000-000000000000", expected_version=1, actor="admin")


def test_team_tasks_are_scoped_by_preset_roles(test_db):
    repository = TaskPresetRepository()
    presets = TaskPresetService(repository)
    windows = presets.create(_values("Windows audit"), [_role_id("engineer_windows")], actor="admin")
    linux = presets.create(_values("Linux audit", "linux"), [_role_id("engineer_linux")], actor="admin")

    service = TeamTasksService(repository)
    created_ids = iter(["task-win", "task-lin"])
    service.configure(
        create_remote=lambda payload: next(created_ids), update_remote=lambda task_id, payload: {},
        start_task=lambda *args: {"status": "started"}, stop_task=lambda task_id: {},
        delete_task=lambda task_id, key: {},
    )
    win_user, lin_user = _engineer("engineer_windows"), _engineer("engineer_linux")
    created = service.create(win_user, preset_id=windows["preset_id"], asset_group_ids=["Windows audit-group"],
                             name="Nightly", description=None, unrestricted=False, idempotency_key="create-1")
    service.create(lin_user, preset_id=linux["preset_id"], asset_group_ids=["Linux audit-group"],
                   name=None, description=None, unrestricted=False)

    task = created["task"]
    assert task["mp_task_id"] == "task-win" and task["created_by"] == "engineer_windows.user"
    assert task["preset_name"] == "Windows audit" and task["preset_version"] == 1
    assert task["payload"]["include"]["assetsGroups"] == ["Windows audit-group"]
    assert task["preset_asset_groups"] == [{"id": "Windows audit-group", "name": "Windows audit"}]

    assert [row["mp_task_id"] for row in service.list(win_user, unrestricted=False)["rows"]] == ["task-win"]
    assert {row["mp_task_id"] for row in service.list(win_user, unrestricted=True)["rows"]} == {"task-win", "task-lin"}
    with pytest.raises(LookupError):
        service.get("task-lin", win_user, unrestricted=False)

    replay = service.create(win_user, preset_id=windows["preset_id"], asset_group_ids=["Windows audit-group"],
                            name="Nightly", description=None, unrestricted=False, idempotency_key="create-1")
    assert replay["idempotent_replay"] is True and replay["task"]["mp_task_id"] == "task-win"
    operation = db.get_operation_by_idempotency_key("create-1")
    assert operation["kind"] == "team_task_create" and operation["status"] == "completed"

    # Tasks created outside presets never leak into team lists.
    db.record_scan_task(mp_task_id="legacy", payload=build_scanner_task_payload(
        name="legacy", description=None, scope_id="s", profile_id="p", include_targets=["10.0.0.1"]), status="created")
    assert "legacy" not in {row["mp_task_id"] for row in service.list(win_user, unrestricted=True)["rows"]}


def test_active_task_count_uses_running_postprocess(test_db):
    repository = TaskPresetRepository()
    preset = TaskPresetService(repository).create(_values("Windows audit"), [_role_id("engineer_windows")], actor="a")
    for task_id in ("t-1", "t-2"):
        db.record_scan_task(mp_task_id=task_id, payload={"name": task_id}, status="started")
        repository.attach_task(task_id, preset_id=preset["preset_id"], preset_version=1,
                               asset_groups=[{"id": "g"}], actor="a")
    db.create_scan_postprocess_run("run-1", mp_task_id="t-1", started_from=db.now_utc(), options={})
    with db.connect() as conn:
        conn.execute("UPDATE scan_postprocess_runs SET status='monitoring' WHERE run_id='run-1'")
    assert repository.count_active_tasks(preset["preset_id"]) == 1
    assert repository.count_active_tasks(preset["preset_id"], exclude_task_id="t-1") == 0
