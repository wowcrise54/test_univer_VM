from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import auth, main
from app.api import team_tasks as team_tasks_api
from app.domain.errors import DomainError
from app.mpvm_client import MpVmApiError, build_scanner_task_payload
from app.services.team_tasks import TeamTaskPersistError, TeamTasksService

PRESET_ID = str(uuid4())
WINDOWS_ROLE = 10
LINUX_ROLE = 11
ENGINEER = {"id": 7, "username": "win.eng", "roles": [{"id": WINDOWS_ROLE, "key": "engineer_windows"}],
            "permissions": sorted(auth.BUILTIN_ROLE_PERMISSIONS["engineer_windows"])}


def _preset(**overrides):
    preset = {
        "preset_id": PRESET_ID, "name": "Windows audit", "os_family": "windows", "scope_id": "scope-1",
        "profile_id": "profile-audit", "credential_id": "cred-win", "credential_transport": "windows",
        "agent_ids": ["agent-1"], "host_discovery_enabled": False, "host_discovery_profile_id": None,
        "is_fqdn_priority": True, "time_zone": "+05:00", "trigger_parameters": None, "denied_scan_settings": None,
        "start_options": {"precheck_enabled": True}, "max_groups_per_task": 2, "max_active_tasks": None,
        "allowed_asset_groups": [{"id": "g-1", "name": "Servers", "path": "Root / Servers"},
                                 {"id": "g-2", "name": "DC", "path": "Root / DC"},
                                 {"id": "g-3", "name": "Branch", "path": "Root / Branch"}],
        "name_prefix": "[WIN]", "is_active": True, "version": 3, "role_ids": [WINDOWS_ROLE],
    }
    preset.update(overrides)
    return preset


def _task(**overrides):
    task = {"mp_task_id": "task-1", "name": "[WIN] Servers", "preset_id": PRESET_ID,
            "payload": {"description": "nightly", "include": {"targets": ["10.0.0.1"], "assetsGroups": []}},
            "preset_asset_groups": [{"id": "g-1", "name": "Servers", "path": "Root / Servers"}],
            "last_remote_response": {}}
    task.update(overrides)
    return task


@pytest.fixture
def repository():
    repo = MagicMock()
    repo.get.return_value = _preset()
    repo.get_team_task.return_value = _task()
    repo.operation_by_key.return_value = None
    repo.count_active_tasks.return_value = 0
    return repo


@pytest.fixture
def service(repository):
    svc = TeamTasksService(repository)
    svc.configure(
        create_remote=MagicMock(return_value="task-1"), update_remote=MagicMock(return_value={"ok": True}),
        start_task=MagicMock(return_value={"status": "started"}), stop_task=MagicMock(return_value={"stopped": True}),
        delete_task=MagicMock(return_value={"deleted": True}),
    )
    return svc


def test_payload_builder_keeps_contract_without_groups():
    payload = build_scanner_task_payload(name="n", description=None, scope_id="s", profile_id="p",
                                         include_targets=["10.0.0.1"])
    assert payload["include"] == {"assets": [], "targets": ["10.0.0.1"], "assetsGroups": []}


def test_create_builds_payload_only_from_preset_and_selected_groups(service, repository):
    result = service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-2", "g-1", "g-2"], name="Nightly",
                            description="desc", unrestricted=False, idempotency_key="key-1")

    payload = service.create_remote.call_args.args[0]
    assert payload["name"] == "[WIN] Nightly"
    assert payload["scope"] == "scope-1" and payload["profile"] == "profile-audit"
    assert payload["include"] == {"assets": [], "targets": [], "assetsGroups": ["g-2", "g-1"]}
    auth_ref = payload["overrides"]["transports"]["windows"]["wmi_and_rpc_and_re"]["connection"]["auth"]
    assert auth_ref == {"ref_value": "cred-win", "ref_type": "credential"}
    assert payload["agents"] == {"agentIds": ["agent-1"]}
    assert payload["triggerParameters"]["isEnabled"] is False
    repository.attach_task.assert_called_once()
    assert repository.attach_task.call_args.kwargs["asset_groups"][0]["id"] == "g-2"
    assert repository.attach_task.call_args.kwargs["preset_version"] == 3
    statuses = [call.kwargs["status"] for call in repository.register_operation.call_args_list]
    assert statuses == ["running", "completed"]
    assert result["idempotent_replay"] is False


@pytest.mark.parametrize(("groups", "message"), [
    ([], "хотя бы одну"),
    (["g-1", "g-2", "g-3"], "не больше 2"),
    (["g-9"], "не разрешены"),
])
def test_create_rejects_groups_outside_preset_policy(service, groups, message):
    with pytest.raises(ValueError, match=message):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=groups, name=None, description=None,
                       unrestricted=False)
    service.create_remote.assert_not_called()


def test_create_scans_ip_and_fqdn_targets_typed_by_engineer(service, repository):
    service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=[], targets=["SRV01.corp.local.", "10.0.0.15"],
                   name=None, description=None, unrestricted=False)

    payload = service.create_remote.call_args.args[0]
    assert payload["include"] == {"assets": [], "targets": ["srv01.corp.local", "10.0.0.15"], "assetsGroups": []}
    assert payload["name"].startswith("[WIN] srv01.corp.local, 10.0.0.15 ")
    assert repository.attach_task.call_args.kwargs["targets"] == ["srv01.corp.local", "10.0.0.15"]
    assert repository.attach_task.call_args.kwargs["asset_groups"] == []
    request = repository.register_operation.call_args_list[0].kwargs["request"]
    assert request["targets"] == ["srv01.corp.local", "10.0.0.15"]


def test_create_combines_groups_and_targets(service):
    service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], targets=["10.0.1.0/24"],
                   name="Mixed", description=None, unrestricted=False)
    payload = service.create_remote.call_args.args[0]
    assert payload["include"] == {"assets": [], "targets": ["10.0.1.0/24"], "assetsGroups": ["g-1"]}


def test_create_accepts_any_well_formed_target(service):
    service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=[],
                   targets=["192.168.5.0/24", "10.9.9.1-10.9.9.20", "other.example.com", "  "],
                   name=None, description=None, unrestricted=False)
    payload = service.create_remote.call_args.args[0]
    assert payload["include"]["targets"] == ["192.168.5.0/24", "10.9.9.1-10.9.9.20", "other.example.com"]


@pytest.mark.parametrize(("targets", "message"), [
    (["10.0.0.300"], "IP-адрес"),
    (["not a host"], "FQDN"),
    (["   "], "хотя бы одну группу"),
])
def test_create_rejects_malformed_targets(service, targets, message):
    with pytest.raises(ValueError, match=message):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=[], targets=targets, name=None,
                       description=None, unrestricted=False)
    service.create_remote.assert_not_called()


def test_preset_of_another_team_is_invisible(service, repository):
    repository.get.return_value = _preset(role_ids=[LINUX_ROLE])
    with pytest.raises(LookupError):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False)
    assert service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                          unrestricted=True)["task"]


def test_archived_preset_blocks_create_and_start(service, repository):
    repository.get.return_value = _preset(is_active=False)
    with pytest.raises(DomainError) as created:
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False)
    with pytest.raises(DomainError) as started:
        service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)
    assert created.value.code == started.value.code == "PRESET_INACTIVE"
    service.start_task.assert_not_called()


def test_idempotent_create_replays_completed_operation(service, repository):
    repository.operation_by_key.return_value = {"kind": "team_task_create", "status": "completed",
                                                "operation_id": "op-1", "result": {"mp_task_id": "task-1"}}
    result = service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                            unrestricted=False, idempotency_key="key-1")
    assert result["idempotent_replay"] is True and result["operation_id"] == "op-1"
    service.create_remote.assert_not_called()

    repository.operation_by_key.return_value = {"kind": "task_delete", "status": "completed"}
    with pytest.raises(DomainError, match="другой операцией"):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False, idempotency_key="key-1")


def test_local_persist_failure_keeps_remote_task(service, repository):
    repository.record_task.side_effect = RuntimeError("db down")
    with pytest.raises(TeamTaskPersistError) as error:
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False)
    assert error.value.mp_task_id == "task-1"
    service.delete_task.assert_not_called()
    final = repository.register_operation.call_args_list[-1].kwargs
    assert final["status"] == "needs_attention" and final["error"]["mp_task_id"] == "task-1"


def test_start_resyncs_payload_from_current_preset(service, repository):
    repository.get.return_value = _preset(credential_id="cred-rotated", version=4)
    result = service.start("task-1", ENGINEER, idempotency_key="start-1", unrestricted=False)

    assert result == {"status": "started"}
    payload = repository.record_task.call_args.args[1]
    assert payload["include"]["assetsGroups"] == ["g-1"] and payload["include"]["targets"] == []
    assert payload["overrides"]["transports"]["windows"]["wmi_and_rpc_and_re"]["connection"]["auth"]["ref_value"] == "cred-rotated"
    assert payload["description"] == "nightly"
    service.start_task.assert_called_once_with("task-1", {"precheck_enabled": True}, "start-1", "win.eng")


def test_start_respects_concurrency_limit_including_inflight(service, repository):
    repository.get.return_value = _preset(max_active_tasks=1)
    repository.count_active_tasks.return_value = 1
    with pytest.raises(DomainError) as error:
        service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)
    assert error.value.code == "PRESET_CONCURRENCY_LIMIT"

    repository.count_active_tasks.return_value = 0
    service._inflight[PRESET_ID] = 1
    with pytest.raises(DomainError):
        service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)
    service._inflight.clear()
    service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)
    assert service._inflight == {}


def test_start_keeps_saved_targets(service, repository):
    repository.get_team_task.return_value = _task(preset_asset_groups=[], preset_targets=["srv01.corp.local"])
    service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)
    payload = repository.record_task.call_args.args[1]
    assert payload["include"]["targets"] == ["srv01.corp.local"] and payload["include"]["assetsGroups"] == []
    assert repository.attach_task.call_args.kwargs["targets"] == ["srv01.corp.local"]


def test_task_without_saved_groups_cannot_start(service, repository):
    repository.get_team_task.return_value = _task(preset_asset_groups=None)
    with pytest.raises(DomainError, match="группы"):
        service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False)


def test_foreign_task_is_not_found_for_every_action(service, repository):
    repository.get_team_task.return_value = None
    for action in (
        lambda: service.start("task-1", ENGINEER, idempotency_key=None, unrestricted=False),
        lambda: service.stop("task-1", ENGINEER, unrestricted=False),
        lambda: service.delete("task-1", ENGINEER, idempotency_key=None, unrestricted=False),
    ):
        with pytest.raises(LookupError):
            action()
    assert repository.get_team_task.call_args.kwargs == {"role_ids": [WINDOWS_ROLE]}
    service.stop_task.assert_not_called()
    service.delete_task.assert_not_called()


def test_update_keeps_name_and_rebuilds_groups(service, repository):
    service.update("task-1", ENGINEER, asset_group_ids=["g-3"], name=None, description=None, unrestricted=False)
    task_id, payload = service.update_remote.call_args.args
    assert task_id == "task-1" and payload["name"] == "[WIN] Servers"
    assert payload["include"]["assetsGroups"] == ["g-3"] and payload["description"] == "nightly"

    service.update("task-1", ENGINEER, asset_group_ids=[], targets=["10.0.0.15"], name=None, description=None,
                   unrestricted=False)
    payload = service.update_remote.call_args.args[1]
    assert payload["include"]["targets"] == ["10.0.0.15"] and payload["include"]["assetsGroups"] == []


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
@pytest.fixture
def http(service):
    app = FastAPI()

    @app.middleware("http")
    async def user(request, call_next):
        request.state.user = ENGINEER
        return await call_next(request)

    app.include_router(team_tasks_api.router)
    app.state.container = SimpleNamespace(services=SimpleNamespace(team_tasks=service))
    with patch.object(auth, "audit_event") as audit:
        yield TestClient(app, raise_server_exceptions=False), audit


def test_create_rejects_client_supplied_scan_settings(http, service):
    client, _ = http
    response = client.post("/api/team-tasks", json={"preset_id": PRESET_ID, "asset_group_ids": ["g-1"],
                                                    "credential_id": "attacker-cred"})
    assert response.status_code == 422
    service.create_remote.assert_not_called()


def test_create_and_start_uses_derived_idempotency_key(http, service):
    client, audit = http
    response = client.post("/api/team-tasks", headers={"X-Idempotency-Key": "abc"},
                           json={"preset_id": PRESET_ID, "asset_group_ids": ["g-1"], "start_now": True})
    assert response.status_code == 201, response.text
    assert response.json()["start"] == {"status": "started"}
    assert service.start_task.call_args.args[2] == "abc:start"
    assert [call.kwargs["event_type"] for call in audit.call_args_list] == ["team_task_created", "team_task_started"]


def test_create_accepts_targets_without_groups(http, service, repository):
    client, audit = http
    repository.get_team_task.return_value = _task(preset_asset_groups=[], preset_targets=["10.0.0.15"])
    response = client.post("/api/team-tasks", json={"preset_id": PRESET_ID, "targets": ["10.0.0.15"]})
    assert response.status_code == 201, response.text
    assert service.create_remote.call_args.args[0]["include"]["targets"] == ["10.0.0.15"]
    assert audit.call_args.kwargs["details"]["targets"] == ["10.0.0.15"]

    response = client.post("/api/team-tasks", json={"preset_id": PRESET_ID})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "INVALID_TEAM_TASK"


@pytest.mark.parametrize(("error", "status", "code"), [
    (LookupError("nope"), 404, "TEAM_TASK_NOT_FOUND"),
    (ValueError("bad"), 422, "INVALID_TEAM_TASK"),
    (DomainError("PRESET_CONCURRENCY_LIMIT", "busy", status_code=409), 409, "PRESET_CONCURRENCY_LIMIT"),
    (TeamTaskPersistError("task-9", RuntimeError("db")), 500, "TEAM_TASK_NOT_PERSISTED"),
])
def test_domain_errors_map_to_http_codes(http, service, error, status, code):
    client, audit = http
    service.start_task.side_effect = error
    response = client.post("/api/team-tasks/task-1/start")
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    audit.assert_not_called()


def test_runs_require_team_access(http, repository):
    client, _ = http
    repository.get_team_task.return_value = None
    assert client.get("/api/team-tasks/task-1/runs").status_code == 404


def test_engineer_cannot_use_admin_task_endpoints():
    with patch.object(auth, "get_session_user", return_value=ENGINEER), patch.object(auth, "audit_event"):
        http_client = TestClient(main.app)
        assert http_client.get("/api/scanner-tasks").status_code == 403
        assert http_client.post("/api/scanner-tasks/task-1/start").status_code == 403
        assert http_client.post("/api/task-presets", json={}).status_code == 403
        assert http_client.get("/api/mpvm/lookups").status_code == 403


def test_engineer_roles_are_seeded_as_system_roles():
    assert {"engineer_windows", "engineer_linux"} <= set(auth.SEEDED_ROLE_KEYS)
    assert {"engineer_windows", "engineer_linux"} <= auth.SYSTEM_ROLE_KEYS
    engineer = auth.BUILTIN_ROLE_PERMISSIONS["engineer_linux"]
    assert {"tasks.team", "task_presets.read"} <= engineer
    assert not engineer & {"tasks.read", "tasks.manage", "tasks.execute", "task_presets.manage", "connection.read"}
    assert "tasks.team" in auth.BUILTIN_ROLE_PERMISSIONS["operator"]
    assert "task_presets.manage" not in auth.BUILTIN_ROLE_PERMISSIONS["operator"]


def test_update_stop_delete_and_jobs_routes(http, service, repository):
    client, audit = http
    assert client.put("/api/team-tasks/task-1", json={"asset_group_ids": ["g-2"], "name": "Renamed"}).status_code == 200
    assert service.update_remote.call_args.args[1]["name"] == "[WIN] Renamed"
    assert client.post("/api/team-tasks/task-1/stop").json() == {"stopped": True}
    response = client.post("/api/team-tasks/task-1/delete", headers={"X-Idempotency-Key": "del-1"})
    assert response.json() == {"deleted": True}
    service.delete_task.assert_called_once_with("task-1", "del-1")
    assert [call.kwargs["event_type"] for call in audit.call_args_list] == [
        "team_task_updated", "team_task_stopped", "team_task_deleted"]
    with patch.object(team_tasks_api.scanner_task_runs, "scanner_task_run_jobs", return_value={"items": []}) as jobs:
        assert client.get("/api/team-tasks/task-1/runs/run-1/jobs").json() == {"items": []}
    jobs.assert_called_once()
    with patch.object(team_tasks_api.scanner_task_runs, "scanner_task_runs", return_value={"items": []}):
        assert client.get("/api/team-tasks/task-1/runs?limit=5").json() == {"items": []}


def test_list_and_replayed_create_are_not_audited_twice(http, service, repository):
    client, audit = http
    repository.list_team_tasks.return_value = [_task()]
    assert client.get("/api/team-tasks").json()["rows"][0]["mp_task_id"] == "task-1"
    assert repository.list_team_tasks.call_args.kwargs == {"role_ids": [WINDOWS_ROLE]}
    repository.operation_by_key.return_value = {"kind": "team_task_create", "status": "completed",
                                                "operation_id": "op-1", "result": {"mp_task_id": "task-1"}}
    response = client.post("/api/team-tasks", headers={"X-Idempotency-Key": "abc"},
                           json={"preset_id": PRESET_ID, "asset_group_ids": ["g-1"]})
    assert response.status_code == 201 and response.json()["idempotent_replay"] is True
    audit.assert_not_called()


@pytest.mark.parametrize(("error", "status", "code"), [
    (psycopg.errors.UniqueViolation(), 409, "IDEMPOTENCY_KEY_CONFLICT"),
    (MpVmApiError("upstream"), 502, "MPVM_REQUEST_FAILED"),
    (HTTPException(409, detail={"code": "MPVM_NOT_CONNECTED"}), 409, "MPVM_NOT_CONNECTED"),
])
def test_infrastructure_errors_on_create(http, service, error, status, code):
    client, _ = http
    service.create_remote.side_effect = error
    response = client.post("/api/team-tasks", json={"preset_id": PRESET_ID, "asset_group_ids": ["g-1"]})
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code


def test_unexpected_errors_are_not_masked(http, service):
    client, _ = http
    service.stop_task.side_effect = RuntimeError("boom")
    assert client.post("/api/team-tasks/task-1/stop").status_code == 500


def test_mpvm_failure_marks_create_operation_failed(service, repository):
    service.create_remote.side_effect = MpVmApiError("down")
    with pytest.raises(MpVmApiError):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False)
    assert repository.register_operation.call_args_list[-1].kwargs["status"] == "failed"


def test_incomplete_replay_and_auto_name(service, repository):
    repository.operation_by_key.return_value = {"kind": "team_task_create", "status": "failed", "result": {}}
    with pytest.raises(DomainError, match="не завершилась"):
        service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                       unrestricted=False, idempotency_key="k")
    repository.operation_by_key.return_value = None
    repository.get.return_value = _preset(name_prefix="")
    service.create(ENGINEER, preset_id=PRESET_ID, asset_group_ids=["g-1"], name=None, description=None,
                   unrestricted=False)
    assert service.create_remote.call_args.args[0]["name"].startswith("Servers ")
