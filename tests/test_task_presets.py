from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import auth
from app.api import task_presets as task_presets_api
from app.domain.errors import DomainError
from app.mpvm_client import MpVmApiError
from app.services.task_presets import TaskPresetService, flatten_asset_groups, user_role_ids

PRESET_ID = str(uuid4())
ADMIN = {"id": 1, "username": "admin", "roles": [{"id": 1, "key": "admin"}], "permissions": sorted(auth.PERMISSIONS)}
ENGINEER = {"id": 7, "username": "lin.eng", "roles": [{"id": 11, "key": "engineer_linux"}],
            "permissions": sorted(auth.BUILTIN_ROLE_PERMISSIONS["engineer_linux"])}

HIERARCHY = [{"id": "root", "name": "Root", "children": [
    {"id": "g-1", "name": "Linux servers", "children": [{"id": "g-2", "name": "DB"}]},
    {"name": "no id"},
]}]
LOOKUPS = {
    "scopes": [{"id": "scope-1", "name": "Main"}],
    "scanner_profiles": [{"id": "profile-audit", "name": "Audit"}, {"id": "profile-check", "name": "Check"}],
    "credentials": [{"id": "cred-ssh", "name": "ssh-audit", "raw": {"login": "x"}}],
    "agents": [{"id": "agent-1", "name": "Collector"}],
}


def _values(**overrides):
    values = {
        "name": "  Linux audit ", "description": "", "os_family": "linux", "scope_id": "scope-1",
        "profile_id": "profile-audit", "credential_id": "cred-ssh", "credential_transport": "ssh",
        "agent_ids": [], "host_discovery_enabled": False, "host_discovery_profile_id": "",
        "is_fqdn_priority": True, "time_zone": "+05:00", "trigger_parameters": None,
        "denied_scan_settings": None, "start_options": {"precheck_profile_id": "profile-check"},
        "allowed_asset_groups": [{"id": "g-2"}, {"id": "g-2"}], "max_groups_per_task": 5,
        "max_active_tasks": 3, "name_prefix": " [LNX] ",
    }
    values.update(overrides)
    return values


@pytest.fixture
def repository():
    repo = MagicMock()
    repo.existing_role_ids.side_effect = lambda ids: set(ids) & {11, 12}
    repo.create.side_effect = lambda values, roles, actor: {**values, "preset_id": PRESET_ID, "role_ids": roles}
    return repo


@pytest.fixture
def service(repository):
    svc = TaskPresetService(repository)
    svc.configure(lookups_provider=lambda: LOOKUPS, groups_provider=lambda: HIERARCHY)
    return svc


def test_flatten_asset_groups_builds_paths_and_skips_groups_without_id():
    assert flatten_asset_groups(HIERARCHY) == [
        {"id": "root", "name": "Root", "path": "Root"},
        {"id": "g-1", "name": "Linux servers", "path": "Root / Linux servers"},
        {"id": "g-2", "name": "DB", "path": "Root / Linux servers / DB"},
    ]


def test_create_normalizes_and_uses_server_group_names(service, repository):
    preset = service.create(_values(), [11], actor="admin")
    values = repository.create.call_args.args[0]
    assert values["name"] == "Linux audit" and values["name_prefix"] == "[LNX]"
    assert values["host_discovery_profile_id"] is None
    assert values["allowed_asset_groups"] == [{"id": "g-2", "name": "DB", "path": "Root / Linux servers / DB"}]
    assert preset["role_ids"] == [11]


@pytest.mark.parametrize(("overrides", "roles", "message"), [
    ({"credential_transport": "windows"}, [11], "Транспорт"),
    ({}, [], "хотя бы одну роль"),
    ({}, [11, 99], "Роли не найдены: 99"),
    ({"allowed_asset_groups": []}, [11], "разрешённую группу"),
    ({"profile_id": "missing"}, [11], "Профиль сканирования missing"),
    ({"credential_id": "missing"}, [11], "Учётная запись missing"),
    ({"start_options": {"precheck_profile_id": "missing"}}, [11], "precheck"),
    ({"allowed_asset_groups": [{"id": "g-404"}]}, [11], "g-404"),
])
def test_create_rejects_invalid_presets(service, repository, overrides, roles, message):
    with pytest.raises(ValueError, match=message):
        service.create(_values(**overrides), roles, actor="admin")
    repository.create.assert_not_called()


def test_preset_without_credential_may_use_any_transport(service, repository):
    service.create(_values(credential_id=None, credential_transport="windows"), [11], actor="admin")
    repository.create.assert_called_once()


def test_engineers_see_only_active_presets_of_their_roles(service, repository):
    repository.list.return_value = []
    service.list_for_user(ENGINEER, can_manage=False, include_archived=True)
    repository.list.assert_called_with(role_ids=[11], include_archived=False)
    service.list_for_user(ADMIN, can_manage=True, include_archived=True)
    repository.list.assert_called_with(role_ids=None, include_archived=True)

    repository.get.return_value = {"preset_id": PRESET_ID, "role_ids": [12], "is_active": True}
    with pytest.raises(LookupError):
        service.get_for_user(PRESET_ID, ENGINEER, can_manage=False)
    repository.get.return_value = {"preset_id": PRESET_ID, "role_ids": [11], "is_active": False}
    with pytest.raises(LookupError):
        service.get_for_user(PRESET_ID, ENGINEER, can_manage=False)
    assert service.get_for_user(PRESET_ID, ADMIN, can_manage=True)["preset_id"] == PRESET_ID


def test_lookups_drop_raw_mpvm_objects(service):
    lookups = service.lookups()
    assert lookups["credentials"] == [{"id": "cred-ssh", "name": "ssh-audit"}]
    assert set(lookups) == {"credentials", "scopes", "scanner_profiles", "agents"}


def test_draft_from_ssh_task():
    draft = TaskPresetService.draft_from_task({
        "mp_task_id": "task-1", "credential_id": "cred-ssh",
        "payload": {"name": "Linux nightly", "scope": "scope-1", "profile": "profile-audit",
                    "overrides": {"transports": {"terminal": {"ssh": {}}}},
                    "include": {"targets": ["10.0.0.1"], "assetsGroups": ["g-1"]},
                    "triggerParameters": {"isEnabled": False, "timeZone": "+03:00"},
                    "agents": {"agentIds": ["agent-1"]}},
    })
    assert draft["os_family"] == "linux" and draft["credential_transport"] == "ssh"
    assert draft["trigger_parameters"] is None and draft["time_zone"] == "+03:00"
    assert draft["allowed_asset_groups"] == [{"id": "g-1"}] and draft["agent_ids"] == ["agent-1"]


def test_user_role_ids_ignores_roles_without_id():
    assert user_role_ids({"roles": [{"id": 3}, {"key": "legacy"}, {"id": 1}]}) == [1, 3]
    assert user_role_ids(None) == []


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #
def _request_body(**overrides):
    body = {
        "name": "Linux audit", "os_family": "linux", "scope_id": "scope-1", "profile_id": "profile-audit",
        "credential_id": "cred-ssh", "credential_transport": "ssh", "allowed_asset_groups": [{"id": "g-2"}],
        "role_ids": [11],
    }
    body.update(overrides)
    return body


@pytest.fixture
def http():
    svc = MagicMock()
    app = FastAPI()
    current = {"user": ADMIN}

    @app.middleware("http")
    async def user(request, call_next):
        request.state.user = current["user"]
        return await call_next(request)

    app.include_router(task_presets_api.router)
    app.state.container = SimpleNamespace(services=SimpleNamespace(task_presets=svc, tasks=MagicMock()))
    with patch.object(auth, "audit_event") as audit:
        yield TestClient(app, raise_server_exceptions=False), svc, audit, current, app


def test_create_update_archive_are_audited(http):
    client, svc, audit, _, _ = http
    svc.create.return_value = svc.update.return_value = svc.archive.return_value = {
        "preset_id": PRESET_ID, "name": "Linux audit", "allowed_asset_groups": [{"id": "g-2"}]}
    assert client.post("/api/task-presets", json=_request_body()).status_code == 201
    values, roles = svc.create.call_args.args
    assert roles == [11] and "role_ids" not in values and values["start_options"]["precheck_enabled"] is False
    assert client.put(f"/api/task-presets/{PRESET_ID}", json=_request_body(expected_version=2)).status_code == 200
    assert svc.update.call_args.kwargs["expected_version"] == 2
    assert client.post(f"/api/task-presets/{PRESET_ID}/archive", json={"expected_version": 3}).status_code == 200
    assert [call.kwargs["event_type"] for call in audit.call_args_list] == [
        "task_preset_created", "task_preset_updated", "task_preset_archived"]


@pytest.mark.parametrize("body", [
    _request_body(role_ids=[]),
    _request_body(allowed_asset_groups=[]),
    _request_body(time_zone="Europe/Moscow"),
    _request_body(password="secret"),
    _request_body(start_options={"precheck_timeout_minutes": 0}),
])
def test_invalid_payloads_are_rejected_before_the_service(http, body):
    client, svc, _, _, _ = http
    assert client.post("/api/task-presets", json=body).status_code == 422
    svc.create.assert_not_called()


def test_update_requires_expected_version(http):
    client, svc, _, _, _ = http
    assert client.put(f"/api/task-presets/{PRESET_ID}", json=_request_body()).status_code == 422
    svc.update.assert_not_called()


@pytest.mark.parametrize(("error", "status", "code"), [
    (LookupError("nope"), 404, "TASK_PRESET_NOT_FOUND"),
    (ValueError("bad"), 422, "INVALID_TASK_PRESET"),
    (DomainError("VERSION_CONFLICT", "changed", status_code=409), 409, "VERSION_CONFLICT"),
    (psycopg.errors.UniqueViolation(), 409, "TASK_PRESET_NAME_EXISTS"),
])
def test_domain_errors_map_to_http_codes(http, error, status, code):
    client, svc, audit, _, _ = http
    svc.update.side_effect = error
    response = client.put(f"/api/task-presets/{PRESET_ID}", json=_request_body(expected_version=1))
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    audit.assert_not_called()


def test_list_scope_depends_on_manage_permission(http):
    client, svc, _, current, _ = http
    svc.list_for_user.return_value = {"rows": []}
    client.get("/api/task-presets?include_archived=true")
    assert svc.list_for_user.call_args.kwargs == {"can_manage": True, "include_archived": True}
    current["user"] = ENGINEER
    client.get("/api/task-presets")
    assert svc.list_for_user.call_args.kwargs == {"can_manage": False, "include_archived": False}


def test_static_routes_win_over_preset_id(http):
    client, svc, _, _, _ = http
    svc.asset_groups.return_value = {"rows": []}
    svc.lookups.return_value = {"scopes": []}
    assert client.get("/api/task-presets/asset-groups").json() == {"rows": []}
    assert client.get("/api/task-presets/lookups").json() == {"scopes": []}
    svc.get_for_user.assert_not_called()
    assert client.get("/api/task-presets/not-a-uuid").status_code == 422


def test_draft_from_task(http):
    client, svc, _, _, app = http
    app.state.container.services.tasks.get.return_value = None
    assert client.post("/api/task-presets/from-task/task-1").status_code == 404
    app.state.container.services.tasks.get.return_value = {"mp_task_id": "task-1"}
    svc.draft_from_task.return_value = {"name": "draft"}
    assert client.post("/api/task-presets/from-task/task-1").json() == {"draft": {"name": "draft"}}


def test_get_and_archive_errors_and_infrastructure_mapping(http):
    client, svc, audit, _, _ = http
    svc.get_for_user.return_value = {"preset_id": PRESET_ID}
    assert client.get(f"/api/task-presets/{PRESET_ID}").json() == {"preset_id": PRESET_ID}
    svc.get_for_user.side_effect = LookupError("missing")
    assert client.get(f"/api/task-presets/{PRESET_ID}").status_code == 404
    svc.archive.side_effect = DomainError("VERSION_CONFLICT", "changed", status_code=409)
    assert client.post(f"/api/task-presets/{PRESET_ID}/archive", json={"expected_version": 1}).status_code == 409
    svc.create.side_effect = MpVmApiError("upstream")
    assert client.post("/api/task-presets", json=_request_body()).json()["detail"]["code"] == "MPVM_REQUEST_FAILED"
    svc.asset_groups.side_effect = HTTPException(409, detail={"code": "MPVM_NOT_CONNECTED"})
    assert client.get("/api/task-presets/asset-groups").status_code == 409
    svc.lookups.side_effect = RuntimeError("boom")
    assert client.get("/api/task-presets/lookups").status_code == 500
    assert client.post("/api/task-presets", json=_request_body(name="   ")).status_code == 422
    audit.assert_not_called()


def test_service_requires_configured_providers_and_handles_update_misses(repository):
    svc = TaskPresetService(repository)
    with pytest.raises(RuntimeError):
        svc.lookups()
    with pytest.raises(RuntimeError):
        svc.asset_groups()
    repository.update.return_value = None
    repository.archive.return_value = None
    with pytest.raises(LookupError):
        svc.update(PRESET_ID, _values(credential_id=None), [11], expected_version=1, actor="a")
    with pytest.raises(LookupError):
        svc.archive(PRESET_ID, expected_version=1, actor="a")
    repository.get.return_value = None
    with pytest.raises(LookupError):
        svc.get_for_user(PRESET_ID, ADMIN, can_manage=True)


def test_asset_groups_are_flattened_for_the_editor(service):
    assert service.asset_groups()["rows"][-1]["path"] == "Root / Linux servers / DB"
