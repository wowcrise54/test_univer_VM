"""Security administration exercises real PostgreSQL transactions and sessions."""

from datetime import timedelta

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

from app import auth, db

pytestmark = pytest.mark.integration
PASSWORD = "fixture-password-only"


@pytest.fixture
def catalog(test_db):
    return {role["key"]: role for role in auth.list_roles()}


def create(catalog, username="fixture.user", roles=("viewer",), **values):
    return auth.create_user(
        auth.UserCreateRequest(
            username=username,
            display_name="Fixture User",
            password=PASSWORD,
            role_ids=[catalog[key]["id"] for key in roles],
            **values,
        )
    )


def error_code(call, expected, status):
    with pytest.raises(HTTPException) as failure:
        call()
    assert failure.value.status_code == status and failure.value.detail["code"] == expected


def test_user_creation_combines_roles_deduplicates_ids_and_never_exposes_password(catalog):
    user = auth.create_user(
        auth.UserCreateRequest(
            username="Mixed.Name",
            display_name=" Fixture ",
            password=PASSWORD,
            role_ids=[catalog["viewer"]["id"], catalog["operator"]["id"], catalog["viewer"]["id"]],
        )
    )
    assert user["username"] == "mixed.name" and user["display_name"] == "Fixture"
    assert user["role"] == "operator" and len(user["roles"]) == 2
    assert set(user["permissions"]) == auth.OPERATOR_PERMISSIONS
    assert "password_hash" not in user and "password" not in user
    assert auth.authenticate(" MIXED.NAME ", PASSWORD)["id"] == user["id"]
    assert auth.authenticate("mixed.name", "wrong") is None
    assert [row["username"] for row in auth.list_users()] == ["mixed.name"]


def test_duplicate_username_rolls_back_role_assignments(catalog):
    user = create(catalog)
    error_code(lambda: create(catalog, roles=("admin",)), "USERNAME_EXISTS", 409)
    assert len(auth.list_users()) == 1
    assert auth.authenticate(user["username"], PASSWORD)["role"] == "viewer"


def test_unknown_role_id_is_rejected_without_inserting_a_user(catalog):
    error_code(
        lambda: auth.create_user(
            auth.UserCreateRequest(
                username="invalid.roles", display_name="Invalid", password=PASSWORD, role_ids=[999999]
            )
        ),
        "INVALID_ROLES",
        422,
    )
    assert auth.list_users() == []


def test_legacy_role_input_resolves_an_existing_role(catalog):
    assert create(catalog, role="operator")["role"] == "operator"


def test_bootstrap_admin_runs_only_for_an_empty_database_and_nonempty_password(catalog):
    assert not auth.ensure_bootstrap_admin("initial", "", "")
    assert auth.ensure_bootstrap_admin(" INITIAL ", PASSWORD, "")
    assert auth.authenticate("initial", PASSWORD)["role"] == "admin"
    assert not auth.ensure_bootstrap_admin("second", PASSWORD, "Second")
    assert len(auth.list_users()) == 1


@pytest.mark.parametrize(
    "change", [{"password": "replacement-fixture-password"}, {"role_ids": "operator"}, {"is_active": False}]
)
def test_security_changes_revoke_all_existing_sessions(catalog, change):
    user = create(catalog)
    first, second = auth.create_session(user["id"], hours=1), auth.create_session(user["id"], hours=2)
    assert auth.get_session_user(first)["id"] == user["id"]
    values = {**change}
    if values.get("role_ids") == "operator":
        values["role_ids"] = [catalog["operator"]["id"]]
    updated = auth.update_user(user["id"], auth.UserUpdateRequest(**values), actor_id=999)
    assert updated["id"] == user["id"]
    assert auth.get_session_user(first) is None and auth.get_session_user(second) is None
    if "password" in values:
        assert auth.authenticate(user["username"], PASSWORD) is None
        assert auth.authenticate(user["username"], values["password"])["id"] == user["id"]
    if values.get("is_active") is False:
        assert auth.authenticate(user["username"], PASSWORD) is None
        assert auth._local_user_record(user["username"]) is None


def test_cosmetic_updates_and_noop_keep_sessions_and_permissions(catalog):
    user = create(catalog)
    token = auth.create_session(user["id"], hours=1)
    changed = auth.update_user(user["id"], auth.UserUpdateRequest(display_name="Renamed"), actor_id=999)
    assert changed["display_name"] == "Renamed"
    assert auth.get_session_user(token)["display_name"] == "Renamed"
    assert auth.update_user(user["id"], auth.UserUpdateRequest(), actor_id=999)["permissions"] == user["permissions"]
    assert auth.get_session_user(token) is not None


@pytest.mark.parametrize(
    "change,actor,code",
    [
        ({"is_active": False}, "self", "SELF_DISABLE"),
        ({"role_ids": "viewer"}, "self", "SELF_DEMOTE"),
        ({"is_active": False}, "other", "LAST_ADMIN"),
        ({"role_ids": "viewer"}, "other", "LAST_ADMIN"),
    ],
)
def test_an_active_administrator_cannot_disable_or_demote_the_last_admin(catalog, change, actor, code):
    user = create(catalog, roles=("admin",))
    values = {**change}
    if "role_ids" in values:
        values["role_ids"] = [catalog["viewer"]["id"]]
    error_code(
        lambda: auth.update_user(
            user["id"], auth.UserUpdateRequest(**values), actor_id=user["id"] if actor == "self" else 999
        ),
        code,
        409,
    )
    assert auth.authenticate(user["username"], PASSWORD)["role"] == "admin"


def test_another_administrator_can_demote_a_user_when_an_active_admin_remains(catalog):
    first = create(catalog, "admin.first", roles=("admin",))
    second = create(catalog, "admin.second", roles=("admin",))
    updated = auth.update_user(first["id"], auth.UserUpdateRequest(role="viewer"), actor_id=second["id"])
    assert updated["role"] == "viewer"
    assert auth.authenticate(second["username"], PASSWORD)["role"] == "admin"


def test_missing_user_and_invalid_role_updates_are_atomic(catalog):
    error_code(
        lambda: auth.update_user(999, auth.UserUpdateRequest(display_name="Missing"), actor_id=1), "USER_NOT_FOUND", 404
    )
    user = create(catalog)
    error_code(
        lambda: auth.update_user(
            user["id"], auth.UserUpdateRequest(display_name="Should rollback", role_ids=[999]), actor_id=999
        ),
        "INVALID_ROLES",
        422,
    )
    assert auth.authenticate(user["username"], PASSWORD)["display_name"] == "Fixture User"


def test_custom_role_cloning_and_permission_replacement_change_effective_permissions(catalog):
    role = auth.clone_role(
        auth.RoleCloneRequest(source_role_id=catalog["viewer"]["id"], name=" Custom ", description=" Description ")
    )
    assert role["name"] == "Custom" and role["description"] == "Description" and role["is_system"] is False
    assert set(role["permission_keys"]) == auth.VIEWER_PERMISSIONS
    user = auth.create_user(
        auth.UserCreateRequest(username="custom.user", display_name="Custom", password=PASSWORD, role_ids=[role["id"]])
    )
    token = auth.create_session(user["id"], hours=1)
    updated = auth.update_role(
        role["id"],
        auth.RoleUpdateRequest(
            name="Renamed role",
            description="Changed",
            permission_keys=["operations.read", "operations.cancel", "operations.read"],
        ),
    )
    assert updated["permission_keys"] == ["operations.cancel", "operations.read"]
    assert auth.get_session_user(token)["permissions"] == ["operations.cancel", "operations.read"]
    assert auth.update_role(role["id"], auth.RoleUpdateRequest())["name"] == "Renamed role"
    emptied = auth.update_role(role["id"], auth.RoleUpdateRequest(permission_keys=[]))
    assert emptied["permission_keys"] == []
    assert auth.get_session_user(token)["permissions"] == []


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_system_roles_are_immutable_and_missing_roles_are_explicit(catalog, operation):
    call = (
        (lambda role_id: auth.update_role(role_id, auth.RoleUpdateRequest(name="Mutation")))
        if operation == "update"
        else auth.delete_role
    )
    error_code(lambda: call(catalog["admin"]["id"]), "SYSTEM_ROLE_IMMUTABLE", 409)
    error_code(lambda: call(999999), "ROLE_NOT_FOUND", 404)


def test_role_clone_rejects_duplicates_and_missing_sources(catalog):
    request = auth.RoleCloneRequest(source_role_id=catalog["viewer"]["id"], name="Custom")
    auth.clone_role(request)
    error_code(lambda: auth.clone_role(request), "ROLE_EXISTS", 409)
    error_code(
        lambda: auth.clone_role(auth.RoleCloneRequest(source_role_id=999, name="Missing")), "ROLE_NOT_FOUND", 404
    )


def test_assigned_role_cannot_be_deleted_until_all_users_are_reassigned(catalog):
    role = auth.clone_role(auth.RoleCloneRequest(source_role_id=catalog["viewer"]["id"], name="Custom"))
    user = auth.create_user(
        auth.UserCreateRequest(
            username="assigned.user", display_name="Assigned", password=PASSWORD, role_ids=[role["id"]]
        )
    )
    error_code(lambda: auth.delete_role(role["id"]), "ROLE_ASSIGNED", 409)
    auth.update_user(user["id"], auth.UserUpdateRequest(role_ids=[catalog["viewer"]["id"]]), actor_id=999)
    auth.delete_role(role["id"])
    assert all(row["id"] != role["id"] for row in auth.list_roles())


def test_sessions_store_only_hashed_tokens_and_expire_or_revoke_idempotently(catalog):
    user = create(catalog)
    token = auth.create_session(user["id"], hours=1)
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM app_auth_sessions").fetchone()
        assert token not in row.values() and row["token_hash"] == auth._token_hash(token)
        conn.execute("UPDATE app_auth_sessions SET expires_at=%s", (auth._iso(auth._utc_now() - timedelta(seconds=1)),))
    assert auth.get_session_user(token) is None
    auth.revoke_session(token)
    auth.revoke_session(token)
    auth.revoke_session(None)
    assert auth.get_session_user(None) is None
    assert auth.get_session_user("invalid") is None
    new_token = auth.create_session(user["id"], hours=1)
    assert auth.get_session_user(new_token)["id"] == user["id"]
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM app_auth_sessions").fetchone()["n"] == 1


def test_authentication_audit_keeps_request_context_and_paginates_without_secrets(catalog):
    user = create(catalog)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/test",
            "headers": [(b"user-agent", b"fixture-browser")],
            "client": ("192.0.2.1", 1234),
        }
    )
    request.state.trace_id = "trace"
    request.state.request_id = "request"
    auth.audit_event(
        request=request,
        user=user,
        event_type="role.update",
        decision="allow",
        permission_key="security.roles.manage",
        target_type="role",
        target_id="123",
        details={"reason": "test"},
    )
    auth.audit_event(request=None, user=None, event_type="login", decision="deny")
    result = auth.list_audit_events(limit=1, offset=0)
    assert result["total"] == 2 and result["rows"][0]["decision"] == "deny"
    earlier = auth.list_audit_events(limit=900, offset=1)["rows"][0]
    assert earlier["ip_address"] == "192.0.2.1" and earlier["user_agent"] == "fixture-browser"
    assert (
        earlier["trace_id"] == "trace"
        and earlier["request_id"] == "request"
        and earlier["details"] == {"reason": "test"}
    )
    assert auth.list_audit_events(limit=900, offset=-1)["limit"] == 500
    with db.connect() as conn:
        conn.execute(
            "UPDATE app_auth_audit_events SET created_at=%s WHERE event_type='login'",
            (auth._iso(auth._utc_now() - timedelta(days=400)),),
        )
    assert auth.cleanup_audit_events() == 1
    assert auth.cleanup_audit_events() == 0
    assert auth.list_audit_events()["total"] == 1


def test_permission_payload_validates_unknown_keys_and_catalog_is_complete(catalog):
    with pytest.raises(ValidationError, match="Unsupported permissions"):
        auth.RoleUpdateRequest(permission_keys=["unknown.permission"])
    assert auth.RoleUpdateRequest(permission_keys=None).permission_keys is None
    assert {item["key"] for item in auth.list_permissions()} == set(auth.PERMISSIONS)


def test_rbac_catalog_migrates_legacy_role_column_without_duplicate_assignments(catalog):
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute("ALTER TABLE app_users ADD COLUMN role TEXT")
        user = conn.execute(
            "INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at,role) VALUES(%s,%s,%s,TRUE,%s,%s,%s) RETURNING id",
            ("legacy.admin", "Legacy Admin", auth.hash_password(PASSWORD), now, now, "admin"),
        ).fetchone()
    try:
        auth.ensure_rbac_catalog()
        auth.ensure_rbac_catalog()
        assert auth.authenticate("legacy.admin", PASSWORD)["role"] == "admin"
        with db.connect() as conn:
            assert (
                conn.execute("SELECT COUNT(*) AS n FROM app_user_roles WHERE user_id=%s", (user["id"],)).fetchone()["n"]
                == 1
            )
            assert (
                conn.execute(
                    "SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_name='app_users' AND column_name='role'"
                ).fetchone()["n"]
                == 0
            )
    finally:
        with db.connect() as conn:
            conn.execute("ALTER TABLE app_users DROP COLUMN IF EXISTS role")


def test_security_http_lifecycle_enforces_permission_changes_on_real_sessions(catalog):
    from fastapi.testclient import TestClient

    from app import main

    admin = create(catalog, "http.admin", roles=("admin",))
    client = TestClient(main.app)
    client.cookies.set(auth.COOKIE_NAME, auth.create_session(admin["id"], hours=1))
    assert client.get("/api/auth/permissions").status_code == 200
    assert client.get("/api/auth/roles").status_code == 200
    cloned = client.post(
        "/api/auth/roles/clone", json={"source_role_id": catalog["viewer"]["id"], "name": "HTTP Custom"}
    )
    assert cloned.status_code == 201
    role_id = cloned.json()["id"]
    assert (
        client.patch(
            f"/api/auth/roles/{role_id}", json={"permission_keys": ["system.read", "security.users.read"]}
        ).status_code
        == 200
    )
    response = client.post(
        "/api/auth/users",
        json={"username": "http.user", "display_name": "HTTP User", "password": PASSWORD, "role_ids": [role_id]},
    )
    assert response.status_code == 201
    user_id = response.json()["id"]
    user_client = TestClient(main.app)
    user_client.cookies.set(auth.COOKIE_NAME, auth.create_session(user_id, hours=1))
    assert user_client.get("/api/auth/users").status_code == 200
    denied = user_client.patch(f"/api/auth/users/{user_id}", json={"role_ids": [catalog["admin"]["id"]]})
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "PERMISSION_DENIED"
    updated = client.patch(f"/api/auth/users/{user_id}", json={"role_ids": [catalog["viewer"]["id"]]})
    assert updated.status_code == 200
    assert user_client.get("/api/auth/users").status_code == 401
    assert client.delete(f"/api/auth/roles/{role_id}").status_code == 204
    audit = client.get("/api/auth/audit?limit=200")
    assert audit.status_code == 200
    assert any(
        row["decision"] == "deny" and row["permission_key"] == "security.users.manage" for row in audit.json()["rows"]
    )
