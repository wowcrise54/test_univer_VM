from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import auth, main


ADMIN = {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin", "is_active": True}
OPERATOR = {**ADMIN, "id": 2, "username": "operator", "role": "operator"}
VIEWER = {**ADMIN, "id": 3, "username": "viewer", "role": "viewer"}


def test_password_hash_is_salted_and_verifiable():
    first = auth.hash_password("correct horse battery staple")
    second = auth.hash_password("correct horse battery staple")

    assert first != second
    assert auth.verify_password("correct horse battery staple", first)
    assert not auth.verify_password("wrong password", first)


def test_api_requires_application_session():
    with patch.object(auth, "get_session_user", return_value=None):
        response = TestClient(main.app).get("/api/operations")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_REQUIRED"


def test_viewer_cannot_modify_data():
    with patch.object(auth, "get_session_user", return_value=VIEWER), patch.object(auth, "audit_event"):
        response = TestClient(main.app).post("/api/operations/example/cancel")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "PERMISSION_DENIED"


def test_denied_mutation_is_audited_before_handler_runs():
    with (
        patch.object(auth, "get_session_user", return_value=VIEWER),
        patch.object(auth, "audit_event") as audit,
        patch.object(main.db, "get_operation") as get_operation,
    ):
        response = TestClient(main.app).post("/api/operations/example/cancel")

    assert response.status_code == 403
    get_operation.assert_not_called()
    assert audit.call_args.kwargs["decision"] == "deny"
    assert audit.call_args.kwargs["permission_key"] == "operations.cancel"


def test_unknown_api_write_is_denied_by_default():
    with patch.object(auth, "get_session_user", return_value=ADMIN), patch.object(auth, "audit_event"):
        response = TestClient(main.app).post("/api/not-a-route")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "PERMISSION_DENIED"


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/not-a-route"),
    ("HEAD", "/api/not-a-route"),
    ("GET", "/api/system/new-sensitive-report"),
    ("GET", "/api/operations/example/new-sensitive-report"),
    ("DELETE", "/api/operations/example"),
])
def test_unmapped_methods_and_routes_are_denied_even_for_admin(method, path):
    with patch.object(auth, "get_session_user", return_value=ADMIN), patch.object(auth, "audit_event"):
        response = TestClient(main.app).request(method, path)
    assert response.status_code == 403


def test_new_registered_read_route_requires_its_own_permission_policy():
    from fastapi import FastAPI

    app = FastAPI()
    app.middleware("http")(main.application_auth_middleware)

    @app.get("/api/system/new-sensitive-report")
    def sensitive_report():
        return {"sensitive": "must not reach handler"}

    with patch.object(auth, "get_session_user", return_value=VIEWER), patch.object(auth, "audit_event"):
        response = TestClient(app).get("/api/system/new-sensitive-report")
    assert response.status_code == 403


def test_cross_site_mutation_is_rejected_before_session_lookup():
    with patch.object(auth, "get_session_user") as get_session_user:
        response = TestClient(main.app).post(
            "/api/operations/example/cancel", headers={"sec-fetch-site": "cross-site"}
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "CROSS_SITE_REQUEST"
    get_session_user.assert_not_called()


def test_operator_cannot_manage_users():
    with patch.object(auth, "get_session_user", return_value=OPERATOR), patch.object(auth, "audit_event"):
        response = TestClient(main.app).get("/api/auth/users")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "PERMISSION_DENIED"


def test_admin_can_reach_user_management_endpoint():
    with (
        patch.object(auth, "get_session_user", return_value=ADMIN),
        patch.object(auth, "list_users", return_value=[ADMIN]),
    ):
        response = TestClient(main.app).get("/api/auth/users")

    assert response.status_code == 200
    assert response.json()["rows"][0]["role"] == "admin"


def test_operator_template_is_intentionally_restricted():
    permissions = auth.BUILTIN_ROLE_PERMISSIONS["operator"]
    assert "tasks.execute" in permissions
    assert "operations.cancel" in permissions
    assert "asset_cards.build" in permissions
    assert "automations.manage" not in permissions
    assert "remediation.policy" not in permissions
    assert "security.users.read" not in permissions


def test_effective_permissions_uses_assigned_roles_then_legacy_role():
    assert auth.effective_permissions({"role": "viewer", "permissions": ["operations.cancel"]}) == {
        "operations.cancel"
    }
    assert auth.effective_permissions({"role": "viewer", "permissions": []}) == set(
        auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    )


def test_all_registered_api_routes_have_an_explicit_policy():
    from app.api.permissions import ROUTE_PERMISSIONS

    public = main.PUBLIC_API_PATHS | {"/api/auth/me", "/api/auth/logout"}
    missing = []
    for path, methods in main.app.openapi()["paths"].items():
        for method in methods:
            if path.startswith("/api/") and path not in public and method != "parameters":
                if (method.upper(), path) not in ROUTE_PERMISSIONS:
                    missing.append(f"{method.upper()} {path}")
    assert missing == []


def test_hidden_static_route_does_not_inherit_dynamic_route_permission():
    from fastapi import FastAPI

    app = FastAPI()
    app.middleware("http")(main.application_auth_middleware)

    @app.get("/api/operations/new-secret", include_in_schema=False)
    def hidden_report():
        return {"secret": "must not be returned"}

    @app.get("/api/operations/{operation_id}")
    def operation(operation_id: str):
        return {"operation_id": operation_id}

    with patch.object(auth, "get_session_user", return_value=VIEWER), patch.object(auth, "audit_event"):
        client = TestClient(app)
        assert client.get("/api/operations/new-secret").status_code == 403
        assert client.get("/api/operations/known-id").status_code == 200


def test_separate_head_handler_requires_its_own_policy():
    from fastapi import FastAPI

    app = FastAPI()
    app.middleware("http")(main.application_auth_middleware)

    @app.head("/api/operations/{operation_id}", include_in_schema=False)
    def sensitive_head(operation_id: str):
        raise AssertionError("unmapped HEAD must not run")

    @app.get("/api/operations/{operation_id}")
    def operation(operation_id: str):
        return {"operation_id": operation_id}

    with patch.object(auth, "get_session_user", return_value=VIEWER), patch.object(auth, "audit_event"):
        response = TestClient(app).head("/api/operations/known-id")
    assert response.status_code == 403


def test_shared_get_head_handler_uses_its_explicit_get_policy():
    from fastapi import FastAPI

    app = FastAPI()
    app.middleware("http")(main.application_auth_middleware)

    @app.api_route("/api/operations/{operation_id}", methods=["GET", "HEAD"])
    def operation(operation_id: str):
        return {"operation_id": operation_id}

    with patch.object(auth, "get_session_user", return_value=VIEWER), patch.object(auth, "audit_event"):
        assert TestClient(app).head("/api/operations/known-id").status_code == 200


@pytest.mark.parametrize("method,path,expected", [
    ("HEAD", "/api/operations/known-id", "operations.read"),
    ("GET", "/api/no-policy", "__deny__"),
    ("POST", "/api/operations/known-id", "__deny__"),
])
def test_compatibility_permission_resolver_is_explicit(method, path, expected):
    assert auth.required_permission(method, path) == expected


def test_sensitive_permission_does_not_require_password_confirmation():
    admin = {**ADMIN, "permissions": sorted(auth.PERMISSIONS)}
    created = {"id": 4, "username": "new-user", "display_name": "New", "role": "viewer", "is_active": True}
    with (
        patch.object(auth, "get_session_user", return_value=admin),
        patch.object(auth, "create_user", return_value=created),
        patch.object(auth, "audit_event"),
    ):
        response = TestClient(main.app).post(
            "/api/auth/users",
            json={"username": "new-user", "display_name": "New", "password": "long-enough-password", "role_ids": [1]},
        )
    assert response.status_code == 201
    assert response.json()["username"] == "new-user"


def test_permissions_from_multiple_roles_are_used_as_a_union():
    user = {**VIEWER, "permissions": ["operations.cancel", "system.read"]}
    with (
        patch.object(auth, "get_session_user", return_value=user),
        patch.object(auth, "audit_event"),
        patch.object(main.db, "get_operation", return_value={"operation_id": "one", "can_cancel": False})
    ):
        response = TestClient(main.app).post("/api/operations/one/cancel")
    assert response.status_code == 200
