from __future__ import annotations

from unittest.mock import patch

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


def test_all_registered_api_routes_have_an_explicit_policy():
    public = main.PUBLIC_API_PATHS | {"/api/auth/me", "/api/auth/logout"}
    missing = []
    for route in main.app.routes:
        path = getattr(route, "path", "")
        for method in getattr(route, "methods", set()):
            if path.startswith("/api/") and path not in public and method != "OPTIONS":
                if auth.required_permission(method, path) == "__deny__":
                    missing.append(f"{method} {path}")
    assert missing == []


def test_sensitive_permission_requires_recent_reauthentication():
    admin = {**ADMIN, "permissions": sorted(auth.PERMISSIONS), "elevated_until": None}
    with patch.object(auth, "get_session_user", return_value=admin), patch.object(auth, "audit_event"):
        response = TestClient(main.app).post(
            "/api/auth/users",
            json={"username": "new-user", "display_name": "New", "password": "long-enough-password", "role_ids": [1]},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "REAUTH_REQUIRED"


def test_permissions_from_multiple_roles_are_used_as_a_union():
    user = {**VIEWER, "permissions": ["operations.cancel", "system.read"]}
    with (
        patch.object(auth, "get_session_user", return_value=user),
        patch.object(auth, "audit_event"),
        patch.object(main.db, "get_operation", return_value={"operation_id": "one", "can_cancel": False})
    ):
        response = TestClient(main.app).post("/api/operations/one/cancel")
    assert response.status_code == 200
