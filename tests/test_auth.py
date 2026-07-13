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
    with patch.object(auth, "get_session_user", return_value=VIEWER):
        response = TestClient(main.app).post("/api/operations/example/cancel")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "READ_ONLY_ROLE"


def test_operator_cannot_manage_users():
    with patch.object(auth, "get_session_user", return_value=OPERATOR):
        response = TestClient(main.app).get("/api/auth/users")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "ADMIN_REQUIRED"


def test_admin_can_reach_user_management_endpoint():
    with (
        patch.object(auth, "get_session_user", return_value=ADMIN),
        patch.object(auth, "list_users", return_value=[ADMIN]),
    ):
        response = TestClient(main.app).get("/api/auth/users")

    assert response.status_code == 200
    assert response.json()["rows"][0]["role"] == "admin"
