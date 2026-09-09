from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from app import auth, main
from app.ldap import LdapError

ADMIN = {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin", "is_active": True,
         "roles": ["admin"], "permissions": []}
VIEWER = {**ADMIN, "id": 3, "username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "viewer"}


def _fake_now_utc():
    return "2026-09-09T12:00:00+00:00"


def test_ldap_login_provisions_regular_user_when_local_missing(monkeypatch):
    """Local auth misses -> LDAP verifies -> a regular local user is created (viewer role)."""
    monkeypatch.setattr(auth, "authenticate", lambda u, p: None)
    identity = {"username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "viewer"}
    monkeypatch.setattr(auth, "resolve_ldap_identity", lambda u, p: identity)

    with patch.object(auth, "_local_user_record", return_value=None), \
         patch.object(auth, "_provision_ldap_user", side_effect=lambda i: dict(VIEWER)), \
         patch.object(auth, "create_session", return_value="tok") as create_session, \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login", json={"username": "ivan.petrov", "password": "secret"})

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["user"]["username"] == "ivan.petrov"
    assert "mpvm_app_session" in response.cookies
    create_session.assert_called_once()


def test_ldap_login_maps_admin_group_to_admin_role(monkeypatch):
    """When the directory identity resolves to the admin role, the mapped user keeps admin."""
    monkeypatch.setattr(auth, "authenticate", lambda u, p: None)
    identity = {"username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "admin"}
    monkeypatch.setattr(auth, "resolve_ldap_identity", lambda u, p: identity)
    with patch.object(auth, "_local_user_record", return_value=None), \
         patch.object(auth, "_provision_ldap_user", return_value=dict(ADMIN)), \
         patch.object(auth, "create_session", return_value="tok"), \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login", json={"username": "ivan.petrov", "password": "secret"})

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


def test_ldap_error_falls_back_to_401(monkeypatch):
    """A directory failure (wrong password, unreachable) must not crash, just 401."""
    monkeypatch.setattr(auth, "authenticate", lambda u, p: None)
    def _raise(u, p):
        raise LdapError("INVALID_CREDENTIALS")
    monkeypatch.setattr(auth, "resolve_ldap_identity", _raise)
    with patch.object(auth, "_local_user_record", return_value=None), \
         patch.object(auth, "_provision_ldap_user", return_value=None), \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login", json={"username": "ivan.petrov", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"


def test_existing_local_user_wins_over_ldap(monkeypatch):
    """If local auth succeeds, LDAP is never consulted."""
    monkeypatch.setattr(auth, "authenticate", lambda u, p: dict(VIEWER))
    def _should_not_run(u, p):
        raise AssertionError("LDAP should not be called for a known local user")
    monkeypatch.setattr(auth, "resolve_ldap_identity", _should_not_run)
    with patch.object(auth, "create_session", return_value="tok"), \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login", json={"username": "ivan.petrov", "password": "secret"})
    assert response.status_code == 200
    assert response.json()["user"]["username"] == "ivan.petrov"
