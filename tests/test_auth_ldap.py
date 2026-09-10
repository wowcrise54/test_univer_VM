from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import auth, ldap, main
from app.ldap import LdapError

ADMIN = {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin", "is_active": True,
         "roles": ["admin"], "permissions": []}
VIEWER = {**ADMIN, "id": 3, "username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "viewer"}


class _QueryResult:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _RoleLookupConn:
    def __init__(self, mapped_role=None):
        self.mapped_role = mapped_role
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "role_key=%s OR name=%s" in sql:
            return _QueryResult(self.mapped_role)
        if "role_key='viewer'" in sql:
            return _QueryResult({"id": 3})
        raise AssertionError(f"Unexpected SQL: {sql}")


def _fake_now_utc():
    return "2026-09-09T12:00:00+00:00"


def test_ldap_default_role_can_resolve_custom_role_by_name_when_key_is_null():
    conn = _RoleLookupConn(mapped_role={"id": 79})

    role = auth._ldap_default_role_row(conn, "Linux_VM")

    assert role["id"] == 79
    assert conn.calls[0][1] == ("Linux_VM", "Linux_VM", "Linux_VM")


def test_ldap_default_role_falls_back_to_viewer_when_configured_role_is_missing():
    conn = _RoleLookupConn(mapped_role=None)

    role = auth._ldap_default_role_row(conn, "MissingRole")

    assert role["id"] == 3
    assert len(conn.calls) == 2


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


def test_local_login_mode_does_not_try_ldap(monkeypatch):
    monkeypatch.setattr(auth, "authenticate", lambda u, p: None)
    def _should_not_run(u, p):
        raise AssertionError("LDAP should not be called for local login mode")
    monkeypatch.setattr(auth, "resolve_ldap_identity", _should_not_run)

    with patch.object(auth, "audit_event"), patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login",
            json={"username": "ivan.petrov", "password": "secret", "auth_type": "local"},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"


def test_ldap_login_mode_uses_ldap_without_local_password_check(monkeypatch):
    def _should_not_run(u, p):
        raise AssertionError("Local password auth should not be called for LDAP login mode")
    monkeypatch.setattr(auth, "authenticate", _should_not_run)
    identity = {"username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "viewer"}
    monkeypatch.setattr(auth, "resolve_ldap_identity", lambda u, p: identity)

    with patch.object(auth, "_local_user_record", return_value=None), \
         patch.object(auth, "_provision_ldap_user", side_effect=lambda i: dict(VIEWER)), \
         patch.object(auth, "create_session", return_value="tok"), \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "now_utc", return_value=_fake_now_utc()):
        response = TestClient(main.app).post(
            "/api/auth/login",
            json={"username": "ivan.petrov", "password": "secret", "auth_type": "ldap"},
        )

    assert response.status_code == 200
    assert response.json()["user"]["username"] == "ivan.petrov"


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


def test_ldap_url_selects_ldaps_transport_and_default_port(monkeypatch):
    captured = {}

    class FakeServer:
        def __init__(self, host, **kwargs):
            captured["server"] = (host, kwargs)

    class FakeConnection:
        def __init__(self, server, **kwargs):
            captured["connection"] = (server, kwargs)

        def unbind(self):
            pass

    fake_ldap3 = SimpleNamespace(NONE=object(), Server=FakeServer, Connection=FakeConnection)
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    settings = SimpleNamespace(
        ldap_url="ldaps://directory.example.local",
        ldap_bind_dn="CN=lookup,DC=example,DC=local",
        ldap_connect_timeout_seconds=10,
    )

    ldap._build_connection(settings, settings.ldap_bind_dn, "secret")

    assert captured["server"] == (
        "directory.example.local",
        {"port": 636, "get_info": fake_ldap3.NONE, "use_ssl": True, "connect_timeout": 10},
    )
    assert captured["connection"][1]["auto_bind"] is True


def test_ldap_bind_failure_is_normalized_to_ldap_error(monkeypatch):
    class FakeServer:
        def __init__(self, *args, **kwargs):
            pass

    def fail_bind(*args, **kwargs):
        raise LDAPBindError("invalidCredentials")

    class LDAPBindError(Exception):
        pass

    fake_ldap3 = SimpleNamespace(
        NONE=object(),
        Server=FakeServer,
        Connection=fail_bind,
        core=SimpleNamespace(exceptions=SimpleNamespace(LDAPBindError=LDAPBindError)),
    )
    monkeypatch.setitem(sys.modules, "ldap3", fake_ldap3)
    settings = SimpleNamespace(
        ldap_url="ldap://directory.example.local:389",
        ldap_bind_dn="CN=lookup,DC=example,DC=local",
        ldap_connect_timeout_seconds=10,
    )

    try:
        ldap._build_connection(settings, settings.ldap_bind_dn, "wrong")
    except LdapError as exc:
        assert str(exc) == "ldap_bind_failed"
    else:
        raise AssertionError("LDAP bind failures must be normalized to LdapError")


def test_search_user_copies_entries_before_unbind(monkeypatch):
    fake_conv = SimpleNamespace(escape_filter_chars=lambda value: value)
    class FakeEntry:
        entry_dn = "CN=Ivan Petrov,DC=example,DC=local"

        def __contains__(self, key):
            return key == "displayName"

        def __getitem__(self, key):
            if key == "displayName":
                return "Ivan Petrov"
            raise KeyError(key)

    class FakeConnection:
        entries = []
        result = {"description": "success"}

        def search(self, *args, **kwargs):
            self.entries = [FakeEntry()]
            return True

        def unbind(self):
            self.entries = []

    monkeypatch.setitem(sys.modules, "ldap3.utils.conv", fake_conv)
    connection = FakeConnection()
    monkeypatch.setattr(ldap, "_build_connection", lambda *args, **kwargs: connection)
    settings = SimpleNamespace(
        ldap_bind_dn="CN=lookup,DC=example,DC=local",
        ldap_bind_password="secret",
        ldap_base_dn="DC=example,DC=local",
        ldap_user_filter="(sAMAccountName={username})",
        ldap_display_name_attribute="displayName",
    )

    result = ldap._search_user(settings, "ivan.petrov")

    assert result == {
        "dn": "CN=Ivan Petrov,DC=example,DC=local",
        "display": "Ivan Petrov",
    }


def test_ldap_required_ou_matches_exact_ou_component():
    settings = SimpleNamespace(ldap_required_ou="t1")

    assert ldap._is_in_required_ou(
        "CN=Ivan,OU=t1,OU=Users,DC=example,DC=local",
        settings,
    )
    assert not ldap._is_in_required_ou(
        "CN=Ivan,OU=t10,OU=Users,DC=example,DC=local",
        settings,
    )
    assert not ldap._is_in_required_ou(
        "CN=Ivan,OU=Users,DC=example,DC=local",
        settings,
    )
