"""Integration: LDAP login flows against real PostgreSQL.

Covers local-user auth, provisioning, the disabled-user regression, username
contention under parallel first logins, sessions and the audit trail.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import auth, main

PASSWORD = "S3cure-Passw0rd!"


def _identity(role: str = "viewer") -> dict[str, Any]:
    return {"username": "ldap.user", "display_name": "Ldap User", "role": role}


def _make_user(username: str, role: str = "viewer", active: bool = True) -> int:
    from app import db

    current = db.now_utc()
    with db.connect() as conn:
        row = conn.execute(
            """INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
               VALUES(%s,%s,%s,%s,%s,%s) RETURNING id""",
            (username, username.title(), auth.hash_password(PASSWORD), active, current, current),
        ).fetchone()
        role_row = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (role,)).fetchone()
        assert row is not None and role_row is not None
        conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role_row["id"]))
    return int(row["id"])


def _user_row(username: str) -> dict[str, Any] | None:
    from app import db

    with db.connect() as conn:
        row = conn.execute("SELECT * FROM app_users WHERE username=%s", (username,)).fetchone()
    return dict(row) if row else None


def _permissions(username: str) -> list[str]:
    from app import db

    with db.connect() as conn:
        user = conn.execute("SELECT id FROM app_users WHERE username=%s", (username,)).fetchone()
        rows = conn.execute(
            """SELECT DISTINCT rp.permission_key FROM app_user_roles ur
               JOIN app_role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=%s ORDER BY 1""",
            (user["id"],),
        ).fetchall()
    return [row["permission_key"] for row in rows]


def test_local_active_user_logs_in(test_db):
    _make_user("local.ops", role="operator")
    client = TestClient(main.app)
    response = client.post("/api/auth/login", json={"username": "local.ops", "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["user"]["role"] == "operator"
    assert "tasks.execute" in body["user"]["permissions"]


def test_local_inactive_user_cannot_log_in_even_with_correct_password(test_db):
    _make_user("local.off", role="operator", active=False)
    client = TestClient(main.app)
    response = client.post("/api/auth/login", json={"username": "local.off", "password": PASSWORD})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"


def test_ldap_first_login_provisions_user_with_configured_role(test_db):
    with patch_ldap(_identity(role="operator")):
        client = TestClient(main.app)
        response = client.post("/api/auth/login", json={"username": "ldap.user", "password": "x"})
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "operator"
    row = _user_row("ldap.user")
    assert row is not None and row["is_active"] is True
    assert "tasks.execute" in _permissions("ldap.user")


def test_ldap_relogin_reuses_provisioned_user(test_db):
    with patch_ldap(_identity(role="operator")):
        client = TestClient(main.app)
        first = client.post("/api/auth/login", json={"username": "ldap.user", "password": "x"})
    assert first.status_code == 200
    user_id = _user_row("ldap.user")["id"]
    with patch_ldap(_identity(role="operator")):
        client = TestClient(main.app)
        second = client.post("/api/auth/login", json={"username": "ldap.user", "password": "x"})
    assert second.status_code == 200
    assert _user_row("ldap.user")["id"] == user_id  # no duplicate row


def test_ldap_login_rejects_disabled_local_user(test_db):
    """Regression: a locally disabled account stays disabled; LDAP must not
    resurrect it (previously this crashed with a 500 UniqueViolation)."""
    _make_user("ldap.user", role="viewer", active=False)
    with patch_ldap(_identity(role="viewer")):
        client = TestClient(main.app)
        response = client.post("/api/auth/login", json={"username": "ldap.user", "password": "x"})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"
    assert _user_row("ldap.user")["is_active"] is False


def test_ldap_login_unknown_user_and_bad_password_rejected(test_db):
    from app.ldap import LdapError

    with patch_ldap_error(LdapError("user_not_found")):
        client = TestClient(main.app)
        response = client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert response.status_code == 401

    with patch_ldap_error(LdapError("bad_credentials")):
        client = TestClient(main.app)
        response = client.post("/api/auth/login", json={"username": "ldap.user", "password": "x"})
    assert response.status_code == 401
    assert _user_row("ldap.user") is None


def test_parallel_ldap_first_logins_provision_exactly_one_user(test_db):
    """Two simultaneous first logins race on the username constraint."""
    from app import db

    errors: list[BaseException] = []
    statuses: list[int] = []
    barrier = threading.Barrier(2)

    # Patch the shared ``resolve_ldap_identity`` global ONCE around all threads.
    # Patching it separately from each thread is racy: ``mock.patch`` start/stop
    # is not atomic, so two threads saving/restoring the same attribute in a
    # bad interleaving can leave the global permanently mocked, leaking into
    # later tests (a bad-password login would then "succeed" via the stale mock).
    def call():
        try:
            barrier.wait()
            client = TestClient(main.app)
            statuses.append(client.post(
                "/api/auth/login", json={"username": "ldap.user", "password": "x"}
            ).status_code)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with patch_ldap(_identity(role="viewer")):
        threads = [threading.Thread(target=call) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert errors == []
    assert sorted(statuses) == [200, 200]
    with db.connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM app_users WHERE username='ldap.user'").fetchone()
    assert int(row["count"]) == 1


def test_failed_logins_are_rate_limited(test_db):
    auth.LOGIN_LIMITER._entries.clear()  # the limiter is process-global
    with patch_ldap_error(None):
        client = TestClient(main.app)
        responses = [
            client.post("/api/auth/login", json={"username": "ghost", "password": str(i)})
            for i in range(auth.LoginLimiter().attempts + 1)
        ]
    assert all(response.status_code == 401 for response in responses[:-1])
    assert responses[-1].status_code == 429
    assert responses[-1].json()["detail"]["code"] == "LOGIN_RATE_LIMIT"


def test_logout_revokes_session(test_db):
    _make_user("local.ops", role="viewer")
    client = TestClient(main.app)
    login = client.post("/api/auth/login", json={"username": "local.ops", "password": PASSWORD})
    assert login.status_code == 200
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    from app import db

    with db.connect() as conn:
        row = conn.execute("SELECT revoked_at FROM app_auth_sessions").fetchone()
    assert row is not None and row["revoked_at"] is not None


def test_expired_and_unknown_sessions_are_rejected(test_db):
    _make_user("local.ops", role="viewer")
    client = TestClient(main.app)
    client.post("/api/auth/login", json={"username": "local.ops", "password": PASSWORD})
    from app import db

    # Expire the session in the database.
    with db.connect() as conn:
        conn.execute("UPDATE app_auth_sessions SET expires_at='2000-01-01T00:00:00'")
    client = TestClient(main.app)
    assert client.get("/api/auth/me").status_code == 401
    client = TestClient(main.app)
    client.cookies.set(auth.COOKIE_NAME, "unknown-token")
    assert client.get("/api/auth/me").status_code == 401


def _audit_diagnostic(missing: list[tuple[str, str]], events: set) -> str:
    """Build a detailed diagnostic string when an expected audit row is absent."""
    from app import db

    parts = [f"missing_audit_rows={missing}", f"present={sorted(events)}"]
    circuit = db.database_circuit_status()
    parts.append(f"circuit_open={circuit['open']} reason={circuit.get('reason')} msg={circuit.get('message')}")
    # Live connection count vs the server ceiling — the usual cause of a
    # transient connect failure that audit_event would swallow.
    try:
        with db.connect() as conn:
            live = conn.execute(
                "SELECT count(*) AS c FROM pg_stat_activity WHERE datname=current_database()"
            ).fetchone()["c"]
            maxc = conn.execute("SHOW max_connections").fetchone()[0]
        parts.append(f"pg_connections={live}/{maxc}")
    except Exception as exc:  # pragma: no cover - diagnostic only
        parts.append(f"pg_connections=UNAVAILABLE({type(exc).__name__})")
    # Is a fresh INSERT working right now?
    import json
    import traceback

    try:
        with db.connect() as conn2:
            conn2.execute(
                """INSERT INTO app_auth_audit_events(actor_user_id,actor_username,event_type,permission_key,decision,target_type,target_id,ip_address,user_agent,trace_id,request_id,details_json,created_at)
                   VALUES(NULL,'diag','login',NULL,'deny',NULL,NULL,NULL,NULL,NULL,NULL,%s,%s)""",
                (json.dumps({"diagnostic": True}), db.now_utc()),
            )
            parts.append("manual_insert=OK(transient)")
    except Exception:
        parts.append(f"manual_insert=FAIL({traceback.format_exc().splitlines()[-1]})")
    return "; ".join(parts)


def test_audit_events_record_login_decisions(test_db):
    _make_user("local.ops", role="viewer")
    client = TestClient(main.app)
    r1 = client.post("/api/auth/login", json={"username": "local.ops", "password": PASSWORD})
    r2 = client.post("/api/auth/login", json={"username": "local.ops", "password": "wrong"})
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 401, r2.text
    from app import db

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT event_type, decision FROM app_auth_audit_events ORDER BY id"
        ).fetchall()
    events = {(row["event_type"], row["decision"]) for row in rows}
    missing = [e for e in (("login", "allow"), ("login", "deny")) if e not in events]
    assert not missing, _audit_diagnostic(missing, events)


def test_local_mode_does_not_call_ldap(test_db):
    def _boom(*args, **kwargs):
        raise AssertionError("LDAP must not be called for auth_type=local")

    _make_user("local.ops", role="viewer")
    with patch_ldap(_boom):
        client = TestClient(main.app)
        response = client.post(
            "/api/auth/login",
            json={"username": "local.ops", "password": PASSWORD, "auth_type": "local"},
        )
    assert response.status_code == 200


class _LdapPatch:
    def __init__(self, identity: dict[str, Any] | None, error: Exception | None):
        self.identity = identity
        self.error = error

    def __enter__(self):
        self._identity_patch = patch.object(auth, "resolve_ldap_identity", self._resolve)
        self._identity_patch.start()
        return self

    def _resolve(self, username, password):
        if self.error is not None:
            raise self.error
        return self.identity

    def __exit__(self, *exc):
        self._identity_patch.stop()


def patch_ldap(identity: dict[str, Any] | None):
    return _LdapPatch(identity, None)


def patch_ldap_error(error: Exception | None):
    return _LdapPatch(None, error)
