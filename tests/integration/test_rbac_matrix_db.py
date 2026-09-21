"""Integration: a single authorization matrix over real PostgreSQL.

The matrix crosses four real, provisioned users (``admin``, ``operator``,
``viewer`` and an authenticated-but-permissionless ``none`` account) against a
curated set of protected API routes.  For every cell the *expected* decision is
derived from the live authorization policy (``app.auth.required_permission``)
and the role's real permission set as stored in ``app_role_permissions``:

* permission required and **not** held  -> ``403 PERMISSION_DENIED``
* permission held (or no policy)        -> the request passes the gate and the
  handler answers a ``2xx`` (every route is chosen so the success is local-DB
  and deterministic on a fresh database, with no MP VM connection available).

This asserts, over a real database and real sessions, that the auth middleware
enforces exactly the declarative policy - nothing more, nothing less.  The four
roles are deliberately differentiated: ``admin`` holds every permission,
``operator`` adds the mutation permissions on top of ``viewer`` (e.g.
``saved_views.manage``), ``viewer`` holds the read-only set, and ``none`` holds
none - so the matrix is only meaningful if those sets actually differ in the
``app_role_permissions`` table.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import auth, db, main

PASSWORD = "S3cure-Passw0rd!"

# (method, request_path, policy_path, body)
# ``policy_path`` is the path (no query string) fed to ``required_permission``;
# ``request_path`` may carry query params so the handler resolves; ``body`` is a
# JSON body for mutation routes (None for pure reads).
ROUTES: list[tuple[str, str, str, dict | None]] = [
    ("GET", "/api/system/status", "/api/system/status", None),
    ("GET", "/api/defaults", "/api/defaults", None),
    ("GET", "/api/operations", "/api/operations", None),
    ("GET", "/api/operations/summary", "/api/operations/summary", None),
    ("GET", "/api/saved-views?route=assets", "/api/saved-views", None),
    ("GET", "/api/asset-cards/local", "/api/asset-cards/local", None),
    ("GET", "/api/assets", "/api/assets", None),
    ("GET", "/api/assets/summary", "/api/assets/summary", None),
    ("GET", "/api/asset-groups/tree", "/api/asset-groups/tree", None),
    ("GET", "/api/vm/workflows", "/api/vm/workflows", None),
    ("GET", "/api/vm/overview", "/api/vm/overview", None),
    ("GET", "/api/remediation/policy", "/api/remediation/policy", None),
    ("GET", "/api/risk/queue", "/api/risk/queue", None),
    ("GET", "/api/risk/summary", "/api/risk/summary", None),
    ("GET", "/api/automations/runbooks", "/api/automations/runbooks", None),
    ("GET", "/api/notifications", "/api/notifications", None),
    ("GET", "/api/asset-card-query/fields", "/api/asset-card-query/fields", None),
    ("GET", "/api/asset-card-query/presets", "/api/asset-card-query/presets", None),
    ("GET", "/api/vulnerability-passports/local", "/api/vulnerability-passports/local", None),
    ("GET", "/api/vulnerabilities/summary", "/api/vulnerabilities/summary", None),
    ("GET", "/api/coverage/summary", "/api/coverage/summary", None),
    ("GET", "/api/attention", "/api/attention", None),
    ("GET", "/api/auth/permissions", "/api/auth/permissions", None),
    ("GET", "/api/auth/roles", "/api/auth/roles", None),
    ("GET", "/api/auth/users", "/api/auth/users", None),
    ("GET", "/api/auth/audit", "/api/auth/audit", None),
    ("POST", "/api/diagnostics/frontend", "/api/diagnostics/frontend",
     {"events": [{"event": "matrix-probe", "level": "info"}]}),
    # A safe, local-DB mutation that differentiates operator from viewer:
    # it needs ``saved_views.manage`` (held by operator/admin, not viewer).
    ("POST", "/api/saved-views", "/api/saved-views",
     {"route": "assets", "name": "matrix-view", "filters": {}}),
]

ROLES = ["admin", "operator", "viewer", "none"]
CASES = [(role, method, request_path, policy_path, body)
         for (method, request_path, policy_path, body) in ROUTES
         for role in ROLES]


def _truncate_all() -> None:
    """Wipe every application table (keeps alembic_version) for a clean matrix."""
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'alembic_version'"
        ).fetchall()
        tables = [row["tablename"] for row in rows]
        if tables:
            conn.execute(f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE")


def _seed_sla_policy() -> None:
    """Restore the single SLA policy row that migration 0006 seeds on install."""
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO remediation_sla_policy (policy_id) VALUES (1) "
            "ON CONFLICT (policy_id) DO NOTHING"
        )


def _create_user(username: str, role_key: str | None) -> None:
    current = db.now_utc()
    with db.connect() as conn:
        row = conn.execute(
            """INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
               VALUES(%s,%s,%s,TRUE,%s,%s) RETURNING id""",
            (username, username.title(), auth.hash_password(PASSWORD), current, current),
        ).fetchone()
        assert row is not None
        if role_key:
            role = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (role_key,)).fetchone()
            assert role is not None
            conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role["id"]))


def _login(username: str) -> TestClient:
    client = TestClient(main.app)
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return client


def _role_permissions(role_key: str | None) -> set[str]:
    if role_key is None:
        return set()
    with db.connect() as conn:
        rows = conn.execute(
            """SELECT DISTINCT rp.permission_key FROM app_roles r
               JOIN app_role_permissions rp ON rp.role_id=r.id WHERE r.role_key=%s""",
            (role_key,),
        ).fetchall()
    return {row["permission_key"] for row in rows}


@pytest.fixture(scope="module")
def rbac_matrix(migrated_db):
    """Provision the four users once and return their logged-in clients + perms."""
    _truncate_all()
    auth.ensure_rbac_catalog()
    _seed_sla_policy()  # /api/remediation/policy needs the 0006 seed row
    _create_user("matrix.admin", "admin")
    _create_user("matrix.operator", "operator")
    _create_user("matrix.viewer", "viewer")
    _create_user("matrix.none", None)  # authenticated, but zero permissions

    clients = {role: _login(f"matrix.{role}") for role in ROLES}
    permissions = {
        "admin": _role_permissions("admin"),
        "operator": _role_permissions("operator"),
        "viewer": _role_permissions("viewer"),
        "none": set(),
    }
    # Sanity: the catalog must actually differentiate the roles, otherwise the
    # matrix would be meaningless (e.g. viewer accidentally holding security.*).
    assert "security.users.read" in permissions["admin"]
    assert "security.users.read" not in permissions["viewer"]
    assert "tasks.execute" in permissions["operator"]
    assert "tasks.execute" not in permissions["viewer"]
    assert "saved_views.manage" in permissions["operator"]
    assert "saved_views.manage" not in permissions["viewer"]
    assert permissions["none"] == set()
    return {"clients": clients, "permissions": permissions}


@pytest.mark.parametrize("role,method,request_path,policy_path,body", CASES,
                         ids=[f"{r}-{m}-{rp}" for (r, m, rp, _, _) in CASES])
def test_rbac_matrix_enforcement(role, method, request_path, policy_path, body, rbac_matrix):
    client = rbac_matrix["clients"][role]
    held = rbac_matrix["permissions"][role]
    required = auth.required_permission(method, policy_path)

    denied = required is not None and (required == "__deny__" or required not in held)

    response = client.request(method, request_path, json=body)

    if denied:
        assert response.status_code == 403, (role, method, request_path, response.status_code)
        assert response.json()["detail"]["code"] == "PERMISSION_DENIED"
    else:
        assert response.status_code < 400, (
            role, method, request_path, response.status_code, response.text[:300]
        )


def test_rbac_matrix_differentiates_roles(rbac_matrix):
    """The matrix must be a genuine matrix: each role yields a distinct decision profile."""
    profiles: dict[str, tuple[int, int]] = {}
    for role in ROLES:
        held = rbac_matrix["permissions"][role]
        allowed = denied = 0
        for (m, _rp, pp, _b) in ROUTES:
            required = auth.required_permission(m, pp)
            if required is not None and (required == "__deny__" or required not in held):
                denied += 1
            else:
                allowed += 1
        profiles[role] = (allowed, denied)

    # admin allows everything; none allows nothing.
    assert profiles["admin"] == (len(ROUTES), 0)
    assert profiles["none"] == (0, len(ROUTES))
    # operator is strictly more permissive than viewer on this route set
    # (via saved_views.manage), and both are strictly more permissive than none.
    assert profiles["operator"][0] > profiles["viewer"][0]
    assert profiles["viewer"][0] > profiles["none"][0]
    # the four profiles are pairwise distinct
    assert len({profiles[role] for role in ROLES}) == len(ROLES)
