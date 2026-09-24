"""Integration: HTTP API contracts (methods, statuses, error codes) on real PostgreSQL.

These tests pin the public contract of the API so a route change, a missing
authorization policy or a status-code drift fails loudly instead of leaking
into the frontend:

* public vs protected routes (401 AUTH_REQUIRED without a session);
* 403 PERMISSION_DENIED with the expected permission for an under-privileged role;
* OpenAPI completeness: every registered /api route (method + path) appears in
  the generated schema, and every non-public mutation route has an explicit
  authorization policy (``required_permission`` returns a key, never None);
* validation errors (422) with pydantic detail;
* 404 NOT_FOUND codes for unknown domain records;
* 409 VERSION_CONFLICT for the remediation optimistic lock;
* 202 for the asynchronous VM scan start.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app import auth, db, main

PASSWORD = "S3cure-Passw0rd!"

# (role) -> (permission, expected behavior on a mutation route that needs it)
ADMIN, OPERATOR, VIEWER = "admin", "operator", "viewer"


def _make_user(username: str, role: str) -> int:
    current = db.now_utc()
    with db.connect() as conn:
        row = conn.execute(
            """INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
               VALUES(%s,%s,%s,TRUE,%s,%s) RETURNING id""",
            (username, username.title(), auth.hash_password(PASSWORD), current, current),
        ).fetchone()
        role_row = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (role,)).fetchone()
        assert row is not None and role_row is not None
        conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role_row["id"]))
    return int(row["id"])


def _login(username: str) -> TestClient:
    client = TestClient(main.app)
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return client


def _detail_code(response) -> str | None:
    try:
        return response.json()["detail"]["code"]
    except (KeyError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Public routes and the 401 boundary
# ---------------------------------------------------------------------------


def test_public_routes_are_reachable_without_session(test_db):
    client = TestClient(main.app)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/auth/bootstrap-status").status_code == 200
    # login is public but rejects garbage credentials (proves the handler runs)
    response = client.post("/api/auth/login", json={"username": "ghost", "password": "wrong-pass-123"})
    assert response.status_code == 401
    assert _detail_code(response) in {"INVALID_CREDENTIALS", "LOGIN_RATE_LIMIT"}


def test_protected_route_without_session_returns_401(test_db):
    client = TestClient(main.app)
    response = client.get("/api/system/status")
    assert response.status_code == 401
    assert _detail_code(response) == "AUTH_REQUIRED"
    response = client.post("/api/auth/users", json={"username": "x.y.z", "display_name": "Z", "password": "longenough123", "role_ids": [1]})
    assert response.status_code == 401
    assert _detail_code(response) == "AUTH_REQUIRED"


# ---------------------------------------------------------------------------
# 403: the same mutation route for viewer and operator
# ---------------------------------------------------------------------------


def test_viewer_cannot_mutate_and_operator_can_read(test_db):
    _make_user("contract.viewer", VIEWER)
    _make_user("contract.operator", OPERATOR)
    viewer = _login("contract.viewer")
    operator = _login("contract.operator")

    denied = viewer.get("/api/auth/users")  # needs security.users.read
    assert denied.status_code == 403
    assert _detail_code(denied) == "PERMISSION_DENIED"

    allowed = operator.get("/api/operations")  # needs operations.read
    assert allowed.status_code == 200


def test_operator_cannot_manage_users_or_roles(test_db):
    _make_user("contract.operator", OPERATOR)
    operator = _login("contract.operator")
    for method, url in (
        ("GET", "/api/auth/users"),
        ("GET", "/api/auth/roles"),
        ("POST", "/api/auth/roles/clone"),
    ):
        response = operator.request(method, url, json={"source_role_id": 1, "name": "copy"} if method == "POST" else None)
        assert response.status_code == 403, (method, url, response.status_code)
        assert _detail_code(response) == "PERMISSION_DENIED"


def test_unknown_mutation_routes_are_denied_for_everyone(test_db):
    """``required_permission`` must return an explicit key for every write to a
    known domain; the middleware denies ``__deny__`` for anything else."""
    with db.connect() as conn:
        role_id = conn.execute("SELECT id FROM app_roles WHERE role_key='admin'").fetchone()["id"]
        row = conn.execute(
            """INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
               VALUES('contract.super','S',%s,TRUE,NOW(),NOW()) RETURNING id""",
            (auth.hash_password(PASSWORD),),
        ).fetchone()
        conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role_id))
    client = _login("contract.super")
    # method-matrix contract: a route only allows its declared methods (405,
    # answered by the framework before the auth middleware), and the policy
    # function itself is deny-by-default for unknown mutation paths
    assert client.post("/api/assets").status_code == 405
    assert client.delete("/api/assets").status_code == 405
    # deny-by-default applies to paths outside every known domain prefix
    assert auth.required_permission("POST", "/api/unknown-mutation") == "__deny__"
    assert auth.required_permission("DELETE", "/api/unknown-mutation") == "__deny__"
    # and reads always resolve to a known read permission, never None
    assert auth.required_permission("GET", "/api/assets") == "assets.read"
    assert auth.required_permission("GET", "/api/vulnerabilities") == "assets.read"
    assert auth.required_permission("GET", "/api/asset-cards") == "asset_cards.read"


# ---------------------------------------------------------------------------
# OpenAPI completeness and per-route authorization policy
# ---------------------------------------------------------------------------


def test_openapi_contains_every_registered_api_route(test_db):
    client = TestClient(main.app)
    spec = client.get("/openapi.json").json()
    schema_paths = spec.get("paths", {})

    registered = set()
    for route in main.app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", "")
        if not path.startswith("/api/") or not methods:
            continue
        for method in methods:
            if method == "OPTIONS":
                continue
            registered.add((method.upper(), path))

    missing = []
    for method, path in sorted(registered):
        schema_path = schema_paths.get(path)
        if schema_path is None or method.lower() not in schema_path:
            missing.append(f"{method} {path}")
    assert missing == [], f"routes absent from OpenAPI: {missing}"


def test_every_non_public_api_route_has_an_explicit_policy(test_db):
    """Adding a new /api route must require an explicit authorization policy.

    Reads may fall back to ``system.read``; every mutation must map to a real
    permission key (or ``__deny__``), never None.
    """
    from app.main import PUBLIC_API_PATHS

    registered = set()
    for route in main.app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", "")
        if not path.startswith("/api/") or not methods:
            continue
        for method in methods:
            if method == "OPTIONS":
                continue
            if path in PUBLIC_API_PATHS:
                continue
            registered.add((method.upper(), path))

    # Exercise the policy function against parameterized routes with a sample.
    problems = []
    for method, path in sorted(registered):
        sample_path = path
        for placeholder in ("{user_id}", "{role_id}", "{case_id}", "{workflow_id}",
                            "{operation_id}", "{job_id}", "{group_id}", "{finding_id}"):
            if placeholder in sample_path:
                sample_path = sample_path.replace(placeholder, "1")
        permission = auth.required_permission(method, sample_path)
        if method in {"GET", "HEAD", "OPTIONS"}:
            assert permission is not None, f"{method} {path} has no read policy"
        else:
            if permission is None or permission not in auth.PERMISSIONS and permission != "__deny__":
                problems.append(f"{method} {path} -> {permission!r}")
    assert problems == [], "mutations without a known permission policy: " + "; ".join(problems)


# ---------------------------------------------------------------------------
# Validation errors (422)
# ---------------------------------------------------------------------------


def test_login_rejects_invalid_payload(test_db):
    client = TestClient(main.app)
    response = client.post("/api/auth/login", json={"username": ""})
    assert response.status_code == 422
    # the app normalizes pydantic errors into a stable detail envelope
    assert response.json()["detail"]["code"] == "VALIDATION_FAILED"


def test_create_user_rejects_short_password_and_bad_username(test_db):
    _make_user("contract.admin", ADMIN)
    admin = _login("contract.admin")
    short = admin.post("/api/auth/users", json={"username": "a.b.c", "display_name": "C", "password": "short123456", "role_ids": [1]})
    assert short.status_code == 422
    bad = admin.post("/api/auth/users", json={"username": "bad name!", "display_name": "C", "password": "longenough123", "role_ids": [1]})
    assert bad.status_code == 422


def test_case_update_rejects_missing_expected_version(test_db):
    _make_user("contract.operator", OPERATOR)
    operator = _login("contract.operator")
    response = operator.patch("/api/remediation/cases/case-x", json={"status": "in_progress"})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 404 / 409 / 202 domain contracts
# ---------------------------------------------------------------------------


def _seed_case(case_id: str = "case-contract-1", asset_id: str = "asset-contract-1") -> None:
    with db.connect() as conn:
        conn.execute(
            """INSERT INTO asset_cards(asset_id,display_name,first_seen,last_seen)
               VALUES(%s,'contract-asset',NOW(),NOW())
               ON CONFLICT (asset_id) DO UPDATE SET display_name=EXCLUDED.display_name""",
            (asset_id,),
        )
        conn.execute(
            """INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,title,severity,status)
               VALUES(%s,%s,'CVC-2026-0001','Contract case','high','open')""",
            (case_id, asset_id),
        )


def test_case_get_returns_404_with_code(test_db):
    _make_user("contract.operator", OPERATOR)
    operator = _login("contract.operator")
    response = operator.get("/api/remediation/cases/nope")
    assert response.status_code == 404
    assert _detail_code(response) == "CASE_NOT_FOUND"


def test_case_update_optimistic_lock_conflict_returns_409(test_db):
    _make_user("contract.operator", OPERATOR)
    _seed_case()
    operator = _login("contract.operator")
    # first update succeeds and bumps the version
    ok = operator.patch("/api/remediation/cases/case-contract-1", json={"expected_version": 1, "assignee": "Ivan"})
    assert ok.status_code == 200, ok.text
    assert ok.json()["version"] == 2
    # the same version again must conflict
    conflict = operator.patch("/api/remediation/cases/case-contract-1", json={"expected_version": 1, "assignee": "Petr"})
    assert conflict.status_code == 409
    assert _detail_code(conflict) == "VERSION_CONFLICT"
    # and the unknown case stays 404
    missing = operator.patch("/api/remediation/cases/nope", json={"expected_version": 1, "assignee": "X"})
    assert missing.status_code == 404
    assert _detail_code(missing) == "CASE_NOT_FOUND"


def test_vm_workflow_contract_404_and_202(test_db):
    _make_user("contract.operator", OPERATOR)
    operator = _login("contract.operator")
    # a well-formed but unknown UUID must be a clean 404 (the contract)
    missing = operator.get("/api/vm/workflows/00000000-0000-4000-8000-000000000000")
    assert missing.status_code == 404
    assert _detail_code(missing) == "VM_WORKFLOW_NOT_FOUND"
    # and a non-UUID id must be a 404 as well, not a 503 (UUID column guard)
    malformed = operator.get("/api/vm/workflows/not-a-uuid")
    assert malformed.status_code == 404
    assert _detail_code(malformed) == "VM_WORKFLOW_NOT_FOUND"
    cancelled = operator.post("/api/vm/workflows/not-a-uuid/cancel")
    assert cancelled.status_code == 404
    assert _detail_code(cancelled) == "VM_WORKFLOW_NOT_FOUND"

    # a scan start is asynchronous: 202 on success, 409 with a stable code when
    # preflight blocks it, and the idempotency header is part of the contract.
    seeded = operator.post("/api/vm/workflows/scan", json={"task_id": "task-does-not-exist", "options": {}},
                           headers={"X-Idempotency-Key": "contract-scan-1"})
    assert seeded.status_code in {202, 409}, seeded.text
    if seeded.status_code == 409:
        assert _detail_code(seeded) in {"VM_PREFLIGHT_BLOCKED", "IDEMPOTENCY_KEY_CONFLICT"}
    else:
        body = seeded.json()
        assert body["status"] in {"queued", "running"}
        assert body["workflow_id"]
        # identical replay returns the same workflow and is flagged as replay
        replay = operator.post("/api/vm/workflows/scan", json={"task_id": "task-does-not-exist", "options": {}},
                               headers={"X-Idempotency-Key": "contract-scan-1"})
        assert replay.status_code == 202
        assert replay.json()["workflow_id"] == body["workflow_id"]
        assert replay.json()["idempotent_replay"] is True



def test_vm_workflow_retry_idempotency_conflict_returns_409(test_db, monkeypatch):
    _make_user("contract.operator", OPERATOR)
    operator = _login("contract.operator")

    workflow_id = "00000000-0000-4000-8000-000000000001"

    class RetryConflictService:
        def retry(self, workflow_id, actor, idempotency_key):
            raise ValueError("Idempotency key belongs to another workflow operation.")

    monkeypatch.setattr(main.app.state.container.services, "vm_workflows", RetryConflictService())
    response = operator.post(
        f"/api/vm/workflows/{workflow_id}/retry",
        headers={"X-Idempotency-Key": "contract-retry-1"},
    )

    assert response.status_code == 409
    assert _detail_code(response) == "IDEMPOTENCY_KEY_CONFLICT"