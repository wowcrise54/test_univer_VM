"""Integration: MCP personal access tokens over real PostgreSQL, sessions and RBAC.

The token is checked by the application, which opens a session of the token
owner capped to the token's read scopes. These tests pin that the cap holds even
for an administrator owner, that revoking, expiry and a disabled owner end
access at once, and that every decision lands in the audit log.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import auth, db, main
from app.services import mcp_tokens
from app.services.mcp_tokens import McpTokenAuthenticator
from mcp_server.embed import install_embedded_mcp
from mcp_server.principal import AuthRejected
from tests.integration.test_api_contracts_db import PASSWORD
from tests.integration.test_api_contracts_db import _make_user as _user
from tests.integration.test_mcp_server_db import _card, _finding
from tests.mcp_server.fakes import make_settings

pytestmark = pytest.mark.integration

SCOPE = {"type": "http", "client": ("203.0.113.9", 5000), "headers": [], "method": "POST", "path": "/mcp"}


def _login(username: str, app: Any = None) -> TestClient:
    client = TestClient(app or main.app)
    response = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return client


@pytest.fixture(autouse=True)
def fresh_limiters():
    for limiter in (mcp_tokens._IP_LIMITER, mcp_tokens._TOKEN_LIMITER):
        limiter._entries.clear()
    yield


@pytest.fixture
def world(test_db):
    return {"admin": _user("root", "admin"), "viewer": _user("viewer-one", "viewer"), "operator": _user("operator-one", "operator")}


def _issue(admin: TestClient, **overrides: Any) -> dict[str, Any]:
    body = {"name": "claude-code", "scopes": ["vulnerabilities:read"], **overrides}
    response = admin.post("/api/auth/mcp-tokens", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _rows(sql: str, *params: Any) -> list[dict[str, Any]]:
    with db.connect() as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _audit(event_type: str) -> list[dict[str, Any]]:
    return _rows("SELECT * FROM app_auth_audit_events WHERE event_type=%s ORDER BY id", event_type)


def _details(event: dict[str, Any]) -> dict[str, Any]:
    return json.loads(event["details_json"])


def _reject(token: str, scope: dict[str, Any] = SCOPE) -> AuthRejected:
    with pytest.raises(AuthRejected) as caught:
        mcp_tokens.authenticate(token, scope=scope)
    return caught.value


def test_an_administrator_issues_a_token_whose_secret_is_shown_once_and_stored_hashed(world):
    admin = _login("root")
    issued = _issue(admin, expires_in_days=30)

    assert issued["token"].startswith(issued["token_id"] + "_") and issued["status"] == "active"
    assert issued["owner"]["username"] == "root" and issued["scopes"] == ["vulnerabilities:read"]
    expires = datetime.fromisoformat(issued["expires_at"])
    assert timedelta(days=29, hours=23) < expires - datetime.now(UTC) <= timedelta(days=30, minutes=1)

    stored = _rows("SELECT * FROM app_mcp_tokens")[0]
    secret = issued["token"].split("_", 3)[3]
    assert secret not in json.dumps(stored, default=str) and stored["secret_hash"] != secret

    listing = admin.get("/api/auth/mcp-tokens").json()
    assert secret not in json.dumps(listing) and "token" not in listing["rows"][0]
    assert {scope["key"] for scope in listing["scopes"]} == set(mcp_tokens.MCP_SCOPES)

    created = _audit("mcp_token_created")
    assert len(created) == 1 and created[0]["actor_username"] == "root"
    assert secret not in created[0]["details_json"] and _details(created[0])["name"] == "claude-code"


def test_only_administrators_manage_tokens(world):
    for username in ("viewer-one", "operator-one"):
        client = _login(username)
        assert client.get("/api/auth/mcp-tokens").status_code == 403
        assert client.post("/api/auth/mcp-tokens", json={"name": "x", "scopes": ["risk:read"]}).status_code == 403
        assert client.post("/api/auth/mcp-tokens/1/revoke").status_code == 403
        assert client.post("/api/auth/mcp-tokens/1/rotate", json={}).status_code == 403
    assert _rows("SELECT * FROM app_mcp_tokens") == []


@pytest.mark.parametrize(
    "overrides,status,code",
    [
        ({"scopes": ["vulnerabilities:read", "tasks.manage"]}, 422, "INVALID_SCOPES"),
        ({"scopes": ["write:everything"]}, 422, "INVALID_SCOPES"),
        ({"ip_allowlist": ["not-an-ip"]}, 422, "INVALID_IP_ALLOWLIST"),
        ({"owner_user_id": 999999}, 404, "USER_NOT_FOUND"),
    ],
)
def test_invalid_token_requests_are_rejected(world, overrides, status, code):
    response = _login("root").post("/api/auth/mcp-tokens", json={"name": "t", "scopes": ["risk:read"], **overrides})
    assert response.status_code == status and response.json()["detail"]["code"] == code
    assert _rows("SELECT * FROM app_mcp_tokens") == []


def test_request_validation_bounds_lifetime_and_scopes(world):
    admin = _login("root")
    for body in (
        {"name": "t", "scopes": ["risk:read"], "expires_in_days": 0},
        {"name": "t", "scopes": ["risk:read"], "expires_in_days": 366},
        {"name": "t", "scopes": []},
        {"name": "", "scopes": ["risk:read"]},
        {"name": "t", "scopes": ["risk:read"], "unexpected": 1},
    ):
        assert admin.post("/api/auth/mcp-tokens", json=body).status_code == 422, body


def test_a_token_cannot_be_issued_for_a_disabled_owner_or_beyond_the_limit(world):
    admin = _login("root")
    with db.connect() as conn:
        conn.execute("UPDATE app_users SET is_active=FALSE WHERE id=%s", (world["viewer"],))
    response = admin.post("/api/auth/mcp-tokens", json={"name": "t", "scopes": ["risk:read"], "owner_user_id": world["viewer"]})
    assert response.status_code == 409 and response.json()["detail"]["code"] == "OWNER_INACTIVE"

    for index in range(mcp_tokens.MAX_ACTIVE_TOKENS_PER_OWNER):
        _issue(admin, name=f"t{index}")
    response = admin.post("/api/auth/mcp-tokens", json={"name": "one-too-many", "scopes": ["risk:read"]})
    assert response.status_code == 409 and response.json()["detail"]["code"] == "TOKEN_LIMIT"


def test_a_valid_token_authenticates_and_records_its_use(world):
    issued = _issue(_login("root"), ip_allowlist=["203.0.113.0/24"])
    principal = mcp_tokens.authenticate(issued["token"], scope=SCOPE)

    assert principal.owner_username == "root"
    assert principal.token_id == issued["token_id"] and principal.client_ip == "203.0.113.9"
    used = _rows("SELECT last_used_at, last_used_ip FROM app_mcp_tokens")[0]
    assert used["last_used_at"] is not None and used["last_used_ip"] == "203.0.113.9"


def test_every_kind_of_bad_token_is_refused_the_same_way_and_audited(world):
    admin = _login("root")
    good = _issue(admin, name="good", ip_allowlist=["203.0.113.0/24"])["token"]
    expired = _issue(admin, name="expired")
    revoked = _issue(admin, name="revoked")
    disabled_owner = _issue(admin, name="disabled", owner_user_id=world["viewer"])
    with db.connect() as conn:
        conn.execute("UPDATE app_mcp_tokens SET expires_at=%s WHERE id=%s", (datetime.now(UTC) - timedelta(minutes=1), expired["id"]))
        conn.execute("UPDATE app_users SET is_active=FALSE WHERE id=%s", (world["viewer"],))
    assert admin.post(f"/api/auth/mcp-tokens/{revoked['id']}/revoke").status_code == 200

    public_id, secret = good.split("_", 3)[2:]
    cases = {
        "malformed": "not-a-token",
        "malformed_secret": f"mpvm_mcp_{public_id}_short",
        "unknown_or_wrong_secret": f"mpvm_mcp_{public_id}_{'x' * len(secret)}",
        "unknown_id": f"mpvm_mcp_{'0' * 12}_{secret}",
        "expired": expired["token"],
        "revoked": revoked["token"],
        "owner_inactive": disabled_owner["token"],
    }
    for name, token in cases.items():
        error = _reject(token)
        assert (error.status, error.retry_after) == (401, None), name
    other_network = {**SCOPE, "client": ("198.51.100.7", 1)}
    assert _reject(good, other_network).status == 401

    reasons = [_details(event)["reason"] for event in _audit("mcp_auth")]
    assert reasons == [
        "malformed", "malformed", "unknown_or_wrong_secret", "unknown_or_wrong_secret",
        "expired", "revoked", "owner_inactive", "ip_not_allowed",
    ]
    assert all(event["decision"] == "deny" and event["ip_address"] for event in _audit("mcp_auth"))
    assert secret not in json.dumps([event["details_json"] for event in _audit("mcp_auth")])


def test_repeated_failures_throttle_the_caller_but_not_other_tokens(world):
    admin = _login("root")
    victim = _issue(admin)
    other = _issue(admin, name="other")
    guess = f"{victim['token_id']}_{'z' * 43}"
    statuses = [_reject(guess).status for _ in range(9)]
    assert statuses == [401] * 8 + [429]
    assert (_reject(guess).status, _reject(guess).retry_after) == (429, 300)
    # the same caller still reaches a different token; the real owner of the guessed one is locked out
    # only from this address
    assert mcp_tokens.authenticate(other["token"], scope=SCOPE).token_id == other["token_id"]
    elsewhere = {**SCOPE, "client": ("198.51.100.8", 1)}
    assert mcp_tokens.authenticate(victim["token"], scope=elsewhere).token_id == victim["token_id"]


def _session_client(app: Any, cookie: str) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://testserver", headers={"Cookie": f"mpvm_app_session={cookie}"}
    )


def _statuses(cookie: str, requests: list[tuple[str, str, dict | None]]) -> list[int]:
    async def run() -> list[int]:
        async with _session_client(main.app, cookie) as client:
            return [(await client.request(method, path, json=body)).status_code for method, path, body in requests]

    return asyncio.run(run())


def test_a_token_session_of_an_administrator_still_reads_only_its_scopes(world):
    admin = _login("root")
    principal = mcp_tokens.authenticate(_issue(admin)["token"], scope=SCOPE)
    cookie = mcp_tokens.open_session(principal)

    assert _statuses(
        cookie,
        [
            ("GET", "/api/vulnerabilities", None),  # in scope
            ("GET", "/api/remediation/summary", None),  # a read, but outside the scopes
            ("GET", "/api/auth/users", None),  # administrator read
            ("GET", "/api/auth/mcp-tokens", None),  # a token cannot list or mint tokens
            ("POST", "/api/auth/mcp-tokens", {"name": "x", "scopes": ["risk:read"]}),
            ("POST", "/api/remediation/cases/start", {"asset_id": "a", "vulnerability_selector": "id:V"}),
            ("DELETE", "/api/asset-cards/web-1", None),
            ("PUT", "/api/remediation/policy", {}),
        ],
    ) == [200, 403, 403, 403, 403, 403, 403, 403]
    # the owner's own browser session is not capped by the token
    assert admin.get("/api/auth/users").status_code == 200


def test_a_session_cap_never_grants_a_write_permission(world):
    cookie = auth.create_session(
        world["admin"], lifetime=timedelta(minutes=5), mcp_token_id=None, permission_cap=["tasks.manage", "assets.read"]
    )
    # A plain session ignores a cap column: the cap belongs to token sessions.
    assert "tasks.manage" in auth.get_session_user(cookie)["permissions"]

    token = mcp_tokens.create_token(
        name="t", owner_user_id=world["admin"], scopes=["risk:read"], ip_allowlist=[], expires_in_days=1, actor={"id": world["admin"], "username": "root"}
    )
    pk = _rows("SELECT id FROM app_mcp_tokens")[0]["id"]
    forged = auth.create_session(
        world["admin"], lifetime=timedelta(minutes=5), mcp_token_id=pk, permission_cap=["tasks.manage", "risk.read", "security.users.manage"]
    )
    user = auth.get_session_user(forged)
    assert user["permissions"] == ["risk.read"]  # a write permission in the cap is dropped
    assert user["mcp_token"] == {"id": token["token_id"], "name": "t"}
    no_cap = auth.create_session(world["admin"], lifetime=timedelta(minutes=5), mcp_token_id=pk, permission_cap=None)
    assert auth.get_session_user(no_cap)["permissions"] == []


def test_a_token_session_ends_with_the_token(world):
    admin = _login("root")
    issued = _issue(admin)
    cookie = mcp_tokens.open_session(mcp_tokens.authenticate(issued["token"], scope=SCOPE))
    assert _statuses(cookie, [("GET", "/api/vulnerabilities", None)]) == [200]

    revoked = admin.post(f"/api/auth/mcp-tokens/{issued['id']}/revoke")
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked" and revoked.json()["revoked_by"] == "root"
    assert _statuses(cookie, [("GET", "/api/vulnerabilities", None)]) == [401]  # at once, not at expiry
    assert _reject(issued["token"]).status == 401
    assert admin.post(f"/api/auth/mcp-tokens/{issued['id']}/revoke").json()["detail"]["code"] == "TOKEN_REVOKED"
    assert admin.post("/api/auth/mcp-tokens/424242/revoke").json()["detail"]["code"] == "TOKEN_NOT_FOUND"
    assert _audit("mcp_token_revoked")[0]["target_id"] == issued["token_id"]


def test_a_session_never_outlives_an_expired_token_or_a_disabled_owner(world):
    admin = _login("root")
    short = _issue(admin, name="short")
    with db.connect() as conn:
        conn.execute("UPDATE app_mcp_tokens SET expires_at=%s WHERE id=%s", (datetime.now(UTC) + timedelta(minutes=2), short["id"]))
    cookie = mcp_tokens.open_session(mcp_tokens.authenticate(short["token"], scope=SCOPE))
    session = _rows("SELECT expires_at FROM app_auth_sessions WHERE mcp_token_id=%s", short["id"])[0]
    assert datetime.fromisoformat(session["expires_at"]) <= datetime.now(UTC) + timedelta(minutes=2)
    with db.connect() as conn:  # the token expires while the session is open
        conn.execute("UPDATE app_mcp_tokens SET expires_at=%s WHERE id=%s", (datetime.now(UTC) - timedelta(seconds=1), short["id"]))
    assert _statuses(cookie, [("GET", "/api/vulnerabilities", None)]) == [401]

    owned = _issue(admin, name="viewers", owner_user_id=world["viewer"])
    cookie = mcp_tokens.open_session(mcp_tokens.authenticate(owned["token"], scope=SCOPE))
    assert _statuses(cookie, [("GET", "/api/vulnerabilities", None)]) == [200]  # a viewer holds assets.read
    admin.patch(f"/api/auth/users/{world['viewer']}", json={"is_active": False})
    assert _statuses(cookie, [("GET", "/api/vulnerabilities", None)]) == [401]
    assert _reject(owned["token"]).status == 401


def test_a_token_gives_no_more_than_its_owner_can_read(world):
    admin = _login("root")
    with db.connect() as conn:
        conn.execute("UPDATE app_users SET is_active=TRUE WHERE id=%s", (world["viewer"],))
    narrow = _issue(admin, owner_user_id=world["viewer"], scopes=["risk:read", "remediation:read"])
    cookie = mcp_tokens.open_session(mcp_tokens.authenticate(narrow["token"], scope=SCOPE))
    assert _statuses(cookie, [("GET", "/api/risk/queue", None), ("GET", "/api/remediation/summary", None), ("GET", "/api/vulnerabilities", None)]) == [200, 200, 403]


def test_rotation_keeps_the_old_token_for_the_grace_period_then_ends_it(world):
    admin = _login("root")
    old = _issue(admin, ip_allowlist=["203.0.113.0/24"])
    rotated = admin.post(f"/api/auth/mcp-tokens/{old['id']}/rotate", json={"grace_hours": 2})
    assert rotated.status_code == 201
    new = rotated.json()
    assert new["token"] != old["token"] and new["rotated_from"] == old["id"] and new["replaced_token_id"] == old["token_id"]
    assert new["scopes"] == old["scopes"] and new["owner"] == old["owner"] and new["ip_allowlist"] == ["203.0.113.0/24"]

    assert mcp_tokens.authenticate(old["token"], scope=SCOPE).key == old["id"]  # still valid during the grace
    assert mcp_tokens.authenticate(new["token"], scope=SCOPE).key == new["id"]
    old_row = next(row for row in admin.get("/api/auth/mcp-tokens").json()["rows"] if row["id"] == old["id"])
    assert datetime.fromisoformat(old_row["expires_at"]) <= datetime.now(UTC) + timedelta(hours=2, minutes=1)

    immediate = admin.post(f"/api/auth/mcp-tokens/{new['id']}/rotate", json={"grace_hours": 0}).json()
    assert _reject(new["token"]).status == 401 and immediate["rotated_from"] == new["id"]
    assert admin.post(f"/api/auth/mcp-tokens/{new['id']}/rotate", json={}).json()["detail"]["code"] == "TOKEN_NOT_ACTIVE"
    assert [_details(event)["grace_hours"] for event in _audit("mcp_token_rotated")] == [2, 0]


def test_sessions_and_tool_calls_are_audited_under_the_token(world):
    issued = _issue(_login("root"))
    principal = mcp_tokens.authenticate(issued["token"], scope=SCOPE)
    mcp_tokens.open_session(principal)
    mcp_tokens.record_tool_call(principal, "find_hosts", ok=False, error="PERMISSION_DENIED", duration_ms=12)

    opened, call = _audit("mcp_session")[0], _audit("mcp_tool_call")[0]
    assert opened["actor_username"] == "root" and _details(opened)["mcp_token"]["id"] == issued["token_id"]
    assert (call["decision"], call["target_id"]) == ("deny", "find_hosts")  # the application refused it
    assert _details(call) == {"ok": False, "duration_ms": 12, "client_ip": "203.0.113.9", "error": "PERMISSION_DENIED", "mcp_token": {"id": issued["token_id"], "name": "claude-code"}}


def _mcp_over_http() -> FastAPI:
    outer = FastAPI()
    outer.mount("/", main.app)
    settings = make_settings(enabled=True, username="", password="")
    assert install_embedded_mcp(outer, settings=settings, authenticator=McpTokenAuthenticator()) is True
    return outer


def _call(client: TestClient, token: str, tool: str, arguments: dict[str, Any]):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
    return client.post("/mcp", json=payload, headers=headers)


def test_a_token_reads_vulnerabilities_over_mcp_and_loses_access_when_revoked(world):
    with db.connect() as conn:
        _card(conn, "web-1", "web-1", "10.0.0.1", datetime.now(UTC) - timedelta(days=1))
        _finding(conn, "web-1", "V-3094", "CVE-2024-3094")
    outer = _mcp_over_http()
    with TestClient(outer) as client:
        admin = _login("root", outer)
        issued = _issue(admin, scopes=["vulnerabilities:read"])

        ok = _call(client, issued["token"], "find_hosts_by_vulnerability", {"query": "CVE-2024-3094"}).json()["result"]
        assert ok["isError"] is False and "web-1" in ok["content"][0]["text"]

        # outside its scopes the application answers 403 and the tool reports it
        denied = _call(client, issued["token"], "remediation_summary", {}).json()["result"]
        assert denied["isError"] is True and "PERMISSION_DENIED" in denied["content"][0]["text"]

        assert client.post("/mcp", json={}, headers={"Authorization": f"Bearer {issued['token_id']}_{'q' * 43}"}).status_code == 401
        assert admin.post(f"/api/auth/mcp-tokens/{issued['id']}/revoke").status_code == 200
        assert _call(client, issued["token"], "find_hosts_by_vulnerability", {"query": "CVE-2024-3094"}).status_code == 401

    calls = _audit("mcp_tool_call")
    assert [(event["target_id"], event["decision"]) for event in calls] == [
        ("find_hosts_by_vulnerability", "allow"),
        ("remediation_summary", "deny"),
    ]
    assert len(_audit("mcp_session")) == 1  # one session for the token, reused by both calls
    assert all(_details(event)["mcp_token"]["id"] == issued["token_id"] for event in calls)


def test_the_token_secret_never_reaches_logs_or_the_audit_log(world, caplog):
    outer = _mcp_over_http()
    issued = _issue(_login("root", outer))
    with caplog.at_level("DEBUG"), TestClient(outer) as client:
        _call(client, issued["token"], "data_freshness", {})
    assert issued["token"] not in caplog.text
    secret = issued["token"].split("_", 3)[3]
    assert secret not in json.dumps([row["details_json"] for row in _rows("SELECT details_json FROM app_auth_audit_events")])
