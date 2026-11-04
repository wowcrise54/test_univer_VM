"""Personal access tokens at the MCP endpoint, with a fake authenticator (no database)."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.testclient import TestClient

from mcp_server.embed import install_embedded_mcp
from mcp_server.principal import AuthRejected, Principal
from tests.mcp_server.fakes import host_row, make_settings, vuln_row

ALICE = "mpvm_mcp_aaaaaaaaaaaa_" + "a" * 43
BOB = "mpvm_mcp_bbbbbbbbbbbb_" + "b" * 43
LEGACY = "legacy-shared-token"


def _principal(key: int, name: str) -> Principal:
    return Principal(key=key, token_id=f"mpvm_mcp_{name * 12}", name=name, owner_id=key, owner_username=name, client_ip="testclient")


class FakeAuthenticator:
    def __init__(self) -> None:
        self.principals = {ALICE: _principal(1, "a"), BOB: _principal(2, "b")}
        self.throttled: set[str] = set()
        self.revoked: set[int] = set()
        self.sessions_opened: list[int] = []
        self.calls: list[dict[str, Any]] = []
        self.seen_tokens: list[str] = []

    async def authenticate(self, token: str, *, scope: dict) -> Principal:
        self.seen_tokens.append(token)
        if token in self.throttled:
            raise AuthRejected(429, retry_after=300)
        if token not in self.principals:
            raise AuthRejected(401)
        return self.principals[token]

    async def open_session(self, principal: Principal) -> str:
        if principal.key in self.revoked:
            raise AuthRejected(401)
        self.sessions_opened.append(principal.key)
        return f"session-of-{principal.owner_username}"

    async def record_tool_call(self, principal: Principal, tool: str, *, ok: bool, error: str | None, duration_ms: int) -> None:
        self.calls.append({"owner": principal.owner_username, "tool": tool, "ok": ok, "error": error})


def _host_app(*, fail_with: int | None = None) -> FastAPI:
    app = FastAPI()
    app.state.cookies = []

    @app.post("/api/auth/login")
    def login(response: Response) -> dict[str, Any]:
        response.set_cookie("mpvm_app_session", "legacy-session")
        return {"authenticated": True, "user": {"permissions": ["assets.read"]}}

    @app.get("/api/auth/me")
    def me() -> dict[str, Any]:
        return {"authenticated": True, "user": {"permissions": ["assets.read"]}}

    def record(request: Request) -> None:
        app.state.cookies.append(request.headers.get("cookie"))
        if fail_with:
            raise HTTPException(fail_with, detail={"code": "PERMISSION_DENIED", "message": "Недостаточно прав: assets.read."})

    @app.get("/api/vulnerabilities")
    def vulnerabilities(request: Request) -> dict[str, Any]:
        record(request)
        return {"total": 1, "rows": [vuln_row("id:1", vulnerability_id="V-1", cve="CVE-2026-1", has_fix=True, how_to_fix="Patch")]}

    @app.get("/api/vulnerabilities/hosts")
    def hosts(request: Request) -> dict[str, Any]:
        record(request)
        return {"total": 1, "rows": [host_row("web-1")]}

    @app.get("/api/vulnerabilities/summary")
    def summary(request: Request) -> dict[str, Any]:
        record(request)
        return {"coverage": {"complete": True}}

    return app


def _install(app: FastAPI, authenticator: FakeAuthenticator | None, **settings: Any) -> None:
    values: dict[str, Any] = {"enabled": True, "username": "", "password": ""}
    values.update(settings)
    assert install_embedded_mcp(app, settings=make_settings(**values), authenticator=authenticator) is True


def _post(client: TestClient, token: str, method: str = "tools/list", params: dict[str, Any] | None = None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, **({"params": params} if params else {})}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    return client.post("/mcp", json=payload, headers=headers)


def _find(client: TestClient, token: str):
    return _post(client, token, "tools/call", {"name": "find_hosts_by_vulnerability", "arguments": {"query": "CVE-2026-1"}})


def test_a_personal_token_needs_no_environment_credentials():
    app, auth = _host_app(), FakeAuthenticator()
    _install(app, auth)  # no MPVM_MCP_AUTH_TOKEN, no service account
    with TestClient(app) as client:
        assert _post(client, ALICE).status_code == 200
        assert _post(client, "mpvm_mcp_cccccccccccc_" + "c" * 43).status_code == 401
        assert _post(client, "not-a-token").status_code == 401


def test_each_token_reads_with_its_own_session_which_is_reused():
    app, auth = _host_app(), FakeAuthenticator()
    _install(app, auth)
    with TestClient(app) as client:
        for token in (ALICE, ALICE, BOB, ALICE):
            assert _find(client, token).json()["result"]["isError"] is False
    assert sorted(auth.sessions_opened) == [1, 2]  # opened once per token, not per request
    # the application is read once per token (two reads); repeats are served from that token's own cache
    assert app.state.cookies.count("mpvm_app_session=session-of-a") == 2
    assert app.state.cookies.count("mpvm_app_session=session-of-b") == 2
    assert set(app.state.cookies) == {"mpvm_app_session=session-of-a", "mpvm_app_session=session-of-b"}


def test_cached_answers_are_never_shared_between_tokens():
    # What the application answered to one token says nothing about what it would answer to another.
    app, auth = _host_app(), FakeAuthenticator()
    _install(app, auth)
    arguments = {"query": "CVE-2026-1", "include_coverage": True}
    with TestClient(app) as client:
        for token in (ALICE, ALICE, BOB, BOB):
            _post(client, token, "tools/call", {"name": "find_hosts_by_vulnerability", "arguments": arguments})
    cookies = app.state.cookies
    for owner in ("a", "b"):
        # vulnerabilities, hosts and summary once per token; the second call is served from its own cache
        assert cookies.count(f"mpvm_app_session=session-of-{owner}") == 3


def test_a_throttled_caller_gets_429_with_retry_after():
    app, auth = _host_app(), FakeAuthenticator()
    auth.throttled.add(ALICE)
    _install(app, auth)
    with TestClient(app) as client:
        response = _post(client, ALICE)
    assert response.status_code == 429 and response.headers["retry-after"] == "300"
    assert response.headers["cache-control"] == "no-store"
    assert ALICE not in response.text


def test_tool_calls_are_audited_with_the_outcome():
    app, auth = _host_app(), FakeAuthenticator()
    _install(app, auth)
    with TestClient(app) as client:
        _find(client, ALICE)
        _post(client, BOB, "tools/list")  # listing is not a tool call
    assert auth.calls == [{"owner": "a", "tool": "find_hosts_by_vulnerability", "ok": True, "error": None}]

    failing, auth = _host_app(fail_with=403), FakeAuthenticator()
    _install(failing, auth)
    with TestClient(failing) as client:
        result = _find(client, ALICE).json()["result"]
    assert result["isError"] is True and "PERMISSION_DENIED" in result["content"][0]["text"]
    assert auth.calls == [{"owner": "a", "tool": "find_hosts_by_vulnerability", "ok": False, "error": "PERMISSION_DENIED"}]


def test_a_revoked_token_cannot_keep_reading_through_a_cached_session():
    app, auth = _host_app(), FakeAuthenticator()
    _install(app, auth)
    with TestClient(app) as client:
        assert _find(client, ALICE).json()["result"]["isError"] is False
        auth.principals.pop(ALICE)  # the application no longer accepts it
        assert _find(client, ALICE).status_code == 401


def test_a_token_whose_session_cannot_be_opened_gives_an_error_not_data():
    app, auth = _host_app(), FakeAuthenticator()
    auth.revoked.add(1)
    _install(app, auth)
    with TestClient(app) as client:
        result = _find(client, ALICE).json()["result"]
    assert result["isError"] is True and "AUTH_REQUIRED" in result["content"][0]["text"]
    assert app.state.cookies == []


def test_the_shared_token_still_works_beside_personal_tokens_and_is_not_audited(caplog):
    app, auth = _host_app(), FakeAuthenticator()
    with caplog.at_level("WARNING", logger="mpvm_mcp"):
        _install(app, auth, auth_token=LEGACY, username="viewer", password="S3cure-Passw0rd!")
    assert "deprecated" in caplog.text
    with TestClient(app) as client:
        assert _find(client, LEGACY).json()["result"]["isError"] is False
        assert _find(client, ALICE).json()["result"]["isError"] is False
        assert _post(client, "wrong").status_code == 401
    assert auth.seen_tokens == [ALICE]  # the shared token never reaches the token store
    assert [call["owner"] for call in auth.calls] == ["a"]
    assert "mpvm_app_session=legacy-session" in app.state.cookies


def test_the_shared_token_is_refused_without_its_service_account():
    app = _host_app()
    assert install_embedded_mcp(app, settings=make_settings(enabled=True, auth_token=LEGACY, username="", password="")) is False
