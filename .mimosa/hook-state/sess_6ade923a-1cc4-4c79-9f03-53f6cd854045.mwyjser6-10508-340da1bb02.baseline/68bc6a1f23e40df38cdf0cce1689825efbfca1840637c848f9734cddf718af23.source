from __future__ import annotations

import asyncio

import httpx2
import pytest
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_server.client import ApiError
from mcp_server.config import McpSettings
from mcp_server.http_auth import McpAuthMiddleware
from mcp_server.principal import AuthRejected, Principal, current_principal
from mcp_server.shaping import fit_response, render
from tests.mcp_server.fakes import COOKIE, TEST_PRINCIPAL, FakeApi, SessionOpener, make_client


def _run(coro):
    return asyncio.run(coro)


def test_client_opens_one_session_per_token_and_sends_its_cookie():
    api = FakeApi()
    api.json("/api/ping", {"ok": True})
    opener = SessionOpener()

    async def run():
        client = make_client(api.transport(), opener=opener)
        try:
            return [await client.get("/api/ping"), await client.get("/api/ping", limit=5, skip=None, flag=True)]
        finally:
            await client.aclose()

    assert _run(run()) == [{"ok": True}, {"ok": True}]
    assert opener.opened == 1
    last = api.data_requests()[-1]
    assert last.headers["cookie"] == f"mpvm_app_session={COOKIE}"
    assert api.params(last) == {"limit": "5", "flag": "true"}
    assert "mpvm-mcp" in last.headers["user-agent"]
    assert {request.method for request in api.requests} == {"GET"}  # the client can only read


def test_client_opens_a_new_session_after_a_401_and_retries_once():
    api = FakeApi()
    api.json("/api/ping", {"ok": True})
    opener = SessionOpener()

    async def run():
        client = make_client(api.transport(), opener=opener)
        try:
            await client.get("/api/ping")
            api.reject_cookie_once = True
            return await client.get("/api/ping")
        finally:
            await client.aclose()

    assert _run(run()) == {"ok": True}
    assert opener.opened == 2


def test_a_token_whose_session_cannot_be_opened_never_reaches_the_api():
    api = FakeApi()

    async def run():
        client = make_client(api.transport(), opener=SessionOpener(reject=True))
        try:
            with pytest.raises(ApiError) as caught:
                await client.get("/api/ping")
            return caught.value
        finally:
            await client.aclose()

    error = _run(run())
    assert (error.status, error.code) == (401, "AUTH_REQUIRED")
    assert "no longer valid" in str(error)
    assert api.requests == []


def test_a_request_without_a_token_principal_is_refused_before_any_call():
    api = FakeApi()
    opener = SessionOpener()
    marker = current_principal.set(None)

    async def run():
        client = make_client(api.transport(), opener=opener)
        try:
            with pytest.raises(ApiError) as caught:
                await client.get("/api/ping")
            return caught.value
        finally:
            await client.aclose()

    try:
        error = _run(run())
    finally:
        current_principal.reset(marker)
    assert (error.status, error.code) == (401, "AUTH_REQUIRED")
    assert api.requests == [] and opener.opened == 0


def test_api_errors_carry_code_and_message():
    api = FakeApi()
    api.json("/api/denied", {"detail": {"code": "PERMISSION_DENIED", "message": "assets.read required"}}, status=403)
    api.json("/api/invalid", {"detail": [{"msg": "bad limit"}]}, status=422)
    api.routes["/api/html"] = lambda _r: httpx2.Response(200, text="<html>")

    async def run():
        client = make_client(api.transport())
        try:
            with pytest.raises(ApiError) as denied:
                await client.get("/api/denied")
            with pytest.raises(ApiError) as invalid:
                await client.get("/api/invalid")
            with pytest.raises(ApiError) as html:
                await client.get("/api/html")
            return denied.value, invalid.value, html.value
        finally:
            await client.aclose()

    denied, invalid, html = _run(run())
    assert (denied.status, denied.code, denied.message) == (403, "PERMISSION_DENIED", "assets.read required")
    assert "bad limit" in invalid.message
    assert html.code == "BAD_RESPONSE"


def test_unreachable_api_is_reported_as_a_tool_error():
    def refuse(_request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused")

    async def run():
        client = make_client(httpx2.MockTransport(refuse))
        try:
            with pytest.raises(ApiError) as caught:
                await client.get("/api/ping")
            return caught.value
        finally:
            await client.aclose()

    error = _run(run())
    assert (error.status, error.code) == (503, "API_UNREACHABLE")


def test_allowed_origins_are_normalized():
    assert McpSettings().origins == frozenset()
    assert McpSettings(allowed_origins=" https://A.example/ ,,http://b.example:8080").origins == frozenset(
        {"https://a.example", "http://b.example:8080"}
    )


def test_settings_validate_the_path_and_ignore_retired_credentials(monkeypatch):
    for retired in ("MPVM_MCP_AUTH_TOKEN", "MPVM_MCP_USERNAME", "MPVM_MCP_PASSWORD"):
        monkeypatch.setenv(retired, "left-over")
    settings = McpSettings()
    assert not hasattr(settings, "auth_token") and "left-over" not in repr(settings)
    assert McpSettings(path=" /mcp/ ").path == "/mcp"
    assert McpSettings(path="/vulnsearch/mcp").path == "/vulnsearch/mcp"
    for bad in ("mcp", "/", "", "/api", "/api/mcp", "/static/x", "/m cp", "/mcp?x=1"):
        with pytest.raises(ValidationError, match="MPVM_MCP_PATH"):
            McpSettings(path=bad)


TOKEN = "mpvm_mcp_aaaaaaaaaaaa_" + "a" * 43


class _Authenticator:
    async def authenticate(self, token: str, *, scope: dict) -> Principal:
        if token != TOKEN:
            raise AuthRejected(401)
        return TEST_PRINCIPAL

    async def open_session(self, principal: Principal) -> str:
        return COOKIE

    async def record_tool_call(self, *args, **kwargs) -> None:
        return None


def _guarded(**options) -> TestClient:
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"]), Route("/healthz", ok)])
    app.add_middleware(McpAuthMiddleware, authenticator=_Authenticator(), **options)
    return TestClient(app)


def test_token_middleware_guards_every_request():
    client = _guarded()
    assert client.get("/healthz").status_code == 401
    denied = client.post("/mcp")
    assert denied.status_code == 401 and denied.headers["www-authenticate"] == "Bearer"
    assert denied.headers["cache-control"] == "no-store"
    assert client.post("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": f"Bearer mpvm_mcp_bbbbbbbbbbbb_{'b' * 43}"}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": f"Basic {TOKEN}"}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert client.post("/mcp", headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200


def test_x_api_key_is_refused_unless_enabled():
    assert _guarded().post("/mcp", headers={"X-API-Key": TOKEN}).status_code == 401
    client = _guarded(allow_x_api_key=True)
    assert client.post("/mcp", headers={"X-API-Key": TOKEN}).status_code == 200
    assert client.post("/mcp", headers={"X-API-Key": "nope"}).status_code == 401


def test_the_guard_fails_closed_without_a_token():
    client = _guarded()
    assert client.post("/mcp").status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer "}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer anything"}).status_code == 401


def test_a_browser_origin_is_refused_unless_listed():
    bearer = {"Authorization": f"Bearer {TOKEN}"}
    client = _guarded(allowed_origins={"https://ok.example"})
    assert client.post("/mcp", headers={**bearer, "Origin": "https://evil.example"}).status_code == 403
    assert client.post("/mcp", headers={**bearer, "Origin": "https://ok.example/"}).status_code == 200
    assert client.post("/mcp", headers=bearer).status_code == 200  # a client that is not a browser sends none
    assert _guarded().post("/mcp", headers={**bearer, "Origin": "https://ok.example"}).status_code == 403


def test_fit_response_halves_the_largest_list_and_marks_truncation():
    small = {"rows": [1, 2, 3]}
    assert fit_response(small, 10_000) == small
    big = {"total": 400, "rows": [{"text": "x" * 100} for _ in range(400)], "other": [1, 2]}
    fitted = fit_response(big, 5_000)
    assert fitted["truncated"] is True and "truncated_note" in fitted
    assert 1 <= len(fitted["rows"]) < 400 and fitted["total"] == 400
    assert big["rows"] and len(big["rows"]) == 400  # input is not mutated
    assert fit_response([1, 2, 3], 10_000) == {"rows": [1, 2, 3]}


def test_render_is_compact_json_without_indentation():
    text = render({"a": [1, 2], "name": "Хост", "fix": {"has_fix": None}}, 10_000)
    assert text == '{"a":[1,2],"name":"Хост","fix":{"has_fix":null}}'
    assert "\n" not in render({"rows": [{"x": i} for i in range(50)]}, 10_000)
