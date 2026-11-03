from __future__ import annotations

import asyncio

import httpx2
import pytest
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_server import client as client_module
from mcp_server.client import ApiError, AppClient
from mcp_server.config import McpSettings
from mcp_server.http_auth import BearerAuthMiddleware
from mcp_server.shaping import fit_response, render
from tests.mcp_server.fakes import COOKIE, FakeApi, make_settings


def _run(coro):
    return asyncio.run(coro)


def test_client_logs_in_once_and_sends_the_session_cookie():
    api = FakeApi()
    api.json("/api/ping", {"ok": True})

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            return [await client.get("/api/ping"), await client.get("/api/ping", limit=5, skip=None, flag=True)]
        finally:
            await client.aclose()

    assert _run(run()) == [{"ok": True}, {"ok": True}]
    assert api.logins == 1
    last = api.data_requests()[-1]
    assert last.headers["cookie"] == f"mpvm_app_session={COOKIE}"
    assert api.params(last) == {"limit": "5", "flag": "true"}
    assert "mpvm-mcp" in last.headers["user-agent"]
    login = next(r for r in api.requests if r.url.path == "/api/auth/login")
    assert b'"auth_type":"local"' in login.content.replace(b" ", b"")


def test_client_relogs_in_after_a_401_and_retries_once():
    api = FakeApi()
    api.json("/api/ping", {"ok": True})

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            await client.get("/api/ping")
            api.reject_cookie_once = True
            return await client.get("/api/ping")
        finally:
            await client.aclose()

    assert _run(run()) == {"ok": True}
    assert api.logins == 2


def test_failed_login_is_not_retried_in_a_loop():
    api = FakeApi()
    api.login_status = 401

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            errors = []
            for _ in range(3):
                with pytest.raises(ApiError) as caught:
                    await client.get("/api/ping")
                errors.append(caught.value)
            return errors
        finally:
            await client.aclose()

    errors = _run(run())
    assert api.logins == 1  # the application rate-limits failed logins
    assert errors[0].code == "INVALID_CREDENTIALS"
    assert "login of the MCP service account failed" in str(errors[0])


def test_api_errors_carry_code_and_message():
    api = FakeApi()
    api.json("/api/denied", {"detail": {"code": "PERMISSION_DENIED", "message": "assets.read required"}}, status=403)
    api.json("/api/invalid", {"detail": [{"msg": "bad limit"}]}, status=422)
    api.routes["/api/html"] = lambda _r: httpx2.Response(200, text="<html>")

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
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
        client = AppClient(make_settings(), transport=httpx2.MockTransport(refuse))
        try:
            with pytest.raises(ApiError) as caught:
                await client.get("/api/ping")
            return caught.value
        finally:
            await client.aclose()

    error = _run(run())
    assert (error.status, error.code) == (503, "API_UNREACHABLE")


def test_client_warns_when_the_account_can_write(caplog):
    api = FakeApi()
    api.json("/api/ping", {})
    original = api._handle

    def handle(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/auth/me":
            return httpx2.Response(200, json={"user": {"permissions": ["assets.read", "remediation.manage", "tasks.execute"]}})
        return original(request)

    async def run():
        client = AppClient(make_settings(), transport=httpx2.MockTransport(handle))
        try:
            await client.get("/api/ping")
        finally:
            await client.aclose()

    with caplog.at_level("WARNING", logger=client_module.logger.name):
        _run(run())
    assert "remediation.manage" in caplog.text and "tasks.execute" in caplog.text


def test_settings_report_what_is_missing():
    base = {"username": "u", "password": "p"}
    assert len(McpSettings().problems()) == 2
    assert "MPVM_MCP_USERNAME" in McpSettings(auth_token="t").problems()[0]
    # the endpoint shares the application port, so a token is always mandatory
    assert "MPVM_MCP_AUTH_TOKEN" in McpSettings(**base).problems()[0]
    assert McpSettings(auth_token="t", **base).problems() == []


def test_settings_validate_fields_and_hide_secrets():
    base = {"username": "u", "password": "p"}
    assert "secret-token" not in repr(McpSettings(auth_token="secret-token", **base))
    assert McpSettings(path=" /mcp/ ").path == "/mcp"
    assert McpSettings(path="/vulnsearch/mcp").path == "/vulnsearch/mcp"
    for bad in ("mcp", "/", "", "/api", "/api/mcp", "/static/x", "/m cp", "/mcp?x=1"):
        with pytest.raises(ValidationError, match="MPVM_MCP_PATH"):
            McpSettings(path=bad)


def _guarded(token: str = "s3cret") -> TestClient:
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/mcp", ok, methods=["GET", "POST"]), Route("/healthz", ok)])
    app.add_middleware(BearerAuthMiddleware, token=token)
    return TestClient(app)


def test_bearer_middleware_guards_every_request():
    client = _guarded()
    assert client.get("/healthz").status_code == 401
    denied = client.post("/mcp")
    assert denied.status_code == 401 and denied.headers["www-authenticate"] == "Bearer"
    assert client.post("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Basic s3cret"}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.post("/mcp", headers={"Authorization": "bearer s3cret"}).status_code == 200
    assert client.post("/mcp", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.post("/mcp", headers={"X-API-Key": "nope"}).status_code == 401


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
