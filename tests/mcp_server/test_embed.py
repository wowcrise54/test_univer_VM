from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from mcp_server import embed
from mcp_server.embed import install_embedded_mcp
from tests.mcp_server.fakes import COOKIE, host_row, make_settings, vuln_row

TOKEN = "embedded-token"
MCP_HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _host_app() -> FastAPI:
    """A stand-in for the application: a cookie-protected API and the SPA catch-all that answers GET only."""
    app = FastAPI()
    calls: list[str] = []
    app.state.calls = calls

    @app.post("/api/auth/login")
    def login(response: Response) -> dict[str, Any]:
        response.set_cookie("mpvm_app_session", COOKIE)
        return {"authenticated": True, "user": {"permissions": ["assets.read"]}}

    @app.get("/api/auth/me")
    def me() -> dict[str, Any]:
        return {"authenticated": True, "user": {"permissions": ["assets.read"]}}

    @app.get("/api/vulnerabilities")
    def vulnerabilities() -> dict[str, Any]:
        calls.append("vulnerabilities")
        return {"total": 1, "rows": [vuln_row("id:1", vulnerability_id="V-1", cve="CVE-2026-43500", has_fix=True, how_to_fix="Patch it")]}

    @app.get("/api/vulnerabilities/hosts")
    def hosts() -> dict[str, Any]:
        calls.append("hosts")
        return {"total": 1, "rows": [host_row("web-1")]}

    @app.get("/api/vulnerabilities/summary")
    def summary() -> dict[str, Any]:
        return {"coverage": {"complete": True}}

    @app.get("/{full_path:path}")
    def spa(full_path: str) -> dict[str, str]:
        return {"spa": full_path}

    return app


def _enabled(**overrides: Any):
    values: dict[str, Any] = {"enabled": True, "auth_token": TOKEN}
    values.update(overrides)
    return make_settings(**values)


@contextmanager
def _served(app: FastAPI):
    with TestClient(app) as client:  # runs the lifespan, which starts the MCP session manager
        yield client


def _call(client: TestClient, method: str, params: dict[str, Any] | None = None, path: str = "/mcp", **kwargs: Any):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, **({"params": params} if params else {})}
    return client.post(path, json=payload, headers=kwargs.pop("headers", MCP_HEADERS), **kwargs)


def test_disabled_by_default_leaves_the_application_untouched():
    app = _host_app()
    assert install_embedded_mcp(app, settings=make_settings()) is False
    with _served(app) as client:
        assert client.post("/mcp", json={}).status_code == 405  # the SPA catch-all, as before


def test_misconfiguration_does_not_mount_and_does_not_raise(caplog):
    app = _host_app()
    with caplog.at_level(logging.ERROR, logger=embed.logger.name):
        assert install_embedded_mcp(app, settings=make_settings(enabled=True)) is False  # no token
        assert install_embedded_mcp(app, settings=make_settings(enabled=True, username="", password="")) is False
    assert "MPVM_MCP_AUTH_TOKEN is required" in caplog.text
    assert "MPVM_MCP_USERNAME" in caplog.text
    with _served(app) as client:
        assert client.post("/mcp", json={}).status_code == 405


def test_invalid_environment_does_not_raise(monkeypatch, caplog):
    monkeypatch.setenv("MPVM_MCP_PATH", "/api/mcp")
    with caplog.at_level(logging.ERROR, logger=embed.logger.name):
        assert install_embedded_mcp(_host_app()) is False
    assert "invalid configuration" in caplog.text


def test_mcp_is_served_on_the_application_port_behind_a_token():
    app = _host_app()
    assert install_embedded_mcp(app, settings=_enabled()) is True
    with _served(app) as client:
        assert client.post("/mcp", json={}, headers={"Content-Type": "application/json"}).status_code == 401
        assert _call(client, "tools/list", headers={**MCP_HEADERS, "Authorization": "Bearer nope"}).status_code == 401

        tools = _call(client, "tools/list")
        assert tools.status_code == 200
        names = {tool["name"] for tool in tools.json()["result"]["tools"]}
        assert "find_hosts_by_vulnerability" in names and len(names) == 14

        # the application keeps serving everything else, including its SPA fallback
        assert client.get("/api/vulnerabilities/summary").status_code == 200
        assert client.get("/some/page").json() == {"spa": "some/page"}


def test_tool_call_reads_through_the_application_api_in_process():
    app = _host_app()
    install_embedded_mcp(app, settings=_enabled())
    with _served(app) as client:
        result = _call(
            client,
            "tools/call",
            {"name": "find_hosts_by_vulnerability", "arguments": {"query": "CVE-2026-43500"}},
        ).json()["result"]
    assert result["isError"] is False
    text = result["content"][0]["text"]
    assert "web-1" in text and "Patch it" in text and '"available"' in text
    assert app.state.calls == ["vulnerabilities", "hosts"]


def test_trailing_slash_is_served_without_a_redirect():
    app = _host_app()
    install_embedded_mcp(app, settings=_enabled())
    with _served(app) as client:
        response = _call(client, "tools/list", path="/mcp/", follow_redirects=False)
    assert response.status_code == 200


def test_endpoint_path_is_configurable():
    app = _host_app()
    install_embedded_mcp(app, settings=_enabled(path="/vulnsearch/mcp"))
    with _served(app) as client:
        assert _call(client, "tools/list", path="/vulnsearch/mcp").status_code == 200
        assert client.post("/mcp", json={}).status_code == 405  # the default path is not taken over


def test_other_paths_and_methods_pass_through_to_the_application():
    app = _host_app()
    install_embedded_mcp(app, settings=_enabled())
    with _served(app) as client:
        assert client.get("/mcp-other").json() == {"spa": "mcp-other"}
        assert client.get("/api/auth/me").status_code == 200
