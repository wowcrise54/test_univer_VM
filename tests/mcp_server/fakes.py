from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2

from mcp_server.client import AppClient
from mcp_server.config import McpSettings
from mcp_server.principal import AuthRejected, Principal

COOKIE = "session-token-1"

# The principal the tools read as when a test calls them without going through the HTTP guard.
TEST_PRINCIPAL = Principal(
    key=9001, token_id="mpvm_mcp_testtesttest", name="test", owner_id=1, owner_username="tester", client_ip="testclient"
)


def make_settings(**overrides: Any) -> McpSettings:
    values: dict[str, Any] = {"stale_days": 14}
    values.update(overrides)
    return McpSettings(**values)


class SessionOpener:
    """Stands in for the application's token-session opener and counts the sessions it opens."""

    def __init__(self, *, reject: bool = False) -> None:
        self.opened = 0
        self.reject = reject

    async def __call__(self, principal: Principal) -> str:
        if self.reject:
            raise AuthRejected(401)
        self.opened += 1
        return COOKIE


def make_client(
    transport: httpx2.AsyncBaseTransport, *, opener: SessionOpener | None = None, **settings: Any
) -> AppClient:
    return AppClient(make_settings(**settings), transport=transport, session_opener=opener or SessionOpener())


def iso_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def vuln_row(selector: str, *, vulnerability_id: str | None = None, cve: str | None = None, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "selector": selector,
        "vulnerability_id": vulnerability_id,
        "cve": cve,
        "name": extra.pop("name", f"vuln {selector}"),
        "severity": "high",
        "cvss_score": 8.1,
        "affected_hosts": 2,
        "findings": 2,
        "sources": ["software"],
        "passports": [],
        "how_to_fix": None,
        "has_fix": False,
    }
    row.update(extra)
    return row


def host_row(asset_id: str, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "asset_id": asset_id,
        "display_name": f"host-{asset_id}",
        "hostname": f"host-{asset_id}",
        "fqdn": f"host-{asset_id}.corp.local",
        "ip_address": "10.0.0.1",
        "os_name": "Linux",
        "os_version": "6.1",
        "asset_type": "host",
        "severity": "high",
        "cvss_score": 8.1,
        "finding_count": 1,
        "sources": ["software"],
        "last_seen": iso_ago(1),
        "remediation": None,
    }
    row.update(extra)
    return row


class FakeApi:
    """A recording stand-in for the MP VM Client REST API (httpx2 MockTransport)."""

    def __init__(self) -> None:
        self.requests: list[httpx2.Request] = []
        self.routes: dict[str, Callable[[httpx2.Request], httpx2.Response]] = {}
        self.reject_cookie_once = False

    def json(self, path: str, payload: Any, status: int = 200) -> None:
        self.routes[path] = lambda _request: httpx2.Response(status, json=payload)

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self._handle)

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path
        if self.reject_cookie_once:
            self.reject_cookie_once = False
            return httpx2.Response(401, json={"detail": {"code": "AUTH_REQUIRED", "message": "login"}})
        if request.headers.get("cookie") != f"mpvm_app_session={COOKIE}":
            return httpx2.Response(401, json={"detail": {"code": "AUTH_REQUIRED", "message": "login"}})
        route = self.routes.get(path)
        if route is None:
            return httpx2.Response(404, json={"detail": {"code": "NOT_FOUND", "message": path}})
        return route(request)

    def params(self, request: httpx2.Request) -> dict[str, str]:
        return dict(request.url.params)

    def data_requests(self) -> list[httpx2.Request]:
        return list(self.requests)


def body(result: Any) -> dict[str, Any]:
    """The JSON payload of an MCP tool result."""
    return json.loads(result.content[0].text)
