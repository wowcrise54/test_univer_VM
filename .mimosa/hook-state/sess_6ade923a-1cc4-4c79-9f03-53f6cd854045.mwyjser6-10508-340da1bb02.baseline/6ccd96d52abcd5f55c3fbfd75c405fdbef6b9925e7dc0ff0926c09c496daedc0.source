from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2

from mcp_server.config import McpSettings

COOKIE = "session-token-1"


def make_settings(**overrides: Any) -> McpSettings:
    values: dict[str, Any] = {"username": "mcp-viewer", "password": "S3cure-Passw0rd!", "stale_days": 14}
    values.update(overrides)
    return McpSettings(**values)


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
        self.login_status = 200
        self.reject_cookie_once = False
        self.logins = 0

    def json(self, path: str, payload: Any, status: int = 200) -> None:
        self.routes[path] = lambda _request: httpx2.Response(status, json=payload)

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self._handle)

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/auth/login":
            self.logins += 1
            if self.login_status != 200:
                return httpx2.Response(
                    self.login_status, json={"detail": {"code": "INVALID_CREDENTIALS", "message": "bad credentials"}}
                )
            return httpx2.Response(
                200,
                json={"authenticated": True, "user": {"permissions": []}},
                headers={"set-cookie": f"mpvm_app_session={COOKIE}; HttpOnly; Path=/; SameSite=strict"},
            )
        if path == "/api/auth/me":
            return httpx2.Response(200, json={"authenticated": True, "user": {"permissions": ["assets.read"]}})
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
        return [r for r in self.requests if not r.url.path.startswith("/api/auth/")]


def body(result: Any) -> dict[str, Any]:
    """The JSON payload of an MCP tool result."""
    return json.loads(result.content[0].text)
