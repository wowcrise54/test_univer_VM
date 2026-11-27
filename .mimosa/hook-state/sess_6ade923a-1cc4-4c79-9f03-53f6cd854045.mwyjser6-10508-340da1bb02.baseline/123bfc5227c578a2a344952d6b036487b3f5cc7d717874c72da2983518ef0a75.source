"""Serve the MCP endpoint from the application's own port.

Behind a reverse proxy that only forwards the application port, MCP lives at a
separate path (``MPVM_MCP_PATH``, ``/mcp`` by default) of the same server. The
tools still call the REST API, in-process over ASGI and under the viewer
account, so RBAC and audit stay in the backend.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from pydantic import ValidationError
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import McpSettings
from .principal import TokenAuthenticator

logger = logging.getLogger("mpvm_mcp")


class McpPathRouter:
    """Send requests for the MCP path to the MCP app and everything else to the application.

    ``/mcp`` and ``/mcp/`` are both accepted without a redirect, because MCP
    clients do not follow redirects on POST.
    """

    def __init__(self, app: ASGIApp, *, path: str, handler: ASGIApp):
        self.app = app
        self._path = path
        self._handler = handler

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") in (self._path, self._path + "/"):
            await self._handler({**scope, "path": self._path, "raw_path": self._path.encode()}, receive, send)
            return
        await self.app(scope, receive, send)


def install_embedded_mcp(
    app: FastAPI, *, settings: McpSettings | None = None, authenticator: TokenAuthenticator | None = None
) -> bool:
    """Mount MCP on ``app`` when ``MPVM_MCP_ENABLED`` is set. Never raises: a broken MCP must not stop the app.

    ``authenticator`` checks personal access tokens; without it only the deprecated shared token works.
    """
    try:
        settings = settings or McpSettings()
    except ValidationError as exc:
        logger.error("MCP is not mounted, invalid configuration: %s", "; ".join(e["msg"] for e in exc.errors()))
        return False
    if not settings.enabled:
        logger.info("MCP endpoint is off: set MPVM_MCP_ENABLED=true to serve it at %s", settings.path)
        return False
    problems = settings.problems()
    if problems:
        logger.error("MCP is not mounted: %s", "; ".join(problems))
        return False

    if authenticator is None and not settings.auth_token:
        logger.error("MCP is not mounted: no authentication is configured (issue MCP access tokens in the application)")
        return False

    try:
        import httpx2

        from .client import AppClient
        from .http_auth import McpAuthMiddleware
        from .server import build_server
    except ImportError as exc:  # the image was built without requirements-mcp.txt
        logger.error("MCP is not mounted: a required package is missing (%s)", exc)
        return False

    if settings.auth_token:
        logger.warning(
            "MPVM_MCP_AUTH_TOKEN (one shared token for every client) is deprecated: "
            "issue a personal MCP access token per client and remove it"
        )
    client = AppClient(
        settings,
        transport=httpx2.ASGITransport(app=app),
        session_opener=authenticator.open_session if authenticator else None,
    )
    server = build_server(settings, client, authenticator=authenticator)
    mcp_app = server.streamable_http_app(
        streamable_http_path=settings.path,
        host="0.0.0.0",  # DNS-rebinding protection is for loopback servers; the token and the Origin check guard this one
        stateless_http=True,
        json_response=True,
    )
    app.add_middleware(
        McpPathRouter,
        path=settings.path,
        handler=McpAuthMiddleware(
            mcp_app,
            authenticator=authenticator,
            legacy_token=settings.auth_token,
            allow_x_api_key=settings.allow_x_api_key,
            allowed_origins=settings.origins,
        ),
    )

    application_lifespan: Any = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[Any]:
        async with application_lifespan(application) as state:
            async with mcp_app.router.lifespan_context(mcp_app):
                try:
                    yield state
                finally:
                    await client.aclose()

    app.router.lifespan_context = lifespan
    logger.info("MCP is served at %s on the application port", settings.path)
    return True
