from __future__ import annotations

import hmac
import json

from starlette.types import ASGIApp, Receive, Scope, Send

HEALTH_PATH = "/healthz"


class BearerAuthMiddleware:
    """Reject HTTP requests that do not carry the shared MCP token.

    Accepts ``Authorization: Bearer <token>`` and, for harnesses that can only set
    a custom header, ``X-API-Key: <token>``. The health path stays open.
    """

    def __init__(self, app: ASGIApp, token: str):
        self.app = app
        self._token = token.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._token or scope.get("path") == HEALTH_PATH:
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value for key, value in scope.get("headers", [])}
        supplied = b""
        authorization = headers.get("authorization", b"")
        if authorization[:7].lower() == b"bearer ":
            supplied = authorization[7:].strip()
        elif "x-api-key" in headers:
            supplied = headers["x-api-key"].strip()
        if supplied and hmac.compare_digest(supplied, self._token):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"error": "unauthorized", "message": "Missing or invalid MCP token."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b"Bearer"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
