from __future__ import annotations

import json
from collections.abc import Collection

from starlette.types import ASGIApp, Receive, Scope, Send

from .principal import TOKEN_PREFIX, AuthRejected, TokenAuthenticator, current_principal

_MESSAGES = {
    401: ("unauthorized", "Missing or invalid MCP token."),
    403: ("forbidden_origin", "This origin is not allowed to call the MCP endpoint."),
    429: ("rate_limited", "Too many failed attempts. Try again later."),
}


class McpAuthMiddleware:
    """Let a request through only with a valid MCP access token.

    A personal token (``mpvm_mcp_…``) is checked by the application, which also
    opens the session the tools read with. Anything else is refused: the guard
    fails closed.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticator: TokenAuthenticator,
        allow_x_api_key: bool = False,
        allowed_origins: Collection[str] = (),
    ):
        self.app = app
        self._authenticator = authenticator
        self._allow_x_api_key = allow_x_api_key
        self._origins = frozenset(allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            return
        headers = {key.decode("latin-1").lower(): value for key, value in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin is not None and origin.decode("latin-1").rstrip("/").lower() not in self._origins:
            await self._reject(send, 403)
            return
        supplied = self._supplied(headers)
        if not supplied.startswith(TOKEN_PREFIX.encode()):
            await self._reject(send, 401)
            return
        try:
            principal = await self._authenticator.authenticate(supplied.decode("latin-1"), scope=scope)
        except AuthRejected as exc:
            await self._reject(send, exc.status, retry_after=exc.retry_after)
            return
        marker = current_principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            current_principal.reset(marker)

    def _supplied(self, headers: dict[str, bytes]) -> bytes:
        authorization = headers.get("authorization", b"")
        if authorization[:7].lower() == b"bearer ":
            return authorization[7:].strip()
        if self._allow_x_api_key and "x-api-key" in headers:
            return headers["x-api-key"].strip()
        return b""

    @staticmethod
    async def _reject(send: Send, status: int, *, retry_after: int | None = None) -> None:
        error, message = _MESSAGES.get(status, _MESSAGES[401])
        body = json.dumps({"error": error, "message": message}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
        ]
        if status == 401:
            headers.append((b"www-authenticate", b"Bearer"))
        if retry_after is not None:
            headers.append((b"retry-after", str(retry_after).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
