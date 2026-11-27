from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx2
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .config import McpSettings
from .principal import AuthRejected, Principal, current_principal

SESSION_COOKIE = "mpvm_app_session"
# Placeholder origin: requests go to the application in-process over ASGI, only the path matters.
INTERNAL_API_URL = "http://mcp.internal"
# A token session lasts an hour; reuse it for less, so a request never meets one that just expired.
TOKEN_SESSION_REUSE_SECONDS = 45 * 60


class ApiError(ToolError):
    """An application API error, worded so that an LLM client can act on it.

    A ``ToolError`` is shown to the model as the tool result; any other exception
    would be reduced to a generic "Error executing tool" message.
    """

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"MP VM Client API {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


def _error_from_response(response: httpx2.Response) -> ApiError:
    code = f"HTTP_{response.status_code}"
    message = response.reason_phrase or "request failed"
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    if isinstance(detail, dict):
        code = str(detail.get("code") or code)
        message = str(detail.get("operator_message") or detail.get("message") or message)
    elif isinstance(detail, str) and detail:
        message = detail
    elif isinstance(detail, list) and detail:
        message = "; ".join(str(item.get("msg", item)) if isinstance(item, dict) else str(item) for item in detail[:3])
    return ApiError(response.status_code, code, message)


def _unreachable(exc: httpx2.HTTPError) -> ApiError:
    return ApiError(503, "API_UNREACHABLE", f"the MP VM Client API did not answer ({type(exc).__name__})")


def _clean_params(params: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in params.items():
        if value is None or value == "":
            continue
        cleaned[key] = str(value).lower() if isinstance(value, bool) else value
    return cleaned


class AppClient:
    """Read-only client of the MP VM Client REST API.

    Every request is a ``GET`` made for a token principal, with the capped
    session the application opened for that token.
    """

    def __init__(
        self,
        settings: McpSettings,
        *,
        session_opener: Callable[[Principal], Awaitable[str]],
        transport: httpx2.AsyncBaseTransport | None = None,
    ):
        self._session_opener = session_opener
        self._token_sessions: dict[int, tuple[str, float]] = {}
        self._http = httpx2.AsyncClient(
            base_url=INTERNAL_API_URL,
            timeout=settings.timeout_seconds,
            headers={"User-Agent": f"mpvm-mcp/{__version__}", "Accept": "application/json"},
            transport=transport,
        )
        self._lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, **params: Any) -> Any:
        query = _clean_params(params)
        principal = current_principal.get()
        if principal is None:
            raise ApiError(401, "AUTH_REQUIRED", "no MCP access token for this request")
        for attempt in (0, 1):
            cookie = await self._cookie_for(principal)
            try:
                response = await self._http.get(path, params=query, headers={"Cookie": f"{SESSION_COOKIE}={cookie}"})
            except httpx2.HTTPError as exc:
                raise _unreachable(exc) from exc
            if response.status_code == 401 and attempt == 0:
                self._token_sessions.pop(principal.key, None)
                continue
            if response.status_code >= 400:
                raise _error_from_response(response)
            try:
                return response.json()
            except ValueError as exc:
                raise ApiError(response.status_code, "BAD_RESPONSE", "the API returned a non-JSON body") from exc
        raise ApiError(401, "AUTH_REQUIRED", "the MCP access token could not keep a session")

    def _cached_session(self, principal: Principal) -> str | None:
        cached = self._token_sessions.get(principal.key)
        if cached and time.monotonic() - cached[1] < TOKEN_SESSION_REUSE_SECONDS:
            return cached[0]
        return None

    async def _cookie_for(self, principal: Principal) -> str:
        if cookie := self._cached_session(principal):
            return cookie
        async with self._lock:
            if cookie := self._cached_session(principal):
                return cookie
            try:
                cookie = await self._session_opener(principal)
            except AuthRejected as exc:
                self._token_sessions.pop(principal.key, None)
                raise ApiError(401, "AUTH_REQUIRED", "the MCP access token is no longer valid") from exc
            now = time.monotonic()
            self._token_sessions = {
                key: value for key, value in self._token_sessions.items() if now - value[1] < TOKEN_SESSION_REUSE_SECONDS
            }
            self._token_sessions[principal.key] = (cookie, now)
            return cookie
