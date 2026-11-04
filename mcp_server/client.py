from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from http.cookies import SimpleCookie
from typing import Any

import httpx2
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .config import McpSettings
from .principal import AuthRejected, Principal, current_principal

logger = logging.getLogger("mpvm_mcp")

SESSION_COOKIE = "mpvm_app_session"
# Placeholder origin: requests go to the application in-process over ASGI, only the path matters.
INTERNAL_API_URL = "http://mcp.internal"
LOGIN_RETRY_COOLDOWN_SECONDS = 30.0
# A token session lasts an hour; reuse it for less, so a request never meets one that just expired.
TOKEN_SESSION_REUSE_SECONDS = 45 * 60
_WRITE_PERMISSION_SUFFIXES = (".manage", ".execute", ".cancel", ".retry", ".build", ".policy", ".team", ".clear")


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

    The only non-GET request it can ever send is the login that obtains the
    session cookie of the deprecated shared-token mode; everything else goes
    through :meth:`get`. A request made for a token principal reads with the
    capped session the application opened for that token.
    """

    def __init__(
        self,
        settings: McpSettings,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        session_opener: Callable[[Principal], Awaitable[str]] | None = None,
    ):
        self._settings = settings
        self._session_opener = session_opener
        self._token_sessions: dict[int, tuple[str, float]] = {}
        self._http = httpx2.AsyncClient(
            base_url=INTERNAL_API_URL,
            timeout=settings.timeout_seconds,
            headers={"User-Agent": f"mpvm-mcp/{__version__}", "Accept": "application/json"},
            transport=transport,
        )
        self._cookie: str | None = None
        self._lock = asyncio.Lock()
        self._login_failed_at: float | None = None
        self._login_error: ApiError | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, **params: Any) -> Any:
        query = _clean_params(params)
        principal = current_principal.get()
        for attempt in (0, 1):
            cookie = await self._cookie_for(principal)
            try:
                response = await self._http.get(path, params=query, headers={"Cookie": f"{SESSION_COOKIE}={cookie}"})
            except httpx2.HTTPError as exc:
                raise _unreachable(exc) from exc
            if response.status_code == 401 and attempt == 0:
                self._forget(principal)
                continue
            if response.status_code >= 400:
                raise _error_from_response(response)
            try:
                return response.json()
            except ValueError as exc:
                raise ApiError(response.status_code, "BAD_RESPONSE", "the API returned a non-JSON body") from exc
        raise ApiError(401, "AUTH_REQUIRED", "the MCP service account could not keep a session")

    def _cached_session(self, principal: Principal) -> str | None:
        cached = self._token_sessions.get(principal.key)
        if cached and time.monotonic() - cached[1] < TOKEN_SESSION_REUSE_SECONDS:
            return cached[0]
        return None

    async def _cookie_for(self, principal: Principal | None) -> str:
        if principal is None:
            if not (self._settings.username and self._settings.password):
                raise ApiError(401, "AUTH_REQUIRED", "no MCP access token for this request")
            await self._ensure_session()
            assert self._cookie is not None
            return self._cookie
        if cookie := self._cached_session(principal):
            return cookie
        if self._session_opener is None:
            raise ApiError(401, "AUTH_REQUIRED", "this server cannot open sessions for access tokens")
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

    def _forget(self, principal: Principal | None) -> None:
        if principal is None:
            self._cookie = None
        else:
            self._token_sessions.pop(principal.key, None)

    async def _ensure_session(self) -> None:
        if self._cookie:
            return
        async with self._lock:
            if self._cookie:
                return
            if (
                self._login_error is not None
                and self._login_failed_at is not None
                and time.monotonic() - self._login_failed_at < LOGIN_RETRY_COOLDOWN_SECONDS
            ):
                # The application rate-limits failed logins; do not feed the limiter in a loop.
                raise self._login_error
            try:
                self._cookie = await self._login()
            except ApiError as exc:
                self._login_error = exc
                self._login_failed_at = time.monotonic()
                raise
            self._login_error = None
            self._login_failed_at = None
            await self._warn_if_privileged()

    async def _login(self) -> str:
        try:
            response = await self._http.post(
                "/api/auth/login",
                json={
                    "username": self._settings.username,
                    "password": self._settings.password,
                    "auth_type": "local",
                },
            )
        except httpx2.HTTPError as exc:
            raise _unreachable(exc) from exc
        if response.status_code >= 400:
            error = _error_from_response(response)
            raise ApiError(error.status, error.code, f"login of the MCP service account failed: {error.message}")
        for header in response.headers.get_list("set-cookie"):
            cookie: SimpleCookie = SimpleCookie()
            cookie.load(header)
            if SESSION_COOKIE in cookie:
                return cookie[SESSION_COOKIE].value
        raise ApiError(response.status_code, "NO_SESSION_COOKIE", "login did not return a session cookie")

    async def _warn_if_privileged(self) -> None:
        try:
            response = await self._http.get("/api/auth/me", headers={"Cookie": f"{SESSION_COOKIE}={self._cookie}"})
            permissions = response.json().get("user", {}).get("permissions") or []
        except (httpx2.HTTPError, ValueError, AttributeError):
            return
        risky = sorted(str(p) for p in permissions if str(p).endswith(_WRITE_PERMISSION_SUFFIXES))
        if risky:
            logger.warning(
                "MCP service account has write-capable permissions (%s); use a viewer role. "
                "This server only reads, but the account should not be able to change anything.",
                ", ".join(risky[:6]),
            )
