"""Who is calling the MCP endpoint, and how the application vouches for them.

The server never sees user credentials: the application checks the personal
access token and opens a capped session of the token owner, so RBAC and audit
stay in the backend.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Protocol

from starlette.types import Scope

TOKEN_PREFIX = "mpvm_mcp_"


@dataclass(frozen=True)
class Principal:
    key: int  # database id of the token
    token_id: str  # public part of the token, safe to log
    name: str
    owner_id: int
    owner_username: str
    client_ip: str | None = None


class AuthRejected(Exception):
    """The token was not accepted. ``status`` is 401 for a bad token and 429 when the caller is throttled."""

    def __init__(self, status: int = 401, retry_after: int | None = None):
        super().__init__(status)
        self.status = status
        self.retry_after = retry_after


class TokenAuthenticator(Protocol):
    async def authenticate(self, token: str, *, scope: Scope) -> Principal:
        """Return the principal of a valid token, or raise :class:`AuthRejected`."""

    async def open_session(self, principal: Principal) -> str:
        """Open a read-capped application session for the token owner and return its cookie value."""

    async def record_tool_call(
        self, principal: Principal, tool: str, *, ok: bool, error: str | None, duration_ms: int
    ) -> None:
        """Write one audit event for a tool call. Must not raise."""


# The principal of the request being served; the tools read the API as this principal.
current_principal: ContextVar[Principal | None] = ContextVar("mpvm_mcp_principal", default=None)
