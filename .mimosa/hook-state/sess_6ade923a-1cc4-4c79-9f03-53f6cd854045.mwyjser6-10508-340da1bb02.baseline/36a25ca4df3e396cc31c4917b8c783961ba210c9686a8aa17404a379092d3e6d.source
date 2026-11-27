from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Paths the application already owns; the embedded MCP endpoint must not shadow them.
_RESERVED_PATH_PREFIXES = ("/api", "/static")


class McpSettings(BaseSettings):
    """Validated configuration loaded from ``MPVM_MCP_*`` variables."""

    model_config = SettingsConfigDict(env_prefix="MPVM_MCP_", extra="ignore", case_sensitive=False)

    # Serve MCP from the application's own port at ``path``.
    enabled: bool = False
    path: str = "/mcp"

    timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    # Clients authenticate with personal access tokens issued in the application; no
    # credentials are configured here.
    # Also accept the token in ``X-API-Key``. Off: a second header is one more place for it to leak.
    allow_x_api_key: bool = False
    # Browser origins allowed to call the endpoint, comma separated. Requests with any other
    # ``Origin`` are refused; MCP clients that are not browsers send none.
    allowed_origins: str = ""

    # Answer shaping.
    stale_days: int = Field(default=14, ge=1, le=3650)
    max_response_chars: int = Field(default=60000, ge=2000, le=1_000_000)

    @property
    def origins(self) -> frozenset[str]:
        return frozenset(item.strip().rstrip("/").lower() for item in self.allowed_origins.split(",") if item.strip())

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith("/") or len(value) < 2 or any(char.isspace() for char in value) or "?" in value:
            raise ValueError("MPVM_MCP_PATH must be an absolute path such as /mcp")
        if any(value == prefix or value.startswith(prefix + "/") for prefix in _RESERVED_PATH_PREFIXES):
            raise ValueError("MPVM_MCP_PATH must not be under /api or /static: the application owns those paths")
        return value
