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

    # The dedicated viewer account the tools read the API with.
    username: str = ""
    password: str = Field(default="", repr=False)
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    # Token that HTTP clients send to the embedded endpoint.
    auth_token: str = Field(default="", repr=False)

    # Answer shaping.
    stale_days: int = Field(default=14, ge=1, le=3650)
    max_response_chars: int = Field(default=60000, ge=2000, le=1_000_000)

    @field_validator("username", "auth_token")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith("/") or len(value) < 2 or any(char.isspace() for char in value) or "?" in value:
            raise ValueError("MPVM_MCP_PATH must be an absolute path such as /mcp")
        if any(value == prefix or value.startswith(prefix + "/") for prefix in _RESERVED_PATH_PREFIXES):
            raise ValueError("MPVM_MCP_PATH must not be under /api or /static: the application owns those paths")
        return value

    def problems(self) -> list[str]:
        """Configuration errors that stop the MCP endpoint from being mounted."""
        found: list[str] = []
        if not self.username or not self.password:
            found.append("MPVM_MCP_USERNAME and MPVM_MCP_PASSWORD are required (use a dedicated viewer account)")
        # The endpoint shares the application's port, so it is reachable wherever the app is.
        if not self.auth_token:
            found.append("MPVM_MCP_AUTH_TOKEN is required when MCP is served from the application port")
        return found
