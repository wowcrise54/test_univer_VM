from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def is_loopback(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


class McpSettings(BaseSettings):
    """Validated configuration loaded from ``MPVM_MCP_*`` variables."""

    model_config = SettingsConfigDict(env_prefix="MPVM_MCP_", extra="ignore", case_sensitive=False)

    # MP VM Client REST API that the server reads from.
    api_url: str = "http://mpvm-client:8000"
    username: str = ""
    password: str = Field(default="", repr=False)
    verify_tls: bool = True
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)

    # How the MCP server itself is exposed.
    transport: Literal["streamable-http", "stdio"] = "streamable-http"
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)
    auth_token: str = Field(default="", repr=False)

    # Answer shaping.
    stale_days: int = Field(default=14, ge=1, le=3650)
    max_response_chars: int = Field(default=60000, ge=2000, le=1_000_000)

    @field_validator("api_url")
    @classmethod
    def normalize_api_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.lower().startswith(("http://", "https://")):
            raise ValueError("MPVM_MCP_API_URL must start with http:// or https://")
        return value

    @field_validator("username", "auth_token")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def require_credentials_and_token(self) -> McpSettings:
        if not self.username or not self.password:
            raise ValueError("MPVM_MCP_USERNAME and MPVM_MCP_PASSWORD are required (use a dedicated viewer account)")
        if self.transport == "streamable-http" and not self.auth_token and not is_loopback(self.host):
            raise ValueError("MPVM_MCP_AUTH_TOKEN is required when the HTTP server listens on a non-loopback address")
        return self
