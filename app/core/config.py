from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Validated process configuration loaded from ``MPVM_*`` variables."""

    model_config = SettingsConfigDict(
        env_prefix="MPVM_",
        env_file=ROOT_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    api_url: str = ""
    token_url: str = ""
    username: str = ""
    password: str = Field(default="", repr=False)
    client_id: str = "mpx"
    client_secret: str = Field(default="", repr=False)
    scope: str = "authorization offline_access mpx.api ptkb.api"
    access_token: str = Field(default="", repr=False)
    insecure: bool = False
    timeout: int = 120

    database_url: str = "postgresql://mpvm:mpvm@localhost:5432/mpvm"
    exports_dir: Path = Path("exports")
    background_request_limit: int = 10
    asset_card_request_workers: int = 8
    scan_postprocess_workers: int = 1
    scan_asset_process_workers: int = 1
    passport_detail_workers: int = 10
    passport_detail_ttl_hours: int = 24
    asset_metadata_ttl_seconds: int = 3600
    scan_asset_resolution_timeout_seconds: int = 600
    scan_asset_resolution_poll_seconds: int = 15
    scan_asset_removal_timeout_seconds: int = 1800
    scan_asset_removal_poll_seconds: int = 10

    @field_validator(
        "timeout",
        "background_request_limit",
        "asset_card_request_workers",
        "scan_postprocess_workers",
        "scan_asset_process_workers",
        "passport_detail_workers",
        "scan_asset_resolution_timeout_seconds",
        "scan_asset_resolution_poll_seconds",
        "scan_asset_removal_timeout_seconds",
        "scan_asset_removal_poll_seconds",
    )
    @classmethod
    def positive_integer(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be greater than zero")
        return value

    @field_validator("passport_detail_ttl_hours", "asset_metadata_ttl_seconds")
    @classmethod
    def non_negative_integer(cls, value: int) -> int:
        if value < 0:
            raise ValueError("must not be negative")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
