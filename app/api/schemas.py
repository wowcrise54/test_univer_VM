from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ..mpvm_client import ASSET_CARD_PDQL, SOFTWARE_VULN_PDQL, VULNER_PASSPORT_PDQL


class ConnectionRequest(BaseModel):
    api_url: str
    token_url: str | None = None
    username: str | None = None
    password: str | None = None
    client_id: str = "mpx"
    client_secret: str | None = None
    scope: str = "authorization offline_access mpx.api ptkb.api"
    access_token: str | None = None
    verify_tls: bool = True
    timeout: float = 120


class ScannerTaskRequest(BaseModel):
    name: str
    description: str | None = ""
    scope_id: str
    profile_id: str
    include_targets: list[str] = Field(default_factory=list)
    exclude_targets: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    credential_id: str | None = None
    host_discovery_enabled: bool = False
    host_discovery_profile_id: str | None = None
    time_zone: str = "+05:00"
    is_fqdn_priority: bool = True
    raw_payload: dict[str, Any] | None = None


class DeleteScannerTaskRequest(BaseModel):
    mode: Literal["delete_v3", "put_v4"] = "delete_v3"
    put_payload: dict[str, Any] | None = None


class StartScannerTaskRequest(BaseModel):
    precheck_enabled: bool = False
    precheck_profile_id: str | None = None
    precheck_task_prefix: str = "MP VM credential precheck"
    precheck_timeout_minutes: float = Field(default=10, gt=0)
    precheck_max_runtime_minutes: float = Field(default=5, ge=0)
    precheck_poll_seconds: float = Field(default=10, gt=0)
    precheck_jobs_limit: int = Field(default=1000, gt=0)
    wait_for_finish: bool = False
    task_timeout_minutes: float = Field(default=120, gt=0)
    task_poll_seconds: float = Field(default=15, gt=0)
    require_clean_jobs: bool = False
    create_settle_seconds: float = Field(default=30, ge=0)
    skip_validation: bool = False


class AssetCardRefreshScanRequest(BaseModel):
    template_task_id: str | None = None
    start_options: StartScannerTaskRequest = Field(default_factory=StartScannerTaskRequest)


class PdqlExportRequest(BaseModel):
    pdql: str = SOFTWARE_VULN_PDQL
    utc_offset: str | None = "+05:00"
    group_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    include_nested_groups: bool = True
    import_results: bool = True
    delete_assets_after_export: bool = True
    delete_timeout_minutes: float = 30
    delete_poll_seconds: float = 10


class CsvTextImportRequest(BaseModel):
    csv_text: str
    source: str = "manual_text"
    pdql: str | None = None
    csv_filename: str | None = None


class VulnerabilityPassportQueryRequest(BaseModel):
    pdql: str = VULNER_PASSPORT_PDQL
    utc_offset: str | None = "+05:00"
    group_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    include_nested_groups: bool = True
    limit: int | None = Field(default=None, ge=1)
    batch_size: int = Field(default=5000, ge=1, le=10000)
    save_to_db: bool = True
    load_details: bool = True


class AssetCardAssetQueryRequest(BaseModel):
    pdql: str = ASSET_CARD_PDQL
    utc_offset: str | None = "+05:00"
    group_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    include_nested_groups: bool = True
    limit: int = Field(default=1001, ge=1, le=50000)
    batch_size: int = Field(default=5000, ge=1, le=10000)


class AssetCardBuildRequest(BaseModel):
    asset_id: str
    timeline_timestamp: int | None = None
    limit_per_collection: int = Field(default=5000, ge=1, le=5000)
    max_items_per_collection: int = Field(default=5000, ge=1, le=50000)
    max_depth: int = Field(default=8, ge=0, le=8)
    save_to_db: bool = True


class AssetCardBuildJobRequest(BaseModel):
    asset_id: str
    timeline_timestamp: int | None = None
    limit_per_collection: int = Field(default=5000, ge=1, le=5000)
    max_items_per_collection: int = Field(default=5000, ge=1, le=50000)
    max_depth: int = Field(default=8, ge=0, le=8)


class AssetCardUpdateRequest(BaseModel):
    timeline_timestamp: int | None = None
    limit_per_collection: int = Field(default=5000, ge=1, le=5000)
    max_items_per_collection: int = Field(default=5000, ge=1, le=50000)
    max_depth: int = Field(default=8, ge=0, le=8)


class FrontendDiagnosticEvent(BaseModel):
    event: str = Field(min_length=1, max_length=128)
    level: Literal["debug", "info", "warning", "error"] = "info"
    timestamp: str | None = Field(default=None, max_length=64)
    trace_id: str | None = Field(default=None, max_length=128)
    request_id: str | None = Field(default=None, max_length=128)
    url: str | None = Field(default=None, max_length=2048)
    section: str | None = Field(default=None, max_length=128)
    stack: str | None = Field(default=None, max_length=128000)
    fields: dict[str, Any] = Field(default_factory=dict)


class FrontendDiagnosticBatch(BaseModel):
    events: list[FrontendDiagnosticEvent] = Field(min_length=1, max_length=100)


class SavedViewRequest(BaseModel):
    route: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    filters: dict[str, Any] = Field(default_factory=dict)


class AssetCardFieldQueryRequest(BaseModel):
    query: dict[str, Any]
    sort_by: str = "display_name"
    sort_dir: Literal["asc", "desc"] = "asc"
    limit: int = Field(default=50, ge=1, le=50000)
    offset: int = Field(default=0, ge=0)
