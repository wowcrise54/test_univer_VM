from __future__ import annotations

import os
import asyncio
import copy
import csv
import io
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import asynccontextmanager
from contextvars import copy_context
from datetime import UTC, datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Literal

import requests
import psycopg
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse, Response, StreamingResponse

UVICORN_LOGGER = logging.getLogger("uvicorn.error")

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

from .diagnostics import (
    configure_diagnostics,
    current_trace_id,
    diagnostic_context,
    log_event,
    log_exception,
    new_trace_id,
    normalize_correlation_id,
    redact,
    set_diagnostic_context,
)

from .services.operation_diagnostics import build_operation_diagnostic_archive

configure_diagnostics()

from . import db
from . import auth as app_auth
from .repositories import passport_refresh
from .services import passport_refresh as passport_refresh_service
from .api.routers import (
    API_ROUTERS,
    asset_cards_router,
    asset_groups_router,
    asset_query_router,
    assets_router,
    diagnostics_router,
    imports_router,
    operations_router,
    passports_router,
    session_router,
    system_router,
    tasks_router,
    automations_router,
    notifications_router,
    auth_router,
)
from .api.schemas import (
    ASSET_CARD_MAX_DEPTH,
    AssetCardAssetQueryRequest,
    AssetCardBuildBatchJobRequest,
    AssetCardBuildJobRequest,
    AssetCardBuildRequest,
    AssetCardBulkRefreshRequest,
    AssetCardFieldQueryRequest,
    AssetCardPresetQueryRequest,
    AssetCardRefreshScanRequest,
    AssetCardUpdateRequest,
    ConnectionRequest,
    CsvTextImportRequest,
    DeleteScannerTaskRequest,
    FrontendDiagnosticBatch,
    PdqlExportRequest,
    SavedViewRequest,
    ScannerTaskRequest,
    StartScannerTaskRequest,
    VulnerabilityPassportQueryRequest,
    VulnerabilityReportRequest,
    VulnerabilityXlsxReportRequest,
    AutomationPublishRequest,
    AutomationRunRequest,
    AutomationRunbookRequest,
    AutomationScheduleRequest,
)
from .automations import AutomationRepository, AutomationService, AutomationStepCancelled
from .reports.vulnerability import render_vulnerability_xlsx
from .core import AppContainer, get_settings
from .factory import create_app
from .services.asset_card_builder import (
    AssetCardBuildCancelled,
    AssetCardRequestExecutor,
    build_asset_card,
    build_asset_vulnerability_snapshot,
)
from .services.asset_card_builder import configure as asset_card_builder_configure
from .api.middleware import (
    application_auth_middleware,
    auth_error,
    database_error_handler,
    diagnostic_http_middleware,
    error_component,
    operator_error_message,
    structured_http_error,
    structured_validation_error,
)
from .api.system import defaults, health, system_status
from .services.vm_workflow_calls import (
    _mpvm_call,
    start_team_scanner_task,
    start_vm_scan_child,
    start_vm_verification_children,
    stop_team_scanner_task,
)
from .services.mpvm_session import (
    _configure_session_from_env_unlocked,
    configure_session_from_env,
    env_connect_error_message,
    mpvm_session_connected,
    require_mpvm,
)
from .services.vulnerability_snapshots import (
    capture_vulnerability_snapshot,
    ensure_vulnerability_snapshot_baseline,
)
from .services.asset_search_backfill import run_asset_search_backfill, start_asset_search_backfill
from .api.asset_cards import (
    active_asset_card_build_job,
    asset_card_build_job,
    asset_card_refresh_templates,
    build_asset_card_endpoint,
    cancel_asset_card_build_job,
    create_asset_card_build_job,
    create_asset_card_build_jobs_batch,
    delete_local_asset_card,
    local_asset_card,
    local_asset_card_configuration_detail,
    local_asset_card_configuration_tree,
    local_asset_card_history,
    local_asset_card_summary,
    local_asset_card_vulnerability_findings,
    local_asset_card_vulnerability_groups,
    local_asset_cards,
    query_asset_card_assets,
    refresh_asset_card_by_scan,
    refresh_asset_cards_bulk,
    update_local_asset_card,
)
from .api.imports_exports import (
    download_export,
    export_pdql,
    export_vulnerability_report,
    export_vulnerability_xlsx,
    import_csv_file,
    import_csv_text,
    import_sample,
)
from .api.passports import (
    active_vulnerability_passport_detail_job,
    cancel_vulnerability_passport_detail_job,
    cancel_vulnerability_passport_refresh_job,
    create_vulnerability_passport_refresh_job,
    delete_vulnerability_passport,
    latest_vulnerability_passport_refresh_job,
    local_vulnerability_passports,
    query_vulnerability_passports,
    refresh_trending_vulnerability_passports,
    update_vulnerability_passport,
    vulnerability_passport,
    vulnerability_passport_asset_links,
    vulnerability_passport_detail_job,
    vulnerability_passport_refresh_job,
)
from .api.assets import assets, assets_summary
from .api.asset_query import (
    asset_card_query,
    asset_card_query_fields,
    asset_card_query_presets,
    execute_asset_card_query_preset,
    execute_asset_card_query_preset_assets,
    export_asset_card_query,
)
from .api.scanner_tasks import (
    create_scanner_task,
    delete_scanner_task_delete,
    delete_scanner_task_post,
    latest_scanner_task_postprocess_run,
    local_scanner_tasks,
    remote_scanner_tasks,
    retry_false_precheck,
    scanner_task_results,
    start_scanner_task,
    stop_scanner_task,
    update_scanner_task,
    validate_scanner_task,
)
from .api.session import connect_session, disconnect_session, mpvm_lookups, session_info
from .api.operations import (
    cancel_operation,
    clear_operations_history,
    operation_detail,
    operation_diagnostics,
    operations,
    operations_summary,
    record_frontend_diagnostics,
    remove_saved_view,
    retry_operation,
    saved_views,
    upsert_saved_view,
)
from .api.auth import (
    auth_audit,
    auth_bootstrap_status,
    auth_clone_role,
    auth_create_user,
    auth_delete_role,
    auth_delete_user,
    auth_login,
    auth_logout,
    auth_me,
    auth_permissions,
    auth_roles,
    auth_update_role,
    auth_update_user,
    auth_users,
)
from .api.automations import (
    automation_run,
    automation_runbook,
    automation_runbooks,
    automation_runs,
    automation_schedules,
    AUTOMATION_TEMPLATES,
    automation_templates,
    cancel_automation_run,
    clone_automation_runbook,
    create_automation_runbook,
    create_automation_schedule,
    delete_automation_runbook,
    delete_automation_schedule,
    mark_notification_read,
    notifications,
    publish_automation_runbook,
    retry_automation_run,
    run_automation_runbook,
    update_automation_runbook,
    update_automation_schedule,
)
from .services.asset_card_build_jobs import (
    _run_asset_card_build_job,
    register_asset_card_build_job,
    run_asset_card_build_job,
    run_asset_card_build_jobs,
    unregister_asset_card_build_job,
)
from .services.vulnerability_passport_jobs import (
    _execute_vulnerability_passport_query,
    register_vulnerability_passport_detail_job,
    run_vulnerability_passport_detail_job,
    run_vulnerability_passport_refresh_job,
    sync_trending_vulnerability_passports,
    unregister_vulnerability_passport_detail_job,
)
from .services.scanner_task_launch import (
    _start_scanner_task_request,
    chunks,
    delete_scanner_task_idempotent,
    delete_scanner_task_impl,
    remove_assets_after_export,
    resolve_asset_ids_by_ips,
    run_false_targets_precheck,
    run_precheck_for_scanner_task,
    scanner_task_payload,
    start_scanner_task_impl,
    sync_scanner_task_configuration_before_start,
)
from .services.asset_card_refresh import (
    build_asset_refresh_task_payload,
    execute_automation_step,
    refresh_asset_card_batch,
    refresh_asset_cards_for_automation,
    refresh_one_asset_card_for_automation,
    refresh_stale_asset_cards_for_automation,
    resolve_asset_card_refresh_template,
    run_asset_card_bulk_refresh_operation,
    run_background_tasks,
    wait_for_automation_operation,
)
from .services.docker_scan_groups import (
    confirm_docker_scan_terminal_for_cleanup,
    docker_group_cleanup_after,
    DOCKER_GROUP_CLEANUP_FUTURES,
    DOCKER_GROUP_CLEANUP_FUTURES_LOCK,
    finish_provisional_scan_start_failure,
    prepare_docker_dynamic_group_for_scan,
    remember_docker_scan_finished_at,
    remove_docker_dynamic_group,
    run_scan_docker_group_cleanup,
    schedule_scan_docker_group_cleanup,
)
from .services.scan_postprocess import (
    build_scanned_asset_card,
    cancel_scan_postprocess_run,
    cleanup_auto_created_refresh_task,
    finalize_asset_card_refresh,
    monitor_successful_scan_jobs,
    process_scanned_asset_item,
    process_scanned_asset_item_with_progress,
    raise_if_scan_postprocess_cancelled,
    refresh_docker_containers_for_scanned_asset,
    resolve_scanned_target_once,
    resume_scan_postprocess_runs,
    run_scan_postprocess,
    scan_log,
    SCAN_LOG,
    scan_postprocess_cancel_event,
    SCAN_POSTPROCESS_CANCEL_EVENTS,
    SCAN_POSTPROCESS_FUTURES,
    SCAN_POSTPROCESS_FUTURES_LOCK,
    ScanPostprocessCancelled,
    schedule_scan_postprocess,
    update_refresh_task_cleanup_message,
)
from .mpvm.common import (
    clean_text,
    extract_collection_count,
    extract_collection_items,
    first_present,
    http_error,
    json_dumps_compact,
    normalize_asset_metadata_key,
    normalize_boolean,
    number_or_none,
    number_or_zero,
    parse_mpvm_datetime,
    simplify_named_items,
)
from .mpvm.docker_vulnerabilities import (
    _docker_container_key,
    _docker_container_label,
    _docker_cve,
    _docker_finding_candidate_keys,
    _docker_finding_key,
    _docker_groups,
    _docker_image_label,
    _docker_instance_id,
    _docker_mapping_text,
    _docker_package_parts,
    _docker_record_raw_value,
    _docker_record_value,
    _extract_docker_fallback,
    build_docker_vulnerability_source,
    docker_dynamic_group_from_options,
    DOCKER_PDQL_REQUIRED_FIELDS,
    docker_scan_group_name,
    normalize_docker_vulnerability_record,
    render_docker_vulnerability_pdql,
    validate_docker_vulnerability_pdql,
)
from .mpvm.asset_metadata import (
    ASSET_CARD_STAGE_PROGRESS,
    asset_value_to_text,
    dedupe_asset_candidates,
    filter_windows_asset_metadata,
    is_excluded_windows_asset_card_branch,
    is_hidden_asset_technical_field,
    is_object_ref,
    is_windows_asset_card_root,
    labelize_asset_key,
    metadata_collection_name,
    metadata_collection_properties,
    metadata_data_has_property,
    metadata_properties_by_name,
    metadata_property_for_name,
    metadata_property_is_collection,
    normalize_asset_candidate_record,
    normalize_asset_vulnerabilities_header,
    normalize_asset_vulnerability_item,
    sanitize_asset_card_for_response,
    should_fetch_collection,
    strip_raw_asset_values,
    vulnerability_collection_id,
    WINDOWS_ASSET_CARD_EXCLUDED_COLLECTIONS,
)
from .mpvm.passport_records import (
    dedupe_vulnerability_passports,
    merge_trending_vulnerability_records,
    normalize_compact_items,
    normalize_passport_labels,
    normalize_passport_text,
    normalize_trending_vulnerability_record,
    normalize_vulnerability_passport_record,
    vulnerability_passport_summary,
)
from .mpvm.scanner_task_rows import (
    build_precheck_task_name,
    extract_remote_scanner_task_rows,
    is_remote_scanner_task_list_response,
    normalize_remote_scanner_task_template,
    remote_scanner_task_exists,
    remote_scanner_task_row_id,
    remote_scanner_task_row_is_deleted,
    remote_scanner_task_templates,
    SCANNER_TASK_TEMPLATE_FIELDS,
)
from .mpvm.scan_results import (
    _ip_equals,
    _ip_in_network,
    extract_asset_grid_records,
    extract_asset_grid_total,
    fetch_asset_grid_records,
    normalize_scanned_asset_record,
    query_scanned_asset_records,
    scanned_asset_record_is_current,
    scanned_asset_record_matches,
    successful_scan_target_jobs,
)
from .reports.vulnerability_csv import (
    safe_csv_cell,
    stream_vulnerability_report_csv,
    VULNERABILITY_REPORT_HEADERS,
)
from .mpvm_client import (
    ASSET_CARD_PDQL,
    DOCKER_VULNERABILITY_PDQL,
    SOFTWARE_VULN_PDQL,
    TRENDING_VULNERABILITY_PDQL,
    VULNER_PASSPORT_PDQL,
    AuthConfig,
    MpVmApiError,
    MpVmClient,
    build_asset_id_pdql_for_ips,
    build_asset_resolution_pdql,
    build_default_token_url,
    build_scanner_task_payload,
    extract_asset_ids_from_csv,
    extract_uuid,
    extract_ips_from_csv,
    has_success_status,
    is_host_discovery_profile,
    is_finished,
    normalize_url,
)


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
EXPORTS_DIR = Path(os.getenv("MPVM_EXPORTS_DIR", "exports"))
SAMPLE_CSV = Path("host_software_vulnerabilities_10.104.103.0_24.csv")
def env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


SETTINGS = get_settings()
BACKGROUND_REQUEST_LIMIT = min(32, SETTINGS.background_request_limit)
ASSET_CARD_REQUEST_WORKERS = min(
    BACKGROUND_REQUEST_LIMIT,
    min(20, SETTINGS.asset_card_request_workers),
)
SCAN_POSTPROCESS_WORKERS = min(10, SETTINGS.scan_postprocess_workers)
ASSET_CARD_REFRESH_WORKERS = min(10, SETTINGS.asset_card_refresh_workers, SCAN_POSTPROCESS_WORKERS)
SCAN_ASSET_PROCESS_WORKERS = min(4, SETTINGS.scan_asset_process_workers)
SCAN_TARGET_RESOLUTION_WORKERS = min(4, SETTINGS.scan_target_resolution_workers)
RECONCILIATION_WORKERS = min(4, SETTINGS.reconciliation_workers)
PASSPORT_DETAIL_WORKERS = min(
    BACKGROUND_REQUEST_LIMIT,
    min(32, SETTINGS.passport_detail_workers),
)
PASSPORT_DETAIL_TTL_HOURS = min(8760, SETTINGS.passport_detail_ttl_hours)
PASSPORT_DETAIL_DB_BATCH_SIZE = 100
ASSET_METADATA_TTL_SECONDS = min(86400, SETTINGS.asset_metadata_ttl_seconds)
SCAN_ASSET_RESOLUTION_TIMEOUT_SECONDS = min(3600, SETTINGS.scan_asset_resolution_timeout_seconds)
SCAN_ASSET_RESOLUTION_POLL_SECONDS = min(300, SETTINGS.scan_asset_resolution_poll_seconds)
SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS = min(7200, SETTINGS.scan_asset_removal_timeout_seconds)
SCAN_ASSET_REMOVAL_POLL_SECONDS = min(300, SETTINGS.scan_asset_removal_poll_seconds)
DOCKER_DYNAMIC_GROUP_ITERATIONS = min(10, SETTINGS.docker_dynamic_group_iterations)
DOCKER_DYNAMIC_GROUP_SETTLE_SECONDS = min(300, SETTINGS.docker_dynamic_group_settle_seconds)
DOCKER_DYNAMIC_GROUP_TIMEOUT_SECONDS = min(900, SETTINGS.docker_dynamic_group_timeout_seconds)
DOCKER_DYNAMIC_GROUP_POLL_SECONDS = min(60, SETTINGS.docker_dynamic_group_poll_seconds)
DOCKER_DYNAMIC_GROUP_RETENTION_SECONDS = min(86400, SETTINGS.docker_dynamic_group_retention_seconds)
DOCKER_DYNAMIC_GROUP_PARENT_ID = "00000000-0000-0000-0000-000000000002"
DOCKER_DYNAMIC_GROUP_PREDICATE = "(ImageSet)"
CONTAINER = AppContainer(SETTINGS)
SESSION = CONTAINER.session
AUTOMATION_REPOSITORY = AutomationRepository()
AUTOMATION_SERVICE: AutomationService | None = None
DATABASE_STARTUP_ERROR: str | None = None
MPVM_ENV_CONNECT_LOCK = threading.Lock()
MPVM_ENV_CONNECT_RETRY_AFTER = 0.0
MPVM_ENV_CONNECT_BACKOFF_SECONDS = 30.0
# Last reason the .env auto-connect failed; surfaced by /api/session so the UI
# does not silently show "disconnected" while the cause is only in the logs.
MPVM_ENV_CONNECT_ERROR: str | None = None
BACKGROUND_REQUEST_SEMAPHORE = CONTAINER.background_request_semaphore
ASSET_CARD_REFRESH_SEMAPHORE = CONTAINER.asset_card_refresh_semaphore
ASSET_CARD_BUILD_WORKERS = 2
ASSET_CARD_BUILD_SEMAPHORE = threading.BoundedSemaphore(ASSET_CARD_BUILD_WORKERS)
ASSET_METADATA_CACHE = CONTAINER.asset_metadata_cache
ASSET_METADATA_INFLIGHT = CONTAINER.asset_metadata_inflight
ASSET_METADATA_CACHE_LOCK = CONTAINER.asset_metadata_cache_lock
asset_card_builder_configure(
    background_semaphore=BACKGROUND_REQUEST_SEMAPHORE,
    metadata_cache=ASSET_METADATA_CACHE,
    metadata_inflight=ASSET_METADATA_INFLIGHT,
    metadata_cache_lock=ASSET_METADATA_CACHE_LOCK,
    metadata_ttl_seconds=ASSET_METADATA_TTL_SECONDS,
)


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    startup()
    try:
        yield
    finally:
        shutdown()


def automation_service_account_ready() -> bool:
    configured = bool(
        SETTINGS.api_url
        and (SETTINGS.access_token or (SETTINGS.username and SETTINGS.password and SETTINGS.client_secret))
    )
    return configured and SESSION.client is not None and SESSION.access_token is not None


def get_automation_service() -> AutomationService:
    global AUTOMATION_SERVICE
    if AUTOMATION_SERVICE is None:
        AUTOMATION_SERVICE = AutomationService(
            AUTOMATION_REPOSITORY,
            CONTAINER.operation_runner,
            SETTINGS,
            execute_automation_step,
            automation_service_account_ready,
            lambda: CONTAINER.services.remediation.ensure_daily_digest(
                webhook_enabled=bool(SETTINGS.automation_webhook_url)
            ),
        )
    return AUTOMATION_SERVICE


def shutdown() -> None:
    CONTAINER.database_recovery.stop()
    if AUTOMATION_SERVICE is not None:
        AUTOMATION_SERVICE.stop_scheduler()
    CONTAINER.shutdown()
    log_event("app", "app.shutdown.completed", active_operations=CONTAINER.operation_runner.active_count())


app = create_app(static_dir=STATIC_DIR, lifespan=app_lifespan, cors_origins=SETTINGS.cors_origins)
app.state.container = CONTAINER


PUBLIC_API_PATHS = {
    "/api/auth/login",
    "/api/auth/bootstrap-status",
    "/api/health",
    "/api/live",
    "/api/ready",
    # Authenticated by MPVM_METRICS_TOKEN inside the handler (404 when unset).
    "/api/metrics",
}
AUDITED_PERMISSIONS = {
    "security.users.manage", "security.roles.manage", "connection.manage",
    "remediation.policy", "diagnostics.read", "operations.clear",
    # Write permissions: who started, stopped, retried or changed what.
    # task_presets.manage and tasks.team are audited in their own handlers.
    "tasks.manage", "tasks.execute", "operations.cancel", "operations.retry",
    "remediation.manage", "risk.manage", "asset_groups.manage",
    "asset_cards.manage", "asset_cards.build", "passports.manage",
    "automations.manage", "automations.execute", "imports_exports.manage",
}


app.middleware("http")(application_auth_middleware)


app.middleware("http")(diagnostic_http_middleware)


ASSET_SEARCH_BACKFILL_LOCK = threading.Lock()
ASSET_SEARCH_BACKFILL_RUNNING = False


app.exception_handler(HTTPException)(structured_http_error)


app.exception_handler(RequestValidationError)(structured_validation_error)


def startup() -> None:
    global DATABASE_STARTUP_ERROR
    CONTAINER.start()
    log_event("app", "app.startup.started", process_id=os.getpid())
    from sys import modules

    from .services.startup import database_startup_steps

    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    configure_session_from_env()
    CONTAINER.database_recovery.configure(database_startup_steps(modules[__name__]))
    state = CONTAINER.database_recovery.check()
    DATABASE_STARTUP_ERROR = None if state["ready"] else state.get("reason", "RecoveryPending")
    CONTAINER.database_recovery.start()
    scan_log(
        logging.INFO,
        "worker_limits",
        scan_postprocess_workers=SCAN_POSTPROCESS_WORKERS,
        scan_asset_process_workers=SCAN_ASSET_PROCESS_WORKERS,
        scan_target_resolution_workers=SCAN_TARGET_RESOLUTION_WORKERS,
        reconciliation_workers=RECONCILIATION_WORKERS,
        asset_card_request_workers=ASSET_CARD_REQUEST_WORKERS,
        asset_card_refresh_workers=ASSET_CARD_REFRESH_WORKERS,
    )
    log_event(
        "app",
        "app.startup.completed",
        database_ready=DATABASE_STARTUP_ERROR is None,
        connected=SESSION.client is not None and SESSION.access_token is not None,
    )


app.exception_handler(psycopg.Error)(database_error_handler)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def resume_connected_workflows() -> None:
    resume_scan_postprocess_runs()
    CONTAINER.services.vm_workflows.resume()


def decode_csv_bytes(content: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


CONTAINER.services.task_presets.configure(
    lookups_provider=mpvm_lookups,
    groups_provider=lambda: _mpvm_call(lambda client, token: client.get_asset_group_hierarchy(token)),
)
CONTAINER.services.team_tasks.configure(
    create_remote=lambda payload: _mpvm_call(lambda client, token: client.create_scanner_task(token, payload)),
    update_remote=lambda task_id, payload: _mpvm_call(
        lambda client, token: client.update_scanner_task(token, task_id, payload),
    ),
    start_task=start_team_scanner_task,
    stop_task=stop_team_scanner_task,
    delete_task=lambda task_id, key: delete_scanner_task_idempotent(
        task_id, DeleteScannerTaskRequest(mode="auto"), key,
    ),
)


CONTAINER.services.vm_workflows.configure(
    scan_starter=start_vm_scan_child,
    verification_starter=start_vm_verification_children,
    operation_canceller=cancel_operation,
    status_provider=system_status,
    task_provider=CONTAINER.services.tasks.list,
    operation_provider=lambda: db.list_operations(limit=200, sync_sources=True),
)


for api_router in API_ROUTERS:
    app.include_router(api_router)


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str) -> FileResponse:
    if full_path.startswith(("api/", "static/")):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(STATIC_DIR / "index.html")


# Added last so the MCP path is matched before the other middleware; it has its own bearer-token guard.
# Off unless MPVM_MCP_ENABLED is set (docs/mcp.md).
from mcp_server.embed import install_embedded_mcp  # noqa: E402

install_embedded_mcp(app)
