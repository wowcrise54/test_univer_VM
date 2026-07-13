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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

import requests
import psycopg
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse, Response, StreamingResponse

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

from .diagnostics import (
    configure_diagnostics,
    build_diagnostic_archive,
    current_trace_id,
    diagnostic_context,
    log_event,
    log_exception,
    new_trace_id,
    normalize_correlation_id,
    redact,
    set_diagnostic_context,
)

configure_diagnostics()

from . import db
from . import auth as app_auth
from .api.routers import (
    API_ROUTERS,
    asset_cards_router,
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
    AssetCardAssetQueryRequest,
    AssetCardBuildJobRequest,
    AssetCardBuildRequest,
    AssetCardFieldQueryRequest,
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
    AutomationPublishRequest,
    AutomationRunRequest,
    AutomationRunbookRequest,
    AutomationScheduleRequest,
)
from .automations import AutomationRepository, AutomationService
from .core import AppContainer, get_settings
from .factory import create_app
from .mpvm_client import (
    ASSET_CARD_PDQL,
    SOFTWARE_VULN_PDQL,
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
SCAN_LOG = logging.getLogger("uvicorn.error")


def scan_log(level: int, event: str, **fields: Any) -> None:
    log_event("app", event, level=level, component="scan-postprocess", **fields)
    payload = {"event": event, **{key: value for key, value in fields.items() if value is not None}}
    SCAN_LOG.log(level, "[scan-postprocess] %s", json.dumps(redact(payload), ensure_ascii=False, default=str))


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
    min(16, SETTINGS.asset_card_request_workers),
)
SCAN_POSTPROCESS_WORKERS = min(4, SETTINGS.scan_postprocess_workers)
SCAN_ASSET_PROCESS_WORKERS = min(4, SETTINGS.scan_asset_process_workers)
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
ASSET_CARD_STAGE_PROGRESS = {
    "queued": 0,
    "starting": 5,
    "collecting": 5,
    "timeline": 10,
    "root": 15,
    "tree_and_vulnerabilities": 25,
    "tree_ready": 60,
    "vulnerabilities_ready": 60,
    "assembling": 85,
    "saving": 95,
    "completed": 100,
}


CONTAINER = AppContainer(SETTINGS)
SESSION = CONTAINER.session
AUTOMATION_REPOSITORY = AutomationRepository()
AUTOMATION_SERVICE: AutomationService | None = None
DATABASE_STARTUP_ERROR: str | None = None
SCAN_POSTPROCESS_FUTURES: dict[str, Future[Any]] = {}
SCAN_POSTPROCESS_FUTURES_LOCK = threading.Lock()
BACKGROUND_REQUEST_SEMAPHORE = CONTAINER.background_request_semaphore
ASSET_METADATA_CACHE = CONTAINER.asset_metadata_cache
ASSET_METADATA_INFLIGHT = CONTAINER.asset_metadata_inflight
ASSET_METADATA_CACHE_LOCK = CONTAINER.asset_metadata_cache_lock


class AssetCardBuildCancelled(Exception):
    pass


class AssetCardRequestExecutor:
    def __init__(
        self,
        *,
        auth: AuthConfig,
        token: str,
        workers: int,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self.auth = auth
        self.token = token
        self.cancel_event = cancel_event or threading.Event()
        self.on_progress = on_progress
        self.worker_count = max(1, workers)
        self._executor = ThreadPoolExecutor(max_workers=self.worker_count, thread_name_prefix="asset-card-request")
        self._worker_state = threading.local()
        self._clients: list[MpVmClient] = []
        self._clients_lock = threading.Lock()
        self._progress_lock = threading.Lock()
        self._telemetry_lock = threading.Lock()
        self.discovered = 0
        self.completed = 0
        self.active = 0
        self.peak_active = 0
        self.queue_wait_ms = 0.0
        self.request_duration_ms: dict[str, float] = {}
        self.request_counts: dict[str, int] = {}

    def _client(self) -> MpVmClient:
        client = getattr(self._worker_state, "client", None)
        if client is None:
            client = MpVmClient(self.auth)
            self._worker_state.client = client
            with self._clients_lock:
                self._clients.append(client)
        return client

    def _run(self, operation: Callable[[MpVmClient], Any], queued_at: float, label: str) -> Any:
        if self.cancel_event.is_set():
            raise AssetCardBuildCancelled("Asset card build was cancelled.")
        with BACKGROUND_REQUEST_SEMAPHORE:
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            with self._progress_lock:
                self.active += 1
                active = self.active
                self.peak_active = max(self.peak_active, active)
            started = time.perf_counter()
            queue_wait_ms = (started - queued_at) * 1000
            with self._telemetry_lock:
                self.queue_wait_ms += queue_wait_ms
            log_event(
                "asset-card-build",
                "request.worker.started",
                level=logging.DEBUG,
                worker=threading.current_thread().name,
                active_workers=active,
                worker_limit=self.worker_count,
            )
            try:
                return operation(self._client())
            finally:
                duration_ms = (time.perf_counter() - started) * 1000
                with self._telemetry_lock:
                    self.request_counts[label] = self.request_counts.get(label, 0) + 1
                    self.request_duration_ms[label] = self.request_duration_ms.get(label, 0.0) + duration_ms
                with self._progress_lock:
                    self.active = max(0, self.active - 1)
                    active = self.active
                log_event(
                    "asset-card-build",
                    "request.worker.completed",
                    level=logging.DEBUG,
                    worker=threading.current_thread().name,
                    active_workers=active,
                    worker_limit=self.worker_count,
                )

    def record_request_started(self) -> None:
        with self._progress_lock:
            self.discovered += 1
            discovered = self.discovered
            completed = self.completed
        if self.on_progress:
            self.on_progress(discovered, completed)

    def record_request_completed(self) -> None:
        with self._progress_lock:
            self.completed += 1
            discovered = self.discovered
            completed = self.completed
        if self.on_progress:
            self.on_progress(discovered, completed)

    def submit(
        self,
        operation: Callable[[MpVmClient], Any],
        *,
        count_progress: bool = True,
        label: str = "request",
    ) -> Future[Any]:
        if count_progress:
            self.record_request_started()
        context = copy_context()
        log_event(
            "asset-card-build",
            "request.scheduled",
            level=logging.DEBUG,
            discovered_requests=self.discovered,
            completed_requests=self.completed,
            queued_requests=max(0, self.discovered - self.completed - self.active),
            active_workers=self.active,
            worker_limit=self.worker_count,
        )
        future = self._executor.submit(context.run, self._run, operation, time.perf_counter(), label)

        def mark_completed(_future: Future[Any]) -> None:
            if count_progress:
                self.record_request_completed()

        future.add_done_callback(mark_completed)
        return future

    def call(self, operation: Callable[[MpVmClient], Any], *, label: str = "request") -> Any:
        return self.submit(operation, label=label).result()

    def map(self, operations: list[Callable[[MpVmClient], Any]]) -> list[Any]:
        settled = self.map_settled(operations)
        values: list[Any] = []
        for value, error in settled:
            if error is not None:
                raise error
            values.append(value)
        return values

    def map_settled(
        self,
        operations: list[Callable[[MpVmClient], Any]],
        *,
        count_progress: bool = True,
        label: str = "request",
    ) -> list[tuple[Any | None, Exception | None]]:
        results: list[tuple[Any | None, Exception | None]] = []
        for start in range(0, len(operations), self.worker_count):
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            # Keep the executor queue bounded. This also means cancellation stops
            # the coordinator before it schedules another batch of requests.
            futures = [
                self.submit(operation, count_progress=count_progress, label=label)
                for operation in operations[start : start + self.worker_count]
            ]
            for future in futures:
                try:
                    results.append((future.result(), None))
                except AssetCardBuildCancelled:
                    raise
                except Exception as exc:
                    results.append((None, exc))
        return results

    def map_labeled_settled(
        self,
        operations: list[tuple[str, Callable[[MpVmClient], Any]]],
        *,
        count_progress: bool = True,
    ) -> list[tuple[Any | None, Exception | None]]:
        results: list[tuple[Any | None, Exception | None]] = []
        for start in range(0, len(operations), self.worker_count):
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            futures = [
                self.submit(operation, count_progress=count_progress, label=label)
                for label, operation in operations[start : start + self.worker_count]
            ]
            for future in futures:
                try:
                    results.append((future.result(), None))
                except AssetCardBuildCancelled:
                    raise
                except Exception as exc:
                    results.append((None, exc))
        return results

    def telemetry(self) -> dict[str, Any]:
        with self._progress_lock, self._telemetry_lock:
            return {
                "peak_active_requests": self.peak_active,
                "queue_wait_ms": round(self.queue_wait_ms, 2),
                "request_counts": dict(sorted(self.request_counts.items())),
                "request_duration_ms": {
                    key: round(value, 2) for key, value in sorted(self.request_duration_ms.items())
                },
            }

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)
        for client in self._clients:
            client.session.close()


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
    if AUTOMATION_SERVICE is not None:
        AUTOMATION_SERVICE.stop_scheduler()
    CONTAINER.shutdown()
    log_event("app", "app.shutdown.completed", active_operations=CONTAINER.operation_runner.active_count())


app = create_app(static_dir=STATIC_DIR, lifespan=app_lifespan)
app.state.container = CONTAINER


PUBLIC_API_PATHS = {
    "/api/auth/login",
    "/api/auth/bootstrap-status",
    "/api/health",
}
SENSITIVE_PERMISSIONS = {
    "security.users.manage", "security.roles.manage", "connection.manage",
    "remediation.policy", "diagnostics.read",
}


def auth_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": {"code": code, "message": message, "component": "auth", "retryable": False}},
    )


@app.middleware("http")
async def application_auth_middleware(request: Request, call_next):
    path = request.url.path
    if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("sec-fetch-site") == "cross-site":
        return auth_error(403, "CROSS_SITE_REQUEST", "Межсайтовый запрос отклонён.")
    if not path.startswith("/api/") or path in PUBLIC_API_PATHS or request.method == "OPTIONS":
        return await call_next(request)
    try:
        user = app_auth.get_session_user(request.cookies.get(app_auth.COOKIE_NAME))
    except psycopg.Error:
        return auth_error(503, "AUTH_DATABASE_UNAVAILABLE", "Авторизация временно недоступна.")
    if not user:
        return auth_error(401, "AUTH_REQUIRED", "Войдите в приложение.")
    request.state.user = user
    if path in {"/api/auth/me", "/api/auth/logout"}:
        return await call_next(request)
    permission = app_auth.required_permission(request.method, path)
    effective = set(user.get("permissions") or app_auth.BUILTIN_ROLE_PERMISSIONS.get(user.get("role"), ()))
    if permission and permission not in effective:
        app_auth.audit_event(request=request, user=user, event_type="access", decision="deny", permission_key=permission, target_type="api", target_id=path)
        return auth_error(403, "PERMISSION_DENIED", f"Недостаточно прав: {permission}.")
    if permission in SENSITIVE_PERMISSIONS and not app_auth.is_elevated(user):
        app_auth.audit_event(request=request, user=user, event_type="reauth_required", decision="deny", permission_key=permission, target_type="api", target_id=path)
        return auth_error(403, "REAUTH_REQUIRED", "Повторно подтвердите пароль для критического действия.")
    response = await call_next(request)
    if permission in SENSITIVE_PERMISSIONS and response.status_code < 400:
        app_auth.audit_event(request=request, user=user, event_type="critical_action", decision="allow", permission_key=permission, target_type="api", target_id=path)
    return response


@app.middleware("http")
async def diagnostic_http_middleware(request: Request, call_next):
    trace_id = normalize_correlation_id(request.headers.get("x-trace-id")) or new_trace_id()
    request_id = normalize_correlation_id(request.headers.get("x-request-id")) or new_trace_id()
    started = time.perf_counter()
    request.state.trace_id = trace_id
    request.state.request_id = request_id
    with diagnostic_context(trace_id=trace_id, request_id=request_id):
        log_event(
            "app",
            "api.request.started",
            level=logging.DEBUG,
            method=request.method,
            path=request.url.path,
            query=redact(dict(request.query_params)),
        )
        try:
            response = await call_next(request)
        except Exception:
            log_exception(
                "app",
                "api.request.failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f'app;dur={duration_ms:.2f}'
        size_header = response.headers.get("content-length")
        response_size = int(size_header) if size_header and size_header.isdigit() else None
        log_event(
            "app",
            "api.response",
            level=logging.INFO if response.status_code < 500 else logging.ERROR,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            handler_and_serialization_ms=duration_ms,
            response_bytes=response_size,
            content_encoding=response.headers.get("content-encoding"),
            etag=response.headers.get("etag"),
            server_timing=response.headers.get("server-timing"),
        )
        return response


ASSET_SEARCH_BACKFILL_LOCK = threading.Lock()
ASSET_SEARCH_BACKFILL_RUNNING = False


def start_asset_search_backfill() -> None:
    global ASSET_SEARCH_BACKFILL_RUNNING
    with ASSET_SEARCH_BACKFILL_LOCK:
        if ASSET_SEARCH_BACKFILL_RUNNING:
            return
        try:
            coverage = db.asset_card_search_index_coverage()
        except psycopg.Error:
            return
        if coverage["indexed_cards"] >= coverage["total_cards"]:
            return
        ASSET_SEARCH_BACKFILL_RUNNING = True
    thread = threading.Thread(target=run_asset_search_backfill, daemon=True, name="asset-search-backfill")
    thread.start()


def run_asset_search_backfill() -> None:
    global ASSET_SEARCH_BACKFILL_RUNNING
    operation_id = str(uuid.uuid4())
    try:
        coverage = db.asset_card_search_index_coverage()
        total = max(coverage["total_cards"], 1)
        db.register_operation(
            operation_id,
            kind="asset_search_reindex",
            source_id=operation_id,
            status="running",
            stage="indexing",
            progress_percent=round(coverage["indexed_cards"] * 100 / total),
            subject_type="asset_cards",
            subject_label="Индекс полей карточек активов",
            message="Индексируются существующие карточки активов.",
        )
        while coverage["indexed_cards"] < coverage["total_cards"]:
            batch = db.backfill_asset_card_search_index_batch(limit=20)
            if not batch["processed"]:
                break
            coverage = batch
            db.register_operation(
                operation_id,
                kind="asset_search_reindex",
                source_id=operation_id,
                status="running",
                stage="indexing",
                progress_percent=round(coverage["indexed_cards"] * 100 / max(coverage["total_cards"], 1)),
                subject_type="asset_cards",
                subject_label="Индекс полей карточек активов",
                message=f"Проиндексировано карточек: {coverage['indexed_cards']} из {coverage['total_cards']}.",
                result=coverage,
            )
        final_status = "completed" if coverage["indexed_cards"] >= coverage["total_cards"] else "completed_with_errors"
        db.register_operation(
            operation_id,
            kind="asset_search_reindex",
            source_id=operation_id,
            status=final_status,
            stage=final_status,
            progress_percent=100,
            subject_type="asset_cards",
            subject_label="Индекс полей карточек активов",
            message=f"Индексация завершена: {coverage['indexed_cards']} из {coverage['total_cards']} карточек.",
            result=coverage,
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
    except Exception as exc:
        log_exception("app", "asset_search.backfill.failed", operation_id=operation_id)
        try:
            db.register_operation(
                operation_id,
                kind="asset_search_reindex",
                source_id=operation_id,
                status="failed",
                stage="failed",
                subject_type="asset_cards",
                subject_label="Индекс полей карточек активов",
                message="Не удалось завершить индексацию карточек.",
                error={"message": str(exc)[:1000]},
                finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
        except Exception:
            pass
    finally:
        with ASSET_SEARCH_BACKFILL_LOCK:
            ASSET_SEARCH_BACKFILL_RUNNING = False


def error_component(path: str) -> str:
    if path.startswith("/api/session") or path.startswith("/api/mpvm"):
        return "mpvm"
    if path.startswith("/api/asset-cards"):
        return "asset_cards"
    if path.startswith("/api/vulnerability-passports"):
        return "vulnerability_passports"
    if path.startswith("/api/vulnerabilities"):
        return "vulnerabilities"
    if path.startswith("/api/scanner-tasks"):
        return "scanner_tasks"
    if path.startswith("/api/operations"):
        return "operations"
    return "application"


def operator_error_message(status_code: int, component: str, message: str) -> str:
    if status_code == 503:
        return "Локальная база данных недоступна. Проверьте PostgreSQL и повторите действие."
    if status_code == 502:
        return "MP VM не ответил на запрос. Проверьте подключение и повторите действие."
    if status_code == 409:
        return "Операция конфликтует с уже запущенной. Откройте центр операций для подробностей."
    if status_code == 404:
        return "Запрошенный объект не найден или уже был удалён."
    if status_code == 422:
        return "Проверьте заполненные поля и параметры запроса."
    return message or f"Ошибка компонента {component}."


@app.exception_handler(HTTPException)
def structured_http_error(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    message = str(detail.get("message") or detail.get("operator_message") or "Request failed")
    component = str(detail.get("component") or error_component(request.url.path))
    trace_id = getattr(request.state, "trace_id", None) or current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    payload = {
        "code": str(detail.get("code") or f"HTTP_{exc.status_code}"),
        "message": message,
        "operator_message": str(detail.get("operator_message") or operator_error_message(exc.status_code, component, message)),
        "component": component,
        "retryable": bool(detail.get("retryable", exc.status_code in {409, 429, 502, 503, 504})),
        "trace_id": trace_id,
        "request_id": request_id,
        "context": detail.get("context") or {key: value for key, value in detail.items() if key not in {"code", "message", "operator_message", "component", "retryable"}},
    }
    return JSONResponse(status_code=exc.status_code, content={"detail": payload}, headers=exc.headers)


@app.exception_handler(RequestValidationError)
def structured_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None) or current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=422,
        content={"detail": {
            "code": "VALIDATION_FAILED",
            "message": "Request validation failed.",
            "operator_message": "Проверьте заполненные поля и параметры запроса.",
            "component": error_component(request.url.path),
            "retryable": False,
            "trace_id": trace_id,
            "request_id": request_id,
            "context": {"fields": exc.errors()},
        }},
    )


def capture_vulnerability_snapshot(trigger_kind: str, trigger_id: str) -> dict[str, Any] | None:
    """Persist best-effort vulnerability history without failing the primary operation."""
    try:
        snapshot = CONTAINER.services.vulnerabilities.capture_snapshot(
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
        )
        log_event(
            "vulnerabilities",
            "snapshot.capture.completed",
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
            snapshot_id=(snapshot.get("snapshot") or {}).get("id")
            if isinstance(snapshot, dict)
            else None,
            created=snapshot.get("created") if isinstance(snapshot, dict) else None,
        )
        return snapshot
    except Exception:
        log_exception(
            "vulnerabilities",
            "snapshot.capture.failed",
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
        )
        return None


def ensure_vulnerability_snapshot_baseline() -> dict[str, Any] | None:
    try:
        return CONTAINER.services.vulnerabilities.ensure_baseline()
    except Exception:
        log_exception("vulnerabilities", "snapshot.baseline.failed")
        return None


def startup() -> None:
    global DATABASE_STARTUP_ERROR
    CONTAINER.start()
    log_event("app", "app.startup.started", process_id=os.getpid())
    try:
        db.init_db()
        app_auth.ensure_rbac_catalog()
        app_auth.ensure_bootstrap_admin(
            SETTINGS.bootstrap_admin_username,
            SETTINGS.bootstrap_admin_password,
            SETTINGS.bootstrap_admin_display_name,
        )
        CONTAINER.operation_runner.submit("maintenance", app_auth.cleanup_audit_events, 365)
        db.interrupt_active_vulnerability_passport_detail_jobs()
        db.interrupt_active_asset_card_build_jobs()
        db.release_scan_postprocess_leases()
        db.sync_operations_from_sources()
        ensure_vulnerability_snapshot_baseline()
        CONTAINER.services.remediation.reconcile_all()
        CONTAINER.services.remediation.ensure_daily_digest(
            webhook_enabled=bool(SETTINGS.automation_webhook_url)
        )
        DATABASE_STARTUP_ERROR = None
    except psycopg.Error as exc:
        DATABASE_STARTUP_ERROR = str(exc)
        log_exception("app", "app.startup.database_failed", database=db.database_label())
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    configure_session_from_env()
    if DATABASE_STARTUP_ERROR is None:
        start_asset_search_backfill()
        try:
            automation = get_automation_service()
            automation.resume_runs()
            automation.start_scheduler()
        except psycopg.Error:
            log_exception("app", "automation.startup.failed", database=db.database_label())
    resume_scan_postprocess_runs()
    scan_log(
        logging.INFO,
        "worker_limits",
        scan_postprocess_workers=SCAN_POSTPROCESS_WORKERS,
        scan_asset_process_workers=SCAN_ASSET_PROCESS_WORKERS,
        asset_card_request_workers=ASSET_CARD_REQUEST_WORKERS,
    )
    log_event(
        "app",
        "app.startup.completed",
        database_ready=DATABASE_STARTUP_ERROR is None,
        connected=SESSION.client is not None and SESSION.access_token is not None,
    )


@app.exception_handler(psycopg.Error)
def database_error_handler(request: Request, exc: psycopg.Error) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None) or current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=503,
        content={
            "detail": {
                "code": "DATABASE_UNAVAILABLE",
                "message": "Database is unavailable.",
                "operator_message": "Локальная база данных недоступна. Проверьте PostgreSQL и повторите действие.",
                "component": "database",
                "retryable": True,
                "trace_id": trace_id,
                "request_id": request_id,
                "context": {},
            }
        },
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@auth_router.get("/bootstrap-status")
def auth_bootstrap_status() -> dict[str, Any]:
    with db.connect() as conn:
        configured = int(conn.execute("SELECT COUNT(*) AS count FROM app_users").fetchone()["count"] or 0) > 0
    return {"configured": configured}


@auth_router.post("/login")
def auth_login(payload: app_auth.LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    return app_auth.login(
        payload,
        request,
        response,
        hours=SETTINGS.auth_session_hours,
        secure=SETTINGS.auth_cookie_secure,
    )


@auth_router.post("/logout")
def auth_logout(request: Request, response: Response) -> dict[str, Any]:
    return app_auth.logout(request, response)


@auth_router.post("/reauth")
def auth_reauth(payload: app_auth.ReauthRequest, request: Request) -> dict[str, Any]:
    try:
        result = app_auth.reauthenticate(request.cookies.get(app_auth.COOKIE_NAME), payload.password)
    except HTTPException:
        app_auth.audit_event(request=request, user=request.state.user, event_type="reauth", decision="deny")
        raise
    app_auth.audit_event(request=request, user=request.state.user, event_type="reauth", decision="allow")
    return result


@auth_router.get("/me")
def auth_me(request: Request) -> dict[str, Any]:
    return {"authenticated": True, "user": request.state.user}


@auth_router.get("/users")
def auth_users() -> dict[str, Any]:
    return {"rows": app_auth.list_users()}


@auth_router.post("/users", status_code=201)
def auth_create_user(payload: app_auth.UserCreateRequest) -> dict[str, Any]:
    return app_auth.create_user(payload)


@auth_router.patch("/users/{user_id}")
def auth_update_user(user_id: int, payload: app_auth.UserUpdateRequest, request: Request) -> dict[str, Any]:
    return app_auth.update_user(user_id, payload, actor_id=request.state.user["id"])


@auth_router.get("/permissions")
def auth_permissions() -> dict[str, Any]:
    return {"rows": app_auth.list_permissions()}


@auth_router.get("/roles")
def auth_roles() -> dict[str, Any]:
    return {"rows": app_auth.list_roles()}


@auth_router.post("/roles/clone", status_code=201)
def auth_clone_role(payload: app_auth.RoleCloneRequest) -> dict[str, Any]:
    return app_auth.clone_role(payload)


@auth_router.patch("/roles/{role_id}")
def auth_update_role(role_id: int, payload: app_auth.RoleUpdateRequest) -> dict[str, Any]:
    return app_auth.update_role(role_id, payload)


@auth_router.delete("/roles/{role_id}", status_code=204)
def auth_delete_role(role_id: int) -> Response:
    app_auth.delete_role(role_id)
    return Response(status_code=204)


@auth_router.get("/audit")
def auth_audit(limit: int = 200, offset: int = 0) -> dict[str, Any]:
    return app_auth.list_audit_events(limit=limit, offset=offset)


@system_router.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "app": "mpvm-rest-client",
        "database": db.database_label(),
        "database_ready": DATABASE_STARTUP_ERROR is None,
        "database_error": DATABASE_STARTUP_ERROR,
        "connected": SESSION.client is not None and SESSION.access_token is not None,
        "api_url": SESSION.api_url,
        "background_workers": {
            "scan_postprocess": SCAN_POSTPROCESS_WORKERS,
            "scan_asset_process": SCAN_ASSET_PROCESS_WORKERS,
            "asset_card_requests": ASSET_CARD_REQUEST_WORKERS,
        },
    }


@system_router.get("/api/system/status")
def system_status() -> dict[str, Any]:
    global DATABASE_STARTUP_ERROR
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    database_error = None
    circuit = db.database_circuit_status()
    if circuit["open"]:
        database_state = "down"
        database_error = circuit.get("reason") or "CircuitOpen"
        DATABASE_STARTUP_ERROR = circuit.get("message") or "Database connection circuit is open."
    else:
        try:
            with db.connect() as conn:
                conn.execute("SELECT 1")
            DATABASE_STARTUP_ERROR = None
            database_state = "ok"
            circuit = db.database_circuit_status()
        except psycopg.Error as exc:
            database_state = "down"
            database_error = type(exc).__name__
            DATABASE_STARTUP_ERROR = str(exc)
            circuit = db.database_circuit_status()
    connected = SESSION.client is not None and SESSION.access_token is not None
    mpvm_state = "ok" if connected else "degraded"
    workers_state = "ok" if database_state == "ok" else "down"
    components = {
        "application": {"state": "ok", "message": "Приложение работает.", "retryable": False},
        "database": {
            "state": database_state,
            "message": "PostgreSQL доступен." if database_state == "ok" else "PostgreSQL недоступен.",
            "reason": database_error,
            "retryable": database_state != "ok",
            "circuit_breaker": circuit,
        },
        "mpvm": {
            "state": mpvm_state,
            "message": "Сессия MP VM активна." if connected else "Нет активной сессии MP VM.",
            "retryable": not connected,
            "api_url": SESSION.api_url,
        },
        "background_workers": {
            "state": workers_state,
            "message": "Фоновые исполнители готовы." if workers_state == "ok" else "Фоновые операции ожидают восстановления PostgreSQL.",
            "retryable": workers_state != "ok",
            "limits": {
                "scan_postprocess": SCAN_POSTPROCESS_WORKERS,
                "scan_asset_process": SCAN_ASSET_PROCESS_WORKERS,
                "asset_card_requests": ASSET_CARD_REQUEST_WORKERS,
                "passport_details": PASSPORT_DETAIL_WORKERS,
            },
        },
    }
    overall = "ok" if database_state == "ok" and connected else "degraded"
    return {"state": overall, "checked_at": checked_at, "components": components}


@operations_router.get("/api/operations")
def operations(
    status: str | None = None,
    kind: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return CONTAINER.services.operations.list(status=status, kind=kind, q=q, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@operations_router.get("/api/operations/summary")
def operations_summary() -> dict[str, Any]:
    return CONTAINER.services.operations.summary()


@operations_router.get("/api/operations/{operation_id}")
def operation_detail(operation_id: str) -> dict[str, Any]:
    operation = CONTAINER.repositories.operations.get(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail={"code": "OPERATION_NOT_FOUND", "message": "Operation not found.", "component": "operations"})
    return operation


@operations_router.post("/api/operations/{operation_id}/cancel")
def cancel_operation(operation_id: str) -> dict[str, Any]:
    # The normalized registry is a read model. Refresh it before deciding whether
    # the source job is still cancellable and again after requesting cancellation.
    operation = db.get_operation(operation_id, sync_sources=True)
    if not operation:
        raise HTTPException(status_code=404, detail={"code": "OPERATION_NOT_FOUND", "message": "Operation not found.", "component": "operations"})
    if not operation["can_cancel"]:
        return operation
    if operation["kind"] == "asset_card_build":
        cancel_asset_card_build_job(operation["source_id"])
    elif operation["kind"] == "passport_detail_sync":
        cancel_vulnerability_passport_detail_job(operation["source_id"])
    elif operation["kind"] == "automation_run":
        AUTOMATION_REPOSITORY.request_cancel(operation["source_id"])
    return db.get_operation(operation_id, sync_sources=True) or operation


@operations_router.post("/api/operations/{operation_id}/retry", status_code=202)
def retry_operation(
    operation_id: str,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    clean_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_key)
    if replay:
        return {"operation": replay, "idempotent_replay": True}
    operation = db.get_operation(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail={"code": "OPERATION_NOT_FOUND", "message": "Operation not found.", "component": "operations"})
    if not operation["can_retry"]:
        raise HTTPException(
            status_code=409,
            detail={"code": "OPERATION_NOT_RETRYABLE", "message": "Operation cannot be retried safely.", "component": "operations"},
        )
    request_data = operation.get("request") if isinstance(operation.get("request"), dict) else {}
    if operation["kind"] == "asset_card_build":
        result = create_asset_card_build_job(AssetCardBuildJobRequest(**request_data), background_tasks)
        new_id = result["job"]["job_id"]
    elif operation["kind"] == "passport_detail_sync":
        if not request_data.get("pdql"):
            raise HTTPException(
                status_code=409,
                detail={"code": "RETRY_CONTEXT_MISSING", "message": "Original passport query is unavailable.", "component": "operations"},
            )
        result = query_vulnerability_passports(VulnerabilityPassportQueryRequest(**request_data), background_tasks)
        detail_job = result.get("detail_job") or {}
        new_id = detail_job.get("job_id")
        if not new_id:
            raise HTTPException(status_code=409, detail={"code": "RETRY_NOT_REQUIRED", "message": "No passport details require refresh.", "component": "operations"})
    elif operation["kind"] == "automation_run":
        source = AUTOMATION_REPOSITORY.get_run(operation["source_id"], include_steps=False)
        if not source:
            raise HTTPException(status_code=409, detail={"code": "RETRY_CONTEXT_MISSING", "message": "Original automation run is unavailable.", "component": "operations"})
        retried_run = get_automation_service().start_run(source["runbook_id"], trigger_type="retry", idempotency_key=clean_key)
        new_id = retried_run["run_id"]
    else:
        raise HTTPException(status_code=409, detail={"code": "OPERATION_NOT_RETRYABLE", "message": "Operation cannot be retried safely.", "component": "operations"})
    db.sync_operations_from_sources()
    retried = db.set_operation_retry(new_id, operation_id, clean_key) or db.get_operation(new_id)
    return {"operation": retried, "retry_of": operation_id}


@operations_router.get("/api/operations/{operation_id}/diagnostics")
def operation_diagnostics(operation_id: str) -> FileResponse:
    operation = db.get_operation(operation_id)
    if not operation:
        raise HTTPException(status_code=404, detail={"code": "OPERATION_NOT_FOUND", "message": "Operation not found.", "component": "operations"})
    path = build_diagnostic_archive(
        trace_id=operation.get("trace_id") or None,
        job_id=None if operation.get("trace_id") else operation.get("source_id"),
    )
    return FileResponse(path, media_type="application/zip", filename=path.name)


@operations_router.get("/api/saved-views")
def saved_views(route: str) -> dict[str, Any]:
    return {"rows": CONTAINER.repositories.operations.saved_views(route)}


@operations_router.post("/api/saved-views")
def upsert_saved_view(payload: SavedViewRequest) -> dict[str, Any]:
    return db.save_view(payload.route.strip(), payload.name.strip(), payload.filters)


@operations_router.delete("/api/saved-views/{view_id}")
def remove_saved_view(view_id: int) -> dict[str, Any]:
    if not db.delete_saved_view(view_id):
        raise HTTPException(status_code=404, detail={"code": "SAVED_VIEW_NOT_FOUND", "message": "Saved view not found.", "component": "application"})
    return {"id": view_id, "deleted": True}


@diagnostics_router.post("/api/diagnostics/frontend", status_code=202)
def record_frontend_diagnostics(payload: FrontendDiagnosticBatch) -> dict[str, Any]:
    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    for item in payload.events:
        item_trace_id = normalize_correlation_id(item.trace_id, fallback=False) or current_trace_id()
        item_request_id = normalize_correlation_id(item.request_id, fallback=False)
        with diagnostic_context(trace_id=item_trace_id, request_id=item_request_id):
            log_event(
                "frontend",
                item.event,
                level=levels[item.level],
                client_timestamp=item.timestamp,
                url=item.url,
                section=item.section,
                stack=item.stack,
                frontend_fields=redact(item.fields),
            )
    return {"accepted": len(payload.events), "trace_id": current_trace_id()}


@system_router.get("/api/defaults")
def defaults() -> dict[str, Any]:
    return {
        "api_url": os.getenv("MPVM_API_URL") or os.getenv("MP10_API_URL") or "https://srv-siem.local",
        "client_id": os.getenv("MPVM_CLIENT_ID") or os.getenv("MP10_CLIENT_ID") or "mpx",
        "scope": os.getenv("MPVM_SCOPE") or os.getenv("MP10_SCOPE") or "authorization offline_access mpx.api ptkb.api",
        "utc_offset": os.getenv("MPVM_UTC_OFFSET") or os.getenv("MP10_UTC_OFFSET") or "+05:00",
        "software_vuln_pdql": SOFTWARE_VULN_PDQL,
        "vulnerability_passport_pdql": VULNER_PASSPORT_PDQL,
        "asset_card_pdql": ASSET_CARD_PDQL,
        "sample_csv_exists": SAMPLE_CSV.exists(),
    }


@session_router.post("/api/session/connect")
def connect_session(payload: ConnectionRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    try:
        api_url = normalize_url(payload.api_url)
        token_url = normalize_url(payload.token_url) if payload.token_url else build_default_token_url(api_url)
        auth = AuthConfig(
            api_url=api_url,
            token_url=token_url,
            username=payload.username,
            password=payload.password,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            scope=payload.scope,
            access_token=payload.access_token,
            verify_tls=payload.verify_tls,
            timeout=payload.timeout,
        )
        client = MpVmClient(auth)
        access_token = client.ensure_access_token()
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    SESSION.client = client
    SESSION.access_token = access_token
    SESSION.api_url = api_url
    SESSION.token_url = token_url
    SESSION.username = payload.username
    SESSION.verify_tls = payload.verify_tls
    # Returning the authenticated session must not wait for stale scan recovery.
    # Recovery is queued after the HTTP response and uses its own bounded executor.
    background_tasks.add_task(resume_scan_postprocess_runs)
    return {
        "connected": True,
        "api_url": api_url,
        "token_url": token_url,
        "username": payload.username,
        "verify_tls": payload.verify_tls,
    }


@session_router.post("/api/session/disconnect")
def disconnect_session() -> dict[str, Any]:
    SESSION.client = None
    SESSION.access_token = None
    SESSION.api_url = None
    SESSION.token_url = None
    SESSION.username = None
    return {"connected": False}


@session_router.get("/api/session")
def session_info() -> dict[str, Any]:
    return {
        "connected": SESSION.client is not None and SESSION.access_token is not None,
        "api_url": SESSION.api_url,
        "token_url": SESSION.token_url,
        "username": SESSION.username,
        "verify_tls": SESSION.verify_tls,
    }


@session_router.get("/api/mpvm/lookups")
def mpvm_lookups() -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        return {
            "credentials": simplify_named_items(client.list_credentials(token)),
            "scopes": simplify_named_items(client.list_scopes(token)),
            "scanner_profiles": simplify_named_items(client.list_scanner_profiles(token)),
        }
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.get("/api/mpvm/scanner-tasks/remote")
def remote_scanner_tasks(offset: int = 0, limit: int = 50, main_filter: str | None = None) -> Any:
    client, token = require_mpvm()
    try:
        return client.list_remote_scanner_tasks(token, offset=offset, limit=limit, main_filter=main_filter)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.get("/api/scanner-tasks")
def local_scanner_tasks() -> list[dict[str, Any]]:
    return CONTAINER.services.tasks.list()


@tasks_router.post("/api/scanner-tasks")
def create_scanner_task(payload: ScannerTaskRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    task_payload = scanner_task_payload(payload)
    try:
        mp_task_id = client.create_scanner_task(token, task_payload)
        return db.record_scan_task(
            mp_task_id=mp_task_id,
            payload=task_payload,
            status="created",
            remote_response={"id": mp_task_id},
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.put("/api/scanner-tasks/{task_id}")
def update_scanner_task(task_id: str, payload: ScannerTaskRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    task_payload = scanner_task_payload(payload)
    try:
        response = client.update_scanner_task(token, task_id, task_payload)
        return db.record_scan_task(
            mp_task_id=task_id,
            payload=task_payload,
            status="updated",
            remote_response=response,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.post("/api/scanner-tasks/{task_id}/validate")
def validate_scanner_task(task_id: str) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        valid, error = client.validate_scanner_task(token, task_id)
        db.update_scan_task_status(task_id, "valid" if valid else "validation_failed", {"error": error})
        return {"id": task_id, "valid": valid, "error": error}
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.post("/api/scanner-tasks/{task_id}/start", status_code=202)
def start_scanner_task(
    task_id: str,
    background_tasks: BackgroundTasks,
    payload: StartScannerTaskRequest | None = None,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    clean_idempotency_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_idempotency_key)
    if replay and replay.get("kind") == "scan_postprocess":
        return {
            "status": "started",
            "postprocess_run_id": replay["source_id"],
            "postprocess": db.get_scan_postprocess_run(replay["source_id"], include_items=True),
            "operation": replay,
            "idempotent_replay": True,
        }
    client, token = require_mpvm()
    options = payload or StartScannerTaskRequest()
    try:
        result = start_scanner_task_impl(client=client, token=token, task_id=task_id, options=options)
        if result.get("status") != "started":
            return result
        postprocess_run_id = str(uuid.uuid4())
        postprocess = db.create_scan_postprocess_run(
            postprocess_run_id,
            mp_task_id=task_id,
            started_from=str(result["started_from"]),
            options=options.model_dump(),
            idempotency_key=clean_idempotency_key,
        )
        background_tasks.add_task(schedule_scan_postprocess, postprocess_run_id, client.auth, token)
        return {
            **result,
            "postprocess_run_id": postprocess_run_id,
            "postprocess": postprocess,
            "operation_id": postprocess_run_id,
        }
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.get("/api/scanner-tasks/{task_id}/postprocess-runs/latest")
def latest_scanner_task_postprocess_run(task_id: str) -> dict[str, Any]:
    run = db.get_latest_scan_postprocess_run(task_id, include_items=True)
    if not run:
        raise HTTPException(status_code=404, detail="Post-processing run not found.")
    return run


@tasks_router.post("/api/scanner-tasks/{task_id}/stop")
def stop_scanner_task(task_id: str) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        response = client.stop_scanner_task(token, task_id)
        db.update_scan_task_status(task_id, "stop_requested", response)
        return response
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.post("/api/scanner-tasks/{task_id}/delete")
def delete_scanner_task_post(
    task_id: str,
    payload: DeleteScannerTaskRequest | None = None,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    return delete_scanner_task_idempotent(task_id, payload or DeleteScannerTaskRequest(), idempotency_key)


@tasks_router.delete("/api/scanner-tasks/{task_id}")
def delete_scanner_task_delete(
    task_id: str,
    payload: DeleteScannerTaskRequest | None = None,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    return delete_scanner_task_idempotent(task_id, payload or DeleteScannerTaskRequest(), idempotency_key)


def delete_scanner_task_idempotent(
    task_id: str,
    payload: DeleteScannerTaskRequest,
    idempotency_key: str | None,
) -> dict[str, Any]:
    clean_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_key)
    if replay:
        if replay.get("kind") != "task_delete":
            raise HTTPException(status_code=409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT", "message": "Idempotency key belongs to another operation.", "component": "operations"})
        return {**(replay.get("result") or {}), "idempotent_replay": True, "operation_id": replay["operation_id"]}
    operation_id = str(uuid.uuid4())
    db.register_operation(
        operation_id,
        kind="task_delete",
        source_id=operation_id,
        status="running",
        stage="deleting_remote_task",
        progress_percent=10,
        subject_type="scanner_task",
        subject_id=task_id,
        subject_label=task_id,
        message="Deleting scanner task from MP VM.",
        request={"mode": payload.mode},
        idempotency_key=clean_key,
    )
    try:
        result = delete_scanner_task_impl(task_id, payload)
    except Exception as exc:
        db.register_operation(
            operation_id,
            kind="task_delete",
            source_id=operation_id,
            status="failed",
            stage="failed",
            progress_percent=100,
            subject_type="scanner_task",
            subject_id=task_id,
            subject_label=task_id,
            message="Scanner task deletion failed.",
            error={"message": str(exc)[:1000]},
            idempotency_key=clean_key,
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
        raise
    db.register_operation(
        operation_id,
        kind="task_delete",
        source_id=operation_id,
        status="completed",
        stage="completed",
        progress_percent=100,
        subject_type="scanner_task",
        subject_id=task_id,
        subject_label=task_id,
        message="Scanner task deleted from MP VM.",
        request={"mode": payload.mode},
        result=result,
        idempotency_key=clean_key,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    return {**result, "operation_id": operation_id}


@imports_router.post("/api/exports/pdql")
def export_pdql(payload: PdqlExportRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        pdql_token = client.create_pdql_token(
            token,
            payload.pdql,
            utc_offset=payload.utc_offset,
            selected_group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
        )
        csv_text = client.fetch_csv(token, pdql_token)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    filename = f"mpvm_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    output_path = EXPORTS_DIR / filename
    output_path.write_text(csv_text, encoding="utf-8-sig")

    import_result: dict[str, Any] | None = None
    run_id: int | None = None
    if payload.import_results:
        import_result = db.import_csv_text(
            csv_text,
            source="mpvm_pdql_export",
            pdql=payload.pdql,
            csv_filename=filename,
            delete_after_export=payload.delete_assets_after_export,
        )
        run_id = int(import_result["run_id"])

    removal_result: dict[str, Any] | None = None
    if payload.delete_assets_after_export:
        removal_result = remove_assets_after_export(
            client=client,
            token=token,
            csv_text=csv_text,
            import_run_id=run_id,
            utc_offset=payload.utc_offset,
            group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
            timeout_minutes=payload.delete_timeout_minutes,
            poll_seconds=payload.delete_poll_seconds,
        )

    return {
        "pdql_token": pdql_token,
        "csv_filename": filename,
        "csv_path": str(output_path),
        "csv_bytes": output_path.stat().st_size,
        "import": import_result,
        "removal": removal_result,
    }


@imports_router.post("/api/import/csv-text")
def import_csv_text(payload: CsvTextImportRequest) -> dict[str, Any]:
    return db.import_csv_text(
        payload.csv_text,
        source=payload.source,
        pdql=payload.pdql,
        csv_filename=payload.csv_filename,
    )


@imports_router.post("/api/import/csv-file")
async def import_csv_file(file: UploadFile = File(...)) -> dict[str, Any]:
    content = await file.read()
    text = decode_csv_bytes(content)
    return db.import_csv_text(text, source="uploaded_csv", csv_filename=file.filename)


@imports_router.post("/api/import/sample")
def import_sample() -> dict[str, Any]:
    if not SAMPLE_CSV.exists():
        raise HTTPException(status_code=404, detail=f"Sample CSV not found: {SAMPLE_CSV}")
    return db.import_csv_text(
        SAMPLE_CSV.read_text(encoding="utf-8-sig"),
        source="sample_csv",
        csv_filename=SAMPLE_CSV.name,
    )


@assets_router.get("/api/assets")
def assets(
    q: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return CONTAINER.services.assets.list_findings(q=q, severity=severity, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@assets_router.get("/api/assets/summary")
def assets_summary() -> dict[str, Any]:
    return CONTAINER.services.assets.summary()


@asset_cards_router.post("/api/asset-cards/query-assets")
def query_asset_card_assets(payload: AssetCardAssetQueryRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        pdql_token = client.create_pdql_token(
            token,
            payload.pdql,
            utc_offset=payload.utc_offset,
            selected_group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
        )
        records, raw_response = fetch_asset_grid_records(
            client=client,
            token=token,
            pdql_token=pdql_token,
            limit=payload.limit,
            batch_size=payload.batch_size,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    normalized = dedupe_asset_candidates([normalize_asset_candidate_record(record) for record in records])
    return {
        "pdql": payload.pdql,
        "pdql_token": pdql_token,
        "limit": payload.limit,
        "batch_size": payload.batch_size,
        "total": len(normalized),
        "records": normalized,
        "raw": raw_response,
    }


@asset_cards_router.post("/api/asset-cards/build")
def build_asset_card_endpoint(payload: AssetCardBuildRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    asset_id = payload.asset_id.strip()
    if not asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")

    try:
        card = build_asset_card(
            client=client,
            token=token,
            asset_id=asset_id,
            timeline_timestamp=payload.timeline_timestamp,
            limit_per_collection=payload.limit_per_collection,
            max_items_per_collection=payload.max_items_per_collection,
            max_depth=payload.max_depth,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    saved_card = db.upsert_asset_card(card) if payload.save_to_db else None
    if saved_card is not None:
        CONTAINER.services.remediation.reconcile_asset(asset_id)
        capture_vulnerability_snapshot(
            "asset_card_build",
            current_trace_id() or str(uuid.uuid4()),
        )
    return {
        "asset_id": asset_id,
        "card": sanitize_asset_card_for_response(card),
        "saved_card": saved_card,
        "saved": saved_card is not None,
    }


@asset_cards_router.post("/api/asset-cards/build-jobs", status_code=202)
def create_asset_card_build_job(
    payload: AssetCardBuildJobRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    clean_idempotency_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_idempotency_key)
    if replay and replay.get("kind") == "asset_card_build":
        replay_job = db.get_asset_card_build_job(replay["source_id"])
        return {"job": replay_job, "operation": replay, "idempotent_replay": True}
    asset_id = payload.asset_id.strip()
    if not asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    active_job = db.get_active_asset_card_build_job()
    if active_job:
        raise HTTPException(
            status_code=409,
            detail={"message": "An asset card build is already running.", "job": active_job},
        )
    client, token = require_mpvm()
    request = payload.model_dump()
    request["asset_id"] = asset_id
    job_id = str(uuid.uuid4())
    trace_id = current_trace_id() or new_trace_id()
    try:
        job = db.create_asset_card_build_job(
            job_id,
            trace_id=trace_id,
            asset_id=asset_id,
            operation="refresh" if db.asset_card_exists(asset_id) else "create",
            request=request,
            idempotency_key=clean_idempotency_key,
        )
    except psycopg.errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "An asset card build is already running.",
                "job": db.get_active_asset_card_build_job(),
            },
        ) from exc
    if job is None:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "An asset card build is already running.",
                "job": db.get_active_asset_card_build_job(),
            },
        )
    cancel_event = register_asset_card_build_job(job_id)
    background_tasks.add_task(
        run_asset_card_build_job,
        job_id=job_id,
        auth=client.auth,
        token=token,
        request=request,
        cancel_event=cancel_event,
        trace_id=trace_id,
    )
    log_event(
        "asset-card-build",
        "build.scheduled",
        trace_id=trace_id,
        job_id=job_id,
        asset_id=asset_id,
        operation=job.get("operation"),
    )
    return {"job": job, "operation_id": job_id}


@asset_cards_router.get("/api/asset-cards/build-jobs/active")
def active_asset_card_build_job() -> dict[str, Any]:
    return {"job": db.get_active_asset_card_build_job()}


@asset_cards_router.post("/api/asset-cards/{asset_id}/refresh-scan", status_code=202)
def refresh_asset_card_by_scan(
    asset_id: str,
    payload: AssetCardRefreshScanRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    """Create and start a one-IP scanner task, then refresh the local card through normal post-processing."""
    clean_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_key)
    if replay and replay.get("kind") == "scan_postprocess":
        run = db.get_scan_postprocess_run(replay["source_id"], include_items=True)
        return {
            "status": "started",
            "task_id": run.get("mp_task_id") if run else None,
            "postprocess_run_id": replay["source_id"],
            "postprocess": run,
            "operation": replay,
            "idempotent_replay": True,
        }

    card = db.get_asset_card(asset_id)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    ip_text = str(card.get("ip_address") or "").strip()
    try:
        target_ip = str(ipaddress.ip_address(ip_text))
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ASSET_CARD_IP_REQUIRED",
                "message": "The saved asset card does not contain one valid IP address for a refresh scan.",
            },
        ) from exc

    active = db.get_active_asset_card_refresh(asset_id)
    if active:
        raise HTTPException(
            status_code=409,
            detail={"code": "ASSET_CARD_REFRESH_ACTIVE", "message": "This asset card is already being refreshed.", "postprocess": active},
        )

    template = db.get_asset_card_refresh_template(asset_id, payload.template_task_id)
    if not template or not isinstance(template.get("payload"), dict):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SCANNER_TASK_TEMPLATE_REQUIRED",
                "message": "Create a regular scanner task first; its scope, profile, agents and credentials are used as the refresh template.",
            },
        )

    client, token = require_mpvm()
    task_payload = build_asset_refresh_task_payload(
        template["payload"],
        asset_id=asset_id,
        target_ip=target_ip,
        display_name=str(card.get("display_name") or card.get("hostname") or target_ip),
    )
    try:
        refresh_task_id = client.create_scanner_task(token, task_payload)
        db.record_scan_task(
            mp_task_id=refresh_task_id,
            payload=task_payload,
            status="asset_refresh_created",
            remote_response={"id": refresh_task_id, "template_task_id": template.get("mp_task_id"), "refresh_asset_id": asset_id},
        )
        start_result = start_scanner_task_impl(
            client=client,
            token=token,
            task_id=refresh_task_id,
            options=payload.start_options,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    if start_result.get("status") != "started":
        return {
            **start_result,
            "task_id": refresh_task_id,
            "template_task_id": template.get("mp_task_id"),
            "refresh_asset_id": asset_id,
            "target_ip": target_ip,
        }

    postprocess_run_id = str(uuid.uuid4())
    options = payload.start_options.model_dump()
    options.update(
        {
            "refresh_asset_id": asset_id,
            "refresh_asset_label": str(card.get("display_name") or card.get("hostname") or target_ip),
            "refresh_target_ip": target_ip,
            "refresh_template_task_id": template.get("mp_task_id"),
            "auto_created_refresh_task": True,
        }
    )
    postprocess = db.create_scan_postprocess_run(
        postprocess_run_id,
        mp_task_id=refresh_task_id,
        started_from=str(start_result["started_from"]),
        options=options,
        idempotency_key=clean_key,
    )
    background_tasks.add_task(schedule_scan_postprocess, postprocess_run_id, client.auth, token)
    scan_log(
        logging.INFO,
        "asset_refresh_scan_started",
        postprocess_run_id=postprocess_run_id,
        task_id=refresh_task_id,
        template_task_id=template.get("mp_task_id"),
        refresh_asset_id=asset_id,
        target=target_ip,
    )
    return {
        **start_result,
        "task_id": refresh_task_id,
        "template_task_id": template.get("mp_task_id"),
        "refresh_asset_id": asset_id,
        "target_ip": target_ip,
        "postprocess_run_id": postprocess_run_id,
        "postprocess": postprocess,
        "operation_id": postprocess_run_id,
    }


VULNERABILITY_REPORT_HEADERS = {
    "os": [
        "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "ОС", "Версия ОС",
        "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
    ],
    "software": [
        "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "Программное обеспечение",
        "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
    ],
}


def safe_csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def stream_vulnerability_report_csv(report_type: Literal["os", "software"], rows):
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(VULNERABILITY_REPORT_HEADERS[report_type])
    yield "\ufeff" + output.getvalue()
    for row in rows:
        output.seek(0)
        output.truncate(0)
        common = [
            row.get("asset_id"), row.get("ip_address"), row.get("fqdn"), row.get("hostname"),
        ]
        if report_type == "os":
            values = common + [row.get("os_name"), row.get("os_version")]
        else:
            values = common + [row.get("object_name")]
        values += [
            row.get("cve_name"), row.get("vulnerability_name"), row.get("severity"),
            row.get("cvss_score"), row.get("last_seen"),
        ]
        writer.writerow([safe_csv_cell(value) for value in values])
        yield output.getvalue()


@imports_router.post("/api/reports/vulnerabilities/{report_type}/csv")
def export_vulnerability_report(
    report_type: Literal["os", "software"],
    payload: VulnerabilityReportRequest,
) -> StreamingResponse:
    rows = db.iter_vulnerability_report_rows(report_type, payload.asset_ids)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"host_{'os' if report_type == 'os' else 'software'}_vulnerabilities_{timestamp}.csv"
    return StreamingResponse(
        stream_vulnerability_report_csv(report_type, rows),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@asset_cards_router.get("/api/asset-cards/build-jobs/{job_id}")
def asset_card_build_job(job_id: str) -> dict[str, Any]:
    job = db.get_asset_card_build_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Asset card build job not found.")
    return job


@asset_cards_router.post("/api/asset-cards/build-jobs/{job_id}/cancel")
def cancel_asset_card_build_job(job_id: str) -> dict[str, Any]:
    current = db.get_asset_card_build_job(job_id)
    if not current:
        raise HTTPException(status_code=404, detail="Asset card build job not found.")
    if current["status"] not in {"queued", "running", "cancelling"}:
        return current
    job = db.request_asset_card_build_job_cancel(job_id) or current
    CONTAINER.operation_runner.cancellations.cancel("asset-card", job_id)
    log_event(
        "asset-card-build",
        "build.cancel.requested",
        trace_id=job.get("trace_id"),
        job_id=job_id,
        asset_id=job.get("asset_id"),
        status=job.get("status"),
    )
    return job


def register_asset_card_build_job(job_id: str) -> threading.Event:
    return CONTAINER.operation_runner.cancellations.register("asset-card", job_id)


def unregister_asset_card_build_job(job_id: str) -> None:
    CONTAINER.operation_runner.cancellations.remove("asset-card", job_id)


def run_asset_card_build_job(
    *,
    job_id: str,
    auth: AuthConfig,
    token: str,
    request: dict[str, Any],
    cancel_event: threading.Event,
    trace_id: str | None = None,
) -> None:
    with diagnostic_context(
        trace_id=trace_id or new_trace_id(),
        job_id=job_id,
        asset_id=request.get("asset_id"),
        stage="starting",
    ):
        _run_asset_card_build_job(
            job_id=job_id,
            auth=auth,
            token=token,
            request=request,
            cancel_event=cancel_event,
        )


def _run_asset_card_build_job(
    *,
    job_id: str,
    auth: AuthConfig,
    token: str,
    request: dict[str, Any],
    cancel_event: threading.Event,
) -> None:
    executor: AssetCardRequestExecutor | None = None
    stage = "starting"
    progress_percent = ASSET_CARD_STAGE_PROGRESS[stage]
    progress_lock = threading.Lock()
    last_progress_write = 0.0
    build_started_at = time.perf_counter()
    stage_started_at = build_started_at

    def write_progress(discovered: int, completed: int, *, force: bool = False, card: dict[str, Any] | None = None) -> None:
        nonlocal last_progress_write
        with progress_lock:
            now = time.monotonic()
            if not force and completed < discovered and now - last_progress_write < 1.0:
                return
            last_progress_write = now
            card_stats = card.get("stats") if isinstance(card, dict) else {}
            vulnerability_stats = (
                card.get("vulnerabilities", {}).get("stats", {})
                if isinstance(card, dict) and isinstance(card.get("vulnerabilities"), dict)
                else {}
            )
            db.update_asset_card_build_job(
                job_id,
                stage=stage,
                progress_percent=progress_percent,
                discovered_requests=discovered,
                completed_requests=completed,
                node_count=int(card_stats.get("nodes") or 0),
                collection_count=int(card_stats.get("collections") or 0),
                finding_count=int(vulnerability_stats.get("findings") or 0),
                warning_count=len(card_stats.get("warnings") or []),
                stats=card_stats if isinstance(card_stats, dict) else {},
            )
            log_event(
                "asset-card-build",
                "build.progress",
                level=logging.DEBUG,
                stage=stage,
                progress_percent=progress_percent,
                discovered_requests=discovered,
                completed_requests=completed,
                node_count=int(card_stats.get("nodes") or 0),
                collection_count=int(card_stats.get("collections") or 0),
                finding_count=int(vulnerability_stats.get("findings") or 0),
            )

    def set_stage(value: str, *, card: dict[str, Any] | None = None) -> None:
        nonlocal stage, progress_percent, stage_started_at
        now = time.perf_counter()
        log_event(
            "asset-card-build",
            "build.stage.completed",
            stage=stage,
            next_stage=value,
            duration_ms=round((now - stage_started_at) * 1000, 2),
        )
        stage = value
        stage_started_at = now
        set_diagnostic_context(stage=value)
        progress_percent = max(progress_percent, ASSET_CARD_STAGE_PROGRESS.get(value, progress_percent))
        discovered = executor.discovered if executor else 0
        completed = executor.completed if executor else 0
        write_progress(discovered, completed, force=True, card=card)
        log_event(
            "asset-card-build",
            "build.stage.started",
            stage=value,
            progress_percent=progress_percent,
        )

    try:
        log_event(
            "asset-card-build",
            "build.started",
            request=redact(request),
            worker_limit=ASSET_CARD_REQUEST_WORKERS,
        )
        started = db.start_asset_card_build_job(job_id)
        if not started:
            current = db.get_asset_card_build_job(job_id)
            if current and current.get("cancel_requested"):
                cancel_event.set()
            else:
                return
        if cancel_event.is_set():
            db.finish_asset_card_build_job(
                job_id,
                status="cancelled",
                stage="cancelled",
                message="Cancelled before start.",
            )
            log_event("asset-card-build", "build.cancelled", reason="cancelled_before_start")
            return

        executor = AssetCardRequestExecutor(
            auth=auth,
            token=token,
            workers=ASSET_CARD_REQUEST_WORKERS,
            cancel_event=cancel_event,
            on_progress=lambda discovered, completed: write_progress(discovered, completed),
        )
        set_stage("collecting")
        card = build_asset_card(
            client=None,
            token=token,
            asset_id=str(request["asset_id"]),
            timeline_timestamp=request.get("timeline_timestamp"),
            limit_per_collection=int(request.get("limit_per_collection") or 5000),
            max_items_per_collection=int(request.get("max_items_per_collection") or 5000),
            max_depth=int(request.get("max_depth") or 8),
            request_executor=executor,
            stage_callback=set_stage,
        )
        if cancel_event.is_set():
            raise AssetCardBuildCancelled("Cancelled before saving.")
        set_stage("saving", card=card)
        saved = db.upsert_asset_card(card)
        if not saved:
            raise RuntimeError("Asset card could not be saved.")
        CONTAINER.services.remediation.reconcile_asset(str(request["asset_id"]))
        set_stage("completed", card=card)
        db.finish_asset_card_build_job(
            job_id,
            status="completed",
            stage="completed",
            message="Asset card build completed.",
            stats=card.get("stats") if isinstance(card.get("stats"), dict) else {},
        )
        if not request.get("parent_operation_id"):
            capture_vulnerability_snapshot("asset_card_build", job_id)
        log_event(
            "asset-card-build",
            "build.completed",
            duration_ms=round((time.perf_counter() - build_started_at) * 1000, 2),
            stats=card.get("stats"),
        )
    except AssetCardBuildCancelled as exc:
        db.finish_asset_card_build_job(
            job_id,
            status="cancelled",
            stage="cancelled",
            message=str(exc),
        )
        log_event(
            "asset-card-build",
            "build.cancelled",
            level=logging.WARNING,
            reason=str(exc),
            duration_ms=round((time.perf_counter() - build_started_at) * 1000, 2),
        )
    except Exception as exc:
        db.finish_asset_card_build_job(
            job_id,
            status="failed",
            stage="failed",
            message=f"Asset card build failed: {exc}"[:2000],
        )
        log_exception(
            "asset-card-build",
            "build.failed",
            duration_ms=round((time.perf_counter() - build_started_at) * 1000, 2),
        )
    finally:
        if executor:
            executor.close()
        unregister_asset_card_build_job(job_id)


@asset_cards_router.get("/api/asset-cards/local")
def local_asset_cards(
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return CONTAINER.services.asset_cards.list(q=q, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@asset_query_router.get("/api/asset-card-query/fields")
def asset_card_query_fields(q: str | None = None, limit: int = 100) -> dict[str, Any]:
    start_asset_search_backfill()
    return CONTAINER.services.asset_query.fields(q=q, limit=limit)


@asset_query_router.post("/api/asset-card-query")
def asset_card_query(payload: AssetCardFieldQueryRequest) -> dict[str, Any]:
    start_asset_search_backfill()
    try:
        return CONTAINER.services.asset_query.query(
            payload.query,
            sort_by=payload.sort_by,
            sort_dir=payload.sort_dir,
            limit=payload.limit,
            offset=payload.offset,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_ASSET_QUERY", "message": str(exc), "component": "asset_cards"},
        ) from exc


@asset_query_router.post("/api/asset-card-query/export")
def export_asset_card_query(payload: AssetCardFieldQueryRequest) -> Response:
    try:
        first_page = db.query_asset_cards_by_fields(
            payload.query,
            sort_by=payload.sort_by,
            sort_dir=payload.sort_dir,
            limit=5000,
            offset=0,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_ASSET_QUERY", "message": str(exc), "component": "asset_cards"},
        ) from exc
    def stream_rows():
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["asset_id", "display_name", "ip_address", "fqdn", "os_name", "last_seen", "entity_path", "field_path", "value"])
        yield "\ufeff" + output.getvalue()
        page = first_page
        offset = 0
        while True:
            for card in page["rows"]:
                matches = card.get("matches") or [{}]
                for match in matches:
                    output.seek(0)
                    output.truncate(0)
                    writer.writerow([
                        card.get("asset_id"), card.get("display_name"), card.get("ip_address"), card.get("fqdn"),
                        card.get("os_name"), card.get("last_seen"), match.get("entity_path"),
                        match.get("field_path"), match.get("value"),
                    ])
                    yield output.getvalue()
            offset += len(page["rows"])
            if not page["rows"] or offset >= page["total"]:
                break
            page = db.query_asset_cards_by_fields(
                payload.query,
                sort_by=payload.sort_by,
                sort_dir=payload.sort_dir,
                limit=5000,
                offset=offset,
            )
    filename = f"asset-query-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        stream_rows(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@asset_cards_router.get("/api/asset-cards/{asset_id}/summary")
def local_asset_card_summary(asset_id: str) -> dict[str, Any]:
    card = db.get_asset_card_summary(asset_id)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return card


@asset_cards_router.get("/api/asset-cards/{asset_id}/configuration/tree")
def local_asset_card_configuration_tree(
    asset_id: str,
    parent_path: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    tree = db.list_asset_card_configuration_tree(asset_id, parent_path=parent_path, limit=limit)
    if tree is None:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return tree


@asset_cards_router.get("/api/asset-cards/{asset_id}/configuration/detail")
def local_asset_card_configuration_detail(
    asset_id: str,
    path: str = "asset",
    kind: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    detail = db.get_asset_card_configuration_detail(asset_id, path=path, kind=kind, limit=limit, offset=offset)
    if detail is None:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return detail


@asset_cards_router.get("/api/asset-cards/{asset_id}/vulnerabilities/groups")
def local_asset_card_vulnerability_groups(asset_id: str) -> dict[str, Any]:
    groups = db.list_asset_card_vulnerability_groups(asset_id)
    if groups is None:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return groups


@asset_cards_router.get("/api/asset-cards/{asset_id}/vulnerabilities/findings")
def local_asset_card_vulnerability_findings(
    asset_id: str,
    source: str,
    collection_id: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    try:
        findings = db.list_asset_card_vulnerability_findings(
            asset_id,
            source=source,
            collection_id=collection_id,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_ASSET_CARD_FINDINGS_QUERY", "message": str(exc)}) from exc
    if findings is None:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return findings


@asset_cards_router.get("/api/asset-cards/{asset_id}")
def local_asset_card(
    asset_id: str,
    section: Literal["full", "summary", "configuration", "vulnerabilities"] = "full",
) -> dict[str, Any]:
    card = CONTAINER.services.asset_cards.get(asset_id, section=section)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return card


@asset_cards_router.put("/api/asset-cards/{asset_id}")
def update_local_asset_card(asset_id: str, payload: AssetCardUpdateRequest) -> dict[str, Any]:
    if not db.asset_card_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")

    client, token = require_mpvm()
    try:
        card = build_asset_card(
            client=client,
            token=token,
            asset_id=asset_id,
            timeline_timestamp=payload.timeline_timestamp,
            limit_per_collection=payload.limit_per_collection,
            max_items_per_collection=payload.max_items_per_collection,
            max_depth=payload.max_depth,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    saved_card = db.upsert_asset_card(card)
    if not saved_card:
        raise HTTPException(status_code=500, detail="Updated asset card could not be saved.")
    CONTAINER.services.remediation.reconcile_asset(asset_id)
    capture_vulnerability_snapshot(
        "asset_card_update",
        current_trace_id() or str(uuid.uuid4()),
    )
    return {
        "asset_id": asset_id,
        "card": sanitize_asset_card_for_response(card),
        "saved_card": saved_card,
        "updated": True,
    }


@asset_cards_router.delete("/api/asset-cards/{asset_id}")
def delete_local_asset_card(asset_id: str) -> dict[str, Any]:
    if not db.delete_asset_card(asset_id):
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    capture_vulnerability_snapshot(
        "asset_card_delete",
        current_trace_id() or str(uuid.uuid4()),
    )
    return {"asset_id": asset_id, "deleted": True}


@passports_router.post("/api/vulnerability-passports/query")
def query_vulnerability_passports(
    payload: VulnerabilityPassportQueryRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    if payload.save_to_db and payload.load_details:
        active_job = db.get_active_vulnerability_passport_detail_job()
        if active_job:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "A vulnerability passport detail sync is already running.",
                    "job": active_job,
                },
            )

    client, token = require_mpvm()
    query_started = time.perf_counter()
    try:
        pdql_token = client.create_pdql_token(
            token,
            payload.pdql,
            utc_offset=payload.utc_offset,
            selected_group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
        )
        records, raw_response = fetch_asset_grid_records(
            client=client,
            token=token,
            pdql_token=pdql_token,
            limit=payload.limit,
            batch_size=payload.batch_size,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
    grid_finished = time.perf_counter()

    normalized = dedupe_vulnerability_passports(
        [normalize_vulnerability_passport_record(record) for record in records]
    )
    db_result = (
        db.upsert_vulnerability_passports(normalized, source_pdql=payload.pdql, pdql_token=pdql_token)
        if payload.save_to_db
        else None
    )
    saved_finished = time.perf_counter()
    detail_job = None
    if payload.save_to_db and payload.load_details:
        internal_ids = [item.get("internal_id") for item in normalized]
        candidates = db.vulnerability_passport_detail_refresh_candidates(
            internal_ids,
            ttl_hours=PASSPORT_DETAIL_TTL_HOURS,
        )
        job_id = str(uuid.uuid4())
        try:
            detail_job = db.create_vulnerability_passport_detail_job(
                job_id,
                requested_count=len(candidates["requested"]),
                eligible_count=len(candidates["eligible"]),
                skipped_fresh_count=len(candidates["skipped_fresh"]),
                request=payload.model_dump(),
            )
        except psycopg.errors.UniqueViolation as exc:
            active_job = db.get_active_vulnerability_passport_detail_job()
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "A vulnerability passport detail sync is already running.",
                    "job": active_job,
                },
            ) from exc
        if candidates["eligible"]:
            cancel_event = register_vulnerability_passport_detail_job(job_id)
            background_tasks.add_task(
                run_vulnerability_passport_detail_job,
                job_id=job_id,
                auth=client.auth,
                token=token,
                internal_ids=candidates["eligible"],
                cancel_event=cancel_event,
                workers=PASSPORT_DETAIL_WORKERS,
                batch_size=PASSPORT_DETAIL_DB_BATCH_SIZE,
            )
        if db_result is not None:
            db_result["detail_job"] = detail_job
    if payload.save_to_db:
        records_response = db.list_vulnerability_passports(
            pdql_token=pdql_token,
            limit=50,
            offset=0,
        )["rows"]
    else:
        records_response = [vulnerability_passport_summary(item) for item in normalized[:50]]
    return {
        "pdql": payload.pdql,
        "pdql_token": pdql_token,
        "limit": payload.limit,
        "batch_size": payload.batch_size,
        "total": len(normalized),
        "records": records_response,
        "db": db_result,
        "detail_job": detail_job,
        "details": detail_job,
        "raw": raw_response,
        "timings_ms": {
            "grid_fetch": round((grid_finished - query_started) * 1000),
            "list_save": round((saved_finished - grid_finished) * 1000),
            "response_prepare": round((time.perf_counter() - saved_finished) * 1000),
        },
    }


@passports_router.get("/api/vulnerability-passports/local")
def local_vulnerability_passports(
    q: str | None = None,
    severity: str | None = None,
    pdql_token: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return CONTAINER.services.passports.list(
            q=q, severity=severity, pdql_token=pdql_token, limit=limit, offset=offset,
            sort_by=sort_by, sort_dir=sort_dir,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@passports_router.get("/api/vulnerability-passports/detail-jobs/active")
def active_vulnerability_passport_detail_job() -> dict[str, Any]:
    return {"job": db.get_active_vulnerability_passport_detail_job()}


@passports_router.get("/api/vulnerability-passports/detail-jobs/{job_id}")
def vulnerability_passport_detail_job(job_id: str) -> dict[str, Any]:
    job = db.get_vulnerability_passport_detail_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Vulnerability passport detail job not found.")
    return job


@passports_router.post("/api/vulnerability-passports/detail-jobs/{job_id}/cancel")
def cancel_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any]:
    current = db.get_vulnerability_passport_detail_job(job_id)
    if not current:
        raise HTTPException(status_code=404, detail="Vulnerability passport detail job not found.")
    if current["status"] not in {"queued", "running", "cancelling"}:
        return current
    job = db.request_vulnerability_passport_detail_job_cancel(job_id) or current
    CONTAINER.operation_runner.cancellations.cancel("passport-detail", job_id)
    return job


def register_vulnerability_passport_detail_job(job_id: str) -> threading.Event:
    return CONTAINER.operation_runner.cancellations.register("passport-detail", job_id)


def unregister_vulnerability_passport_detail_job(job_id: str) -> None:
    CONTAINER.operation_runner.cancellations.remove("passport-detail", job_id)


def run_vulnerability_passport_detail_job(
    *,
    job_id: str,
    auth: AuthConfig,
    token: str,
    internal_ids: list[str],
    cancel_event: threading.Event,
    workers: int = PASSPORT_DETAIL_WORKERS,
    batch_size: int = PASSPORT_DETAIL_DB_BATCH_SIZE,
) -> None:
    worker_state = threading.local()
    worker_clients: list[MpVmClient] = []
    worker_clients_lock = threading.Lock()

    def fetch_detail(internal_id: str) -> tuple[str, dict[str, Any]]:
        client = getattr(worker_state, "client", None)
        if client is None:
            client = MpVmClient(auth)
            worker_state.client = client
            with worker_clients_lock:
                worker_clients.append(client)
        with BACKGROUND_REQUEST_SEMAPHORE:
            return internal_id, client.get_vulnerability_passport(token, internal_id)

    def flush_batch(
        details: list[tuple[str, dict[str, Any]]],
        errors: list[dict[str, str]],
    ) -> None:
        if not details and not errors:
            return
        db.save_vulnerability_passport_detail_job_batch(job_id, details=details, errors=errors)
        details.clear()
        errors.clear()

    details_batch: list[tuple[str, dict[str, Any]]] = []
    errors_batch: list[dict[str, str]] = []
    futures: dict[Future[tuple[str, dict[str, Any]]], str] = {}
    internal_id_iterator = iter(internal_ids)

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        if cancel_event.is_set():
            return False
        try:
            internal_id = next(internal_id_iterator)
        except StopIteration:
            return False
        futures[executor.submit(fetch_detail, internal_id)] = internal_id
        return True

    try:
        started = db.start_vulnerability_passport_detail_job(job_id)
        if not started:
            current = db.get_vulnerability_passport_detail_job(job_id)
            if current and current.get("cancel_requested"):
                cancel_event.set()
            else:
                return
        if cancel_event.is_set():
            db.finish_vulnerability_passport_detail_job(job_id, status="cancelled", message="Cancelled before start.")
            return

        with ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="passport-detail") as executor:
            for _ in range(max(1, workers)):
                if not submit_next(executor):
                    break
            while futures:
                completed, _ = wait(tuple(futures), return_when=FIRST_COMPLETED)
                for future in completed:
                    internal_id = futures.pop(future)
                    try:
                        details_batch.append(future.result())
                    except Exception as exc:  # Keep one broken passport from stopping the job.
                        errors_batch.append({"internal_id": internal_id, "error": str(exc)[:1000]})
                    if len(details_batch) + len(errors_batch) >= max(1, batch_size):
                        flush_batch(details_batch, errors_batch)
                    submit_next(executor)

        flush_batch(details_batch, errors_batch)
        job = db.get_vulnerability_passport_detail_job(job_id) or {}
        if cancel_event.is_set():
            final_status = "cancelled"
            message = "Cancelled by operator."
        elif job.get("failed_count"):
            final_status = "completed_with_errors"
            message = "Detail sync finished with individual passport errors."
        else:
            final_status = "completed"
            message = "Detail sync completed."
        db.finish_vulnerability_passport_detail_job(job_id, status=final_status, message=message)
    except Exception as exc:
        db.finish_vulnerability_passport_detail_job(
            job_id,
            status="failed",
            message=f"Detail sync failed: {exc}"[:2000],
        )
    finally:
        for worker_client in worker_clients:
            session = getattr(worker_client, "session", None)
            if session is not None:
                session.close()
        unregister_vulnerability_passport_detail_job(job_id)


@passports_router.get("/api/vulnerability-passports/{passport_id}/asset-links")
def vulnerability_passport_asset_links(passport_id: str) -> dict[str, Any]:
    return {
        "passport_id": passport_id,
        "rows": db.list_asset_card_links_for_vulnerability_passport(passport_id),
    }


@passports_router.get("/api/vulnerability-passports/{passport_id}")
def vulnerability_passport(passport_id: str) -> dict[str, Any]:
    local = CONTAINER.services.passports.get(passport_id)
    if local and local.get("raw_detail"):
        return {"id": passport_id, "raw": local["raw_detail"], "source": "db", "passport": local}

    client, token = require_mpvm()
    try:
        raw_response = client.get_vulnerability_passport(token, passport_id)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
    saved = db.upsert_vulnerability_passport_detail(passport_id, raw_response)
    return {"id": passport_id, "raw": raw_response, "source": "mpvm", "passport": saved}


@passports_router.put("/api/vulnerability-passports/{passport_id}")
def update_vulnerability_passport(passport_id: str) -> dict[str, Any]:
    if not db.get_vulnerability_passport(passport_id):
        raise HTTPException(status_code=404, detail="Vulnerability passport not found in local DB.")

    client, token = require_mpvm()
    try:
        raw_response = client.get_vulnerability_passport(token, passport_id)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    saved = db.upsert_vulnerability_passport_detail(passport_id, raw_response)
    return {
        "id": passport_id,
        "raw": raw_response,
        "source": "mpvm",
        "passport": saved,
        "updated": True,
    }


@passports_router.delete("/api/vulnerability-passports/{passport_id}")
def delete_vulnerability_passport(passport_id: str) -> dict[str, Any]:
    if not db.delete_vulnerability_passport(passport_id):
        raise HTTPException(status_code=404, detail="Vulnerability passport not found in local DB.")
    return {"id": passport_id, "deleted": True}


@imports_router.get("/api/exports/{filename}")
def download_export(filename: str) -> FileResponse:
    path = EXPORTS_DIR / Path(filename).name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Export file not found")
    return FileResponse(path, media_type="text/csv", filename=path.name)


def configure_session_from_env() -> None:
    api_url = os.getenv("MPVM_API_URL") or os.getenv("MP10_API_URL")
    if not api_url:
        return
    try:
        normalized_api_url = normalize_url(api_url)
        token_url = normalize_url(os.getenv("MPVM_TOKEN_URL") or os.getenv("MP10_TOKEN_URL")) if (
            os.getenv("MPVM_TOKEN_URL") or os.getenv("MP10_TOKEN_URL")
        ) else build_default_token_url(normalized_api_url)
        verify_tls_env = os.getenv("MPVM_VERIFY_TLS") or os.getenv("MP10_VERIFY_TLS")
        if verify_tls_env is not None:
            verify_tls = verify_tls_env.lower() in {"1", "true", "yes", "on"}
        else:
            verify_tls = (os.getenv("MPVM_INSECURE") or os.getenv("MP10_INSECURE") or "").lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }

        auth = AuthConfig(
            api_url=normalized_api_url,
            token_url=token_url,
            username=os.getenv("MPVM_USERNAME") or os.getenv("MP10_USERNAME"),
            password=os.getenv("MPVM_PASSWORD") or os.getenv("MP10_PASSWORD"),
            client_id=os.getenv("MPVM_CLIENT_ID") or os.getenv("MP10_CLIENT_ID") or "mpx",
            client_secret=os.getenv("MPVM_CLIENT_SECRET") or os.getenv("MP10_CLIENT_SECRET"),
            scope=os.getenv("MPVM_SCOPE") or os.getenv("MP10_SCOPE") or "authorization offline_access mpx.api ptkb.api",
            access_token=os.getenv("MPVM_ACCESS_TOKEN") or os.getenv("MP10_ACCESS_TOKEN"),
            verify_tls=verify_tls,
            timeout=float(os.getenv("MPVM_TIMEOUT") or os.getenv("MP10_TIMEOUT") or "120"),
        )
        client = MpVmClient(auth)
        SESSION.client = client
        SESSION.access_token = client.ensure_access_token()
        SESSION.api_url = normalized_api_url
        SESSION.token_url = token_url
        SESSION.username = auth.username
        SESSION.verify_tls = auth.verify_tls
    except Exception:
        SESSION.client = None
        SESSION.access_token = None


def require_mpvm() -> tuple[MpVmClient, str]:
    if not SESSION.client or not SESSION.access_token:
        configure_session_from_env()
    if not SESSION.client or not SESSION.access_token:
        raise HTTPException(status_code=409, detail="MP VM connection is not configured. Connect first.")
    return SESSION.client, SESSION.access_token


def scanner_task_payload(payload: ScannerTaskRequest) -> dict[str, Any]:
    if payload.raw_payload:
        return payload.raw_payload
    include_targets = [item.strip() for item in payload.include_targets if item.strip()]
    if not include_targets:
        raise HTTPException(status_code=422, detail="include_targets is required")
    return build_scanner_task_payload(
        name=payload.name,
        description=payload.description,
        scope_id=payload.scope_id,
        profile_id=payload.profile_id,
        include_targets=include_targets,
        exclude_targets=[item.strip() for item in payload.exclude_targets if item.strip()],
        agent_ids=[item.strip() for item in payload.agent_ids if item.strip()],
        credential_id=payload.credential_id,
        host_discovery_enabled=payload.host_discovery_enabled or bool(payload.host_discovery_profile_id),
        host_discovery_profile_id=payload.host_discovery_profile_id,
        time_zone=payload.time_zone,
        is_fqdn_priority=payload.is_fqdn_priority,
    )


def build_asset_refresh_task_payload(
    template_payload: dict[str, Any],
    *,
    asset_id: str,
    target_ip: str,
    display_name: str,
) -> dict[str, Any]:
    task_payload = copy.deepcopy(template_payload)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    task_payload["name"] = f"Asset card refresh {display_name} {stamp}"[:250]
    task_payload["description"] = f"Automatic refresh scan for local asset card {asset_id}; target {target_ip}."
    include = task_payload.get("include") if isinstance(task_payload.get("include"), dict) else {}
    include.update({"assets": [], "targets": [target_ip], "assetsGroups": []})
    task_payload["include"] = include
    exclude = task_payload.get("exclude") if isinstance(task_payload.get("exclude"), dict) else {}
    exclude.update({"assets": [], "targets": [], "assetsGroups": []})
    task_payload["exclude"] = exclude
    trigger = task_payload.get("triggerParameters")
    if isinstance(trigger, dict):
        trigger["isEnabled"] = False
    return task_payload


def start_scanner_task_impl(
    *,
    client: MpVmClient,
    token: str,
    task_id: str,
    options: StartScannerTaskRequest,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": task_id,
        "precheck": None,
        "start": None,
        "finish": None,
    }
    if not options.skip_validation:
        valid, error = client.validate_scanner_task_with_retry(
            token,
            task_id,
            timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.task_poll_seconds, 5),
        )
        if not valid:
            db.update_scan_task_status(task_id, "validation_failed", {"error": error})
            return {**result, "status": "validation_failed", "error": error}

    if options.precheck_enabled:
        precheck_result = run_precheck_for_scanner_task(client=client, token=token, task_id=task_id, options=options)
        result["precheck"] = precheck_result
        successful_targets = precheck_result.get("successful_targets") or []
        if not successful_targets:
            db.update_scan_task_status(task_id, "precheck_failed", precheck_result)
            return {**result, "status": "precheck_failed"}

    started_from = datetime.now(timezone.utc).isoformat()
    start_response = client.start_scanner_task_with_retry(
        token,
        task_id,
        timeout_seconds=options.create_settle_seconds,
        poll_seconds=min(options.task_poll_seconds, 5),
    )
    result["start"] = start_response
    db.update_scan_task_status(task_id, "started", start_response)
    return {**result, "status": "started", "started_from": started_from}


def run_precheck_for_scanner_task(
    *,
    client: MpVmClient,
    token: str,
    task_id: str,
    options: StartScannerTaskRequest,
) -> dict[str, Any]:
    local_task = db.get_scan_task(task_id)
    if not local_task or not isinstance(local_task.get("payload"), dict):
        raise HTTPException(status_code=404, detail="Local scanner task payload not found. Create or update the task first.")

    audit_payload = copy.deepcopy(local_task["payload"])
    precheck_payload = copy.deepcopy(audit_payload)
    precheck_payload["name"] = build_precheck_task_name(options.precheck_task_prefix, str(audit_payload.get("name") or task_id))
    if options.precheck_profile_id:
        precheck_payload["profile"] = options.precheck_profile_id

    precheck_task_id = client.create_scanner_task(token, precheck_payload)
    db.record_scan_task(
        mp_task_id=precheck_task_id,
        payload=precheck_payload,
        status="precheck_created",
        remote_response={"audit_task_id": task_id},
    )

    if not options.skip_validation:
        valid, error = client.validate_scanner_task_with_retry(
            token,
            precheck_task_id,
            timeout_seconds=options.create_settle_seconds,
            poll_seconds=min(options.precheck_poll_seconds, 5),
        )
        if not valid:
            response = {"id": precheck_task_id, "valid": False, "error": error}
            db.update_scan_task_status(precheck_task_id, "precheck_validation_failed", response)
            return {"task_id": precheck_task_id, "successful_targets": [], "message": error, "valid": False}

    started_from = datetime.now(timezone.utc).isoformat()
    start_response = client.start_connection_check_with_retry(
        token,
        precheck_task_id,
        timeout_seconds=options.create_settle_seconds,
        poll_seconds=min(options.precheck_poll_seconds, 5),
    )
    db.update_scan_task_status(precheck_task_id, "precheck_started", start_response)

    targets, message = client.wait_for_connection_check_targets(
        token,
        precheck_task_id,
        time_from=started_from,
        timeout_seconds=options.precheck_timeout_minutes * 60,
        stop_after_seconds=options.precheck_max_runtime_minutes * 60,
        poll_seconds=options.precheck_poll_seconds,
        jobs_limit=options.precheck_jobs_limit,
    )
    status = "precheck_finished" if targets else "precheck_failed"
    precheck_result = {
        "task_id": precheck_task_id,
        "successful_targets": targets,
        "successful_target_count": len(targets),
        "message": message,
    }
    db.update_scan_task_status(precheck_task_id, status, precheck_result)

    if targets:
        include = audit_payload.get("include") if isinstance(audit_payload.get("include"), dict) else {}
        include["targets"] = targets
        audit_payload["include"] = include
        update_response = client.update_scanner_task(token, task_id, audit_payload)
        db.record_scan_task(
            mp_task_id=task_id,
            payload=audit_payload,
            status="precheck_updated_targets",
            remote_response={"precheck": precheck_result, "update": update_response},
        )

    return precheck_result


def build_precheck_task_name(prefix: str, audit_task_name: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix} {audit_task_name} {stamp}"


def schedule_scan_postprocess(run_id: str, auth: AuthConfig, token: str) -> None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        current = SCAN_POSTPROCESS_FUTURES.get(run_id)
        if current and not current.done():
            scan_log(logging.DEBUG, "schedule_skipped_already_running", postprocess_run_id=run_id)
            return
        future = CONTAINER.operation_runner.submit(
            "scan-postprocess",
            run_scan_postprocess,
            run_id=run_id,
            auth=auth,
            token=token,
        )
        SCAN_POSTPROCESS_FUTURES[run_id] = future
        scan_log(logging.INFO, "scheduled", postprocess_run_id=run_id, api_url=auth.api_url)

    def forget(_future: Future[Any]) -> None:
        with SCAN_POSTPROCESS_FUTURES_LOCK:
            if SCAN_POSTPROCESS_FUTURES.get(run_id) is _future:
                SCAN_POSTPROCESS_FUTURES.pop(run_id, None)

    future.add_done_callback(forget)


def resume_scan_postprocess_runs() -> None:
    if not SESSION.client or not SESSION.access_token:
        scan_log(logging.DEBUG, "resume_skipped_no_session")
        return
    try:
        cleanup_runs = db.list_pending_asset_refresh_task_cleanups()
        runs = db.list_resumable_scan_postprocess_runs()
    except psycopg.Error:
        SCAN_LOG.exception("[scan-postprocess] failed to list resumable runs")
        return
    scan_log(logging.INFO, "refresh_task_cleanup_resume", pending_count=len(cleanup_runs))
    for cleanup_run in cleanup_runs:
        cleanup_auto_created_refresh_task(
            client=SESSION.client,
            token=SESSION.access_token,
            run_id=str(cleanup_run["run_id"]),
            task_id=str(cleanup_run["mp_task_id"]),
        )
    scan_log(logging.INFO, "resume_scan", resumable_count=len(runs))
    for run in runs:
        schedule_scan_postprocess(str(run["run_id"]), SESSION.client.auth, SESSION.access_token)


def run_scan_postprocess(*, run_id: str, auth: AuthConfig, token: str) -> None:
    worker_id = str(uuid.uuid4())
    claimed = db.claim_scan_postprocess_run(run_id, worker_id)
    if not claimed:
        scan_log(logging.INFO, "claim_skipped", postprocess_run_id=run_id, worker_id=worker_id)
        return
    client = MpVmClient(auth)
    task_id = str(claimed["mp_task_id"])
    options = claimed.get("options") if isinstance(claimed.get("options"), dict) else {}
    started_from = str(claimed["started_from"])
    timeout_seconds = max(1.0, float(options.get("task_timeout_minutes") or 120) * 60)
    poll_seconds = max(1.0, float(options.get("task_poll_seconds") or 15))
    require_clean_jobs = bool(options.get("require_clean_jobs"))
    scan_log(
        logging.INFO,
        "run_started",
        postprocess_run_id=run_id,
        task_id=task_id,
        worker_id=worker_id,
        started_from=started_from,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        require_clean_jobs=require_clean_jobs,
    )
    try:
        monitoring = monitor_successful_scan_jobs(
            client=client,
            auth=auth,
            token=token,
            task_id=task_id,
            started_from=started_from,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
            postprocess_run_id=run_id,
            require_clean_jobs=require_clean_jobs,
        )
        if not monitoring["successful_job_count"]:
            scan_log(
                logging.ERROR,
                "no_successful_jobs",
                postprocess_run_id=run_id,
                task_id=task_id,
                total_job_count=monitoring["total_job_count"],
            )
            db.update_scan_task_status(task_id, "postprocess_failed", {"postprocess_run_id": run_id, "reason": "no successful targets"})
            cleanup_deleted = (
                cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
                if options.get("auto_created_refresh_task")
                else None
            )
            cleanup_text = " Refresh task deleted." if cleanup_deleted else " Refresh task deletion is pending." if cleanup_deleted is False else ""
            db.finish_scan_postprocess_run(
                run_id,
                status="failed",
                stage="failed",
                message=f"The scanner run has no jobs with errorStatus=success.{cleanup_text}",
            )
            return

        summary = db.refresh_scan_postprocess_counts(run_id) or {}
        failed_count = int(summary.get("failed_count") or 0)
        completed_count = int(summary.get("completed_count") or 0)
        refresh_result = finalize_asset_card_refresh(run_id, options) if completed_count else None
        final_status = "failed" if failed_count and not completed_count else "completed_with_errors" if failed_count else "completed"
        message = f"Completed {completed_count} asset(s); failures: {failed_count}."
        if refresh_result:
            message += f" Asset card refreshed as {refresh_result['asset_id']}."
        db.update_scan_task_status(
            task_id,
            "postprocess_failed" if final_status == "failed" else "postprocess_completed_with_errors" if failed_count else "postprocess_completed",
            {"postprocess_run_id": run_id, "completed_count": completed_count, "failed_count": failed_count},
        )
        if options.get("auto_created_refresh_task"):
            cleanup_deleted = cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
            if cleanup_deleted:
                message += " Refresh task deleted."
            else:
                message += " Refresh task deletion is pending."
                if final_status == "completed":
                    final_status = "completed_with_errors"
        db.finish_scan_postprocess_run(run_id, status=final_status, stage=final_status, message=message)
        if completed_count:
            capture_vulnerability_snapshot("scan_postprocess", run_id)
        scan_log(
            logging.INFO if final_status == "completed" else logging.ERROR,
            "run_finished",
            postprocess_run_id=run_id,
            task_id=task_id,
            status=final_status,
            completed_count=completed_count,
            failed_count=failed_count,
        )
    except Exception as exc:
        error = str(exc)[:4000]
        SCAN_LOG.exception(
            "[scan-postprocess] unhandled failure postprocess_run_id=%s task_id=%s error_type=%s error=%s",
            run_id,
            task_id,
            type(exc).__name__,
            error,
        )
        db.update_scan_task_status(task_id, "postprocess_failed", {"postprocess_run_id": run_id, "error": error})
        cleanup_deleted = (
            cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
            if options.get("auto_created_refresh_task")
            else None
        )
        cleanup_text = " Refresh task deleted." if cleanup_deleted else " Refresh task deletion is pending." if cleanup_deleted is False else ""
        db.finish_scan_postprocess_run(
            run_id,
            status="failed",
            stage="failed",
            message=f"Scan post-processing failed.{cleanup_text}",
            error=error,
        )
    finally:
        client.session.close()


def cleanup_auto_created_refresh_task(
    *,
    client: MpVmClient,
    token: str,
    run_id: str,
    task_id: str,
) -> bool:
    try:
        response = client.delete_scanner_task(token, task_id, mode="delete_v3")
        db.delete_scan_task(task_id)
        update_refresh_task_cleanup_message(run_id, f"Refresh task {task_id} deleted from MP VM.")
        scan_log(
            logging.INFO,
            "asset_refresh_task_deleted",
            postprocess_run_id=run_id,
            task_id=task_id,
            already_deleted=bool(response.get("alreadyDeleted")) if isinstance(response, dict) else False,
        )
        return True
    except (MpVmApiError, requests.RequestException, psycopg.Error) as exc:
        try:
            update_refresh_task_cleanup_message(run_id, f"Refresh task {task_id} deletion is pending: {exc}")
        except psycopg.Error:
            SCAN_LOG.exception(
                "[scan-postprocess] failed to persist refresh task cleanup error postprocess_run_id=%s task_id=%s",
                run_id,
                task_id,
            )
        SCAN_LOG.exception(
            "[scan-postprocess] refresh task cleanup failed postprocess_run_id=%s task_id=%s",
            run_id,
            task_id,
        )
        return False


def update_refresh_task_cleanup_message(run_id: str, cleanup_message: str) -> None:
    run = db.get_scan_postprocess_run(run_id)
    if not run:
        return
    base_message = str(run.get("message") or "").split(" Refresh task cleanup:", 1)[0].strip()
    prefix = f"{base_message} " if base_message else ""
    db.update_scan_postprocess_run(run_id, message=f"{prefix}Refresh task cleanup: {cleanup_message}"[:4000])


def finalize_asset_card_refresh(run_id: str, options: dict[str, Any]) -> dict[str, Any] | None:
    source_asset_id = str(options.get("refresh_asset_id") or "").strip()
    if not source_asset_id:
        return None
    completed_ids = sorted(
        {
            str(item.get("asset_id"))
            for item in db.list_scan_postprocess_items(run_id)
            if item.get("status") == "completed" and item.get("asset_id") and db.asset_card_exists(str(item["asset_id"]))
        }
    )
    if source_asset_id in completed_ids:
        refreshed_asset_id = source_asset_id
    elif len(completed_ids) == 1:
        refreshed_asset_id = completed_ids[0]
    else:
        scan_log(
            logging.WARNING,
            "asset_refresh_replacement_skipped",
            postprocess_run_id=run_id,
            refresh_asset_id=source_asset_id,
            completed_asset_ids=completed_ids,
            reason="no_completed_card" if not completed_ids else "ambiguous_completed_cards",
        )
        return None
    if refreshed_asset_id != source_asset_id:
        db.delete_asset_card(source_asset_id)
    scan_log(
        logging.INFO,
        "asset_refresh_replaced",
        postprocess_run_id=run_id,
        previous_asset_id=source_asset_id,
        asset_id=refreshed_asset_id,
    )
    return {"previous_asset_id": source_asset_id, "asset_id": refreshed_asset_id}


def monitor_successful_scan_jobs(
    *,
    client: MpVmClient,
    auth: AuthConfig,
    token: str,
    task_id: str,
    started_from: str,
    timeout_seconds: float,
    poll_seconds: float,
    postprocess_run_id: str,
    require_clean_jobs: bool,
) -> dict[str, int]:
    scan_deadline = time.monotonic() + timeout_seconds
    resolution_deadline: float | None = None
    latest_run: dict[str, Any] | None = None
    latest_jobs: list[dict[str, Any]] = []
    successful_jobs: list[dict[str, Any]] = []
    pending_targets: dict[str, str | None] = {}
    target_errors: dict[str, str] = {}
    existing_items = db.list_scan_postprocess_items(postprocess_run_id)
    seen_asset_ids = {str(item["asset_id"]) for item in existing_items if item.get("asset_id")}
    resolved_job_targets = {
        (str(item.get("mp_job_id") or ""), str(item.get("target") or ""))
        for item in existing_items
        if item.get("asset_id")
    }
    futures: list[Future[Any]] = []
    last_job_states: dict[str, str] = {}
    last_summary: tuple[int, int, int] | None = None
    logged_mp_run_id: str | None = None
    logged_waiting_for_run = False

    with ThreadPoolExecutor(
        max_workers=SCAN_ASSET_PROCESS_WORKERS,
        thread_name_prefix="scan-asset-process",
    ) as asset_executor:
        for item in existing_items:
            if item.get("asset_id") and item.get("status") not in {
                "completed",
                "resolution_failed",
                "build_failed",
                "removal_failed",
            }:
                futures.append(
                    asset_executor.submit(
                        process_scanned_asset_item_with_progress,
                        item=item,
                        auth=auth,
                        token=token,
                        postprocess_run_id=postprocess_run_id,
                    )
                )
                scan_log(
                    logging.INFO,
                    "item_resumed",
                    postprocess_run_id=postprocess_run_id,
                    item_id=item.get("id"),
                    job_id=item.get("mp_job_id"),
                    target=item.get("target"),
                    asset_id=item.get("asset_id"),
                    status=item.get("status"),
                )

        while True:
            runs = client.get_task_runs(token, task_id, time_from=started_from)
            if not runs and not logged_waiting_for_run:
                logged_waiting_for_run = True
                scan_log(
                    logging.INFO,
                    "waiting_for_mp_run",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    started_from=started_from,
                )
            if runs:
                latest_run = runs[0]
                mp_run_id = str(latest_run.get("id") or "")
                if mp_run_id:
                    if logged_mp_run_id != mp_run_id:
                        logged_mp_run_id = mp_run_id
                        scan_log(
                            logging.INFO,
                            "mp_run_found",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            run_status=latest_run.get("status"),
                            run_error_status=latest_run.get("errorStatus"),
                            run_started_at=latest_run.get("startedAt"),
                        )
                    latest_jobs, successful_jobs = client.split_successful_run_jobs(
                        token,
                        mp_run_id,
                        require_clean_jobs=require_clean_jobs,
                    )
                    successful_ids = {str(job.get("id") or "") for job in successful_jobs}
                    for job in latest_jobs:
                        job_id = str(job.get("id") or "")
                        profile = job.get("profile") if isinstance(job.get("profile"), dict) else {}
                        profile_name = profile.get("name") if isinstance(profile, dict) else None
                        state = json.dumps(
                            {
                                "status": job.get("status"),
                                "errorStatus": job.get("errorStatus"),
                                "runMode": job.get("runMode"),
                                "profile": profile_name,
                                "targets": job.get("targets"),
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                            default=str,
                        )
                        if last_job_states.get(job_id) == state:
                            continue
                        last_job_states[job_id] = state
                        run_mode = re.sub(r"[^a-z0-9]+", "", str(job.get("runMode") or "").casefold())
                        if "connectioncheck" in run_mode:
                            decision = "ignored_connection_check"
                        elif is_host_discovery_profile(job.get("profile")):
                            decision = "ignored_host_discovery_profile"
                        elif job_id in successful_ids:
                            decision = "ready_for_asset_processing"
                        elif job.get("errorStatus") is None:
                            decision = "waiting_error_status"
                        elif not has_success_status(job.get("errorStatus")):
                            decision = "ignored_non_success_error_status"
                        else:
                            decision = "ignored_require_clean_jobs"
                        scan_log(
                            logging.INFO,
                            "job_state_changed",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            job_id=job_id,
                            decision=decision,
                            status=job.get("status"),
                            error_status=job.get("errorStatus"),
                            run_mode=job.get("runMode"),
                            profile_name=profile_name,
                            targets=job.get("targets"),
                        )
                    summary_key = (len(latest_jobs), len(successful_jobs), len(seen_asset_ids))
                    if summary_key != last_summary:
                        last_summary = summary_key
                        scan_log(
                            logging.INFO,
                            "jobs_summary",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            total_job_count=len(latest_jobs),
                            successful_job_count=len(successful_jobs),
                            resolved_asset_count=len(seen_asset_ids),
                        )
                    for target, job_id in successful_scan_target_jobs(successful_jobs).items():
                        if (str(job_id or ""), target) not in resolved_job_targets:
                            pending_targets[target] = job_id

                    run_started_at = str(latest_run.get("startedAt") or started_from)
                    for target, job_id in list(pending_targets.items()):
                        try:
                            assets, error = resolve_scanned_target_once(
                                client=client,
                                token=token,
                                target=target,
                                mp_job_id=job_id,
                                run_started_at=run_started_at,
                            )
                        except (MpVmApiError, requests.RequestException, ValueError) as exc:
                            error = f"{type(exc).__name__}: {exc}"
                            target_errors[target] = error
                            SCAN_LOG.exception(
                                "[scan-postprocess] asset resolution request failed postprocess_run_id=%s task_id=%s mp_run_id=%s job_id=%s target=%s",
                                postprocess_run_id,
                                task_id,
                                mp_run_id,
                                job_id,
                                target,
                            )
                            continue
                        if not assets:
                            target_errors[target] = error
                            scan_log(
                                logging.WARNING,
                                "asset_not_resolved_yet",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=job_id,
                                target=target,
                                error=error,
                            )
                            continue
                        target_scheduled = False
                        for asset in assets:
                            asset_id = str(asset["asset_id"])
                            if asset_id in seen_asset_ids:
                                target_scheduled = True
                                continue
                            try:
                                item = db.upsert_scan_postprocess_item(
                                    postprocess_run_id,
                                    item_key=f"asset:{asset_id}",
                                    mp_job_id=asset.get("mp_job_id"),
                                    target=asset.get("target"),
                                    asset_id=asset_id,
                                    display_name=asset.get("display_name"),
                                    status="queued",
                                    stage="queued",
                                )
                            except Exception as exc:
                                error = f"{type(exc).__name__}: {exc}"
                                target_errors[target] = error
                                SCAN_LOG.exception(
                                    "[scan-postprocess] asset queue persistence failed "
                                    "postprocess_run_id=%s task_id=%s mp_run_id=%s job_id=%s target=%s asset_id=%s "
                                    "error_type=%s error=%s",
                                    postprocess_run_id,
                                    task_id,
                                    mp_run_id,
                                    job_id,
                                    target,
                                    asset_id,
                                    type(exc).__name__,
                                    str(exc),
                                )
                                continue
                            seen_asset_ids.add(asset_id)
                            target_scheduled = True
                            scan_log(
                                logging.INFO,
                                "asset_queued",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=job_id,
                                target=target,
                                asset_id=asset_id,
                                item_id=item.get("id"),
                            )
                            futures.append(
                                asset_executor.submit(
                                    process_scanned_asset_item_with_progress,
                                    item=item,
                                    auth=auth,
                                    token=token,
                                    postprocess_run_id=postprocess_run_id,
                                )
                            )
                        if not target_scheduled:
                            scan_log(
                                logging.WARNING,
                                "asset_queue_retry_pending",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=job_id,
                                target=target,
                                resolved_asset_ids=[str(asset.get("asset_id")) for asset in assets],
                                error=target_errors.get(target),
                            )
                            continue
                        resolved_job_targets.add((str(job_id or ""), target))
                        pending_targets.pop(target, None)
                        target_errors.pop(target, None)

                    terminal = is_finished(latest_run)
                    if terminal and resolution_deadline is None:
                        resolution_deadline = time.monotonic() + SCAN_ASSET_RESOLUTION_TIMEOUT_SECONDS
                    db.update_scan_postprocess_run(
                        postprocess_run_id,
                        mp_run_id=mp_run_id,
                        run_started_at=run_started_at,
                        status="processing" if seen_asset_ids else "monitoring",
                        stage="building_cards" if seen_asset_ids else "watching_jobs",
                        total_job_count=len(latest_jobs),
                        successful_job_count=len(successful_jobs),
                        target_count=len(successful_scan_target_jobs(successful_jobs)),
                        asset_count=len(seen_asset_ids),
                        message=(
                            f"Processing {len(seen_asset_ids)} asset(s); watching errorStatus for {len(latest_jobs)} job(s)."
                        ),
                    )

            now = time.monotonic()
            scan_timed_out = now >= scan_deadline
            resolution_finished = resolution_deadline is not None and (not pending_targets or now >= resolution_deadline)
            if resolution_finished or (scan_timed_out and latest_run is None):
                scan_log(
                    logging.INFO,
                    "monitoring_loop_finished",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    scan_timed_out=scan_timed_out,
                    pending_target_count=len(pending_targets),
                    scheduled_asset_count=len(seen_asset_ids),
                )
                break
            if scan_timed_out and latest_run is not None and resolution_deadline is None:
                client.stop_scanner_task_best_effort(token, task_id)
                scan_log(
                    logging.WARNING,
                    "scan_timeout_stop_requested",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    timeout_seconds=timeout_seconds,
                )
                resolution_deadline = now + SCAN_ASSET_RESOLUTION_TIMEOUT_SECONDS
            time.sleep(min(poll_seconds, SCAN_ASSET_RESOLUTION_POLL_SECONDS))

        for target, job_id in pending_targets.items():
            item = db.upsert_scan_postprocess_item(
                postprocess_run_id,
                item_key=f"target:{target}",
                mp_job_id=job_id,
                target=target,
                asset_id=None,
                display_name=None,
                status="resolution_failed",
                stage="resolution_failed",
            )
            db.update_scan_postprocess_item(
                int(item["id"]),
                status="resolution_failed",
                stage="resolution_failed",
                error=target_errors.get(target, "Asset resolution timed out."),
                finished_at=db.now_utc(),
            )
            scan_log(
                logging.ERROR,
                "asset_resolution_failed",
                postprocess_run_id=postprocess_run_id,
                task_id=task_id,
                job_id=job_id,
                target=target,
                error=target_errors.get(target, "Asset resolution timed out."),
            )
        for future in futures:
            future.result()

    if latest_run is None:
        raise RuntimeError(f"Scanner run was not found before timeout ({timeout_seconds / 60:.1f} minutes).")
    return {
        "total_job_count": len(latest_jobs),
        "successful_job_count": len(successful_jobs),
        "asset_count": len(seen_asset_ids),
    }


def resolve_scanned_target_once(
    *,
    client: MpVmClient,
    token: str,
    target: str,
    mp_job_id: str | None,
    run_started_at: str,
) -> tuple[list[dict[str, Any]], str]:
    records = query_scanned_asset_records(client, token, target)
    require_freshness = "/" in target
    assets = [
        normalize_scanned_asset_record(record, target=target, mp_job_id=mp_job_id)
        for record in records
        if not require_freshness or scanned_asset_record_is_current(record, run_started_at)
    ]
    assets = [asset for asset in assets if asset.get("asset_id")]
    scan_log(
        logging.INFO,
        "asset_resolution_result",
        job_id=mp_job_id,
        target=target,
        pdql_record_count=len(records),
        resolved_asset_count=len(assets),
        require_freshness=require_freshness,
        resolved_asset_ids=[asset.get("asset_id") for asset in assets],
    )
    if assets:
        return assets, ""
    if not records:
        return [], f"PDQL returned no assets for successful job target {target}."
    if require_freshness:
        return [], f"PDQL returned {len(records)} asset(s) for {target}, but none has CreationTime/UpdateTime from this run."
    return [], f"PDQL returned {len(records)} record(s) for {target}, but none contains asset_id."


def successful_scan_target_jobs(jobs: list[dict[str, Any]]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for job in jobs:
        job_id = str(job.get("id") or "") or None
        raw_targets = job.get("targets")
        targets = raw_targets if isinstance(raw_targets, list) else [raw_targets] if isinstance(raw_targets, str) else []
        for target in targets:
            value = str(target or "").strip()
            if value and value not in result:
                result[value] = job_id
    return result


def query_scanned_asset_records(client: MpVmClient, token: str, target: str) -> list[dict[str, Any]]:
    pdql_token = client.create_pdql_token(token, build_asset_resolution_pdql(target))
    records, _summary = fetch_asset_grid_records(
        client=client,
        token=token,
        pdql_token=pdql_token,
        limit=50000,
        batch_size=5000,
    )
    return records


def normalize_scanned_asset_record(record: dict[str, Any], *, target: str, mp_job_id: str | None) -> dict[str, Any]:
    candidate = normalize_asset_candidate_record(record)
    raw_display_name = candidate.get("display_name") or first_present(
        record.get("Fqdn"),
        record.get("Hostname"),
        target,
    )
    return {
        "asset_id": candidate.get("asset_id"),
        "display_name": asset_value_to_text(raw_display_name),
        "target": target,
        "mp_job_id": mp_job_id,
    }


def scanned_asset_record_matches(record: dict[str, Any], target: str) -> bool:
    ip_values = [
        record.get("IpAddress"),
        record.get("Host.IpAddress"),
        record.get("IP"),
    ]
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return any(_ip_in_network(value, network) for value in ip_values)
        address = ipaddress.ip_address(target)
        return any(_ip_equals(value, address) for value in ip_values)
    except ValueError:
        names = [record.get("Fqdn"), record.get("Host.Fqdn"), record.get("Hostname"), record.get("Host.Hostname")]
        return any(str(value or "").rstrip(".").casefold() == target.rstrip(".").casefold() for value in names)


def scanned_asset_record_is_current(record: dict[str, Any], run_started_at: str) -> bool:
    threshold = parse_mpvm_datetime(run_started_at)
    if threshold is None:
        return False
    values = [
        record.get("UpdateTime"),
        record.get("CreationTime"),
        record.get("Host.@UpdateTime"),
        record.get("Host.@CreationTime"),
    ]
    return any((parsed := parse_mpvm_datetime(value)) is not None and parsed >= threshold for value in values)


def parse_mpvm_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ip_equals(value: Any, address: ipaddress._BaseAddress) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()) == address
    except ValueError:
        return False


def _ip_in_network(value: Any, network: ipaddress._BaseNetwork) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()) in network
    except ValueError:
        return False


def process_scanned_asset_item(*, item: dict[str, Any], auth: AuthConfig, token: str) -> None:
    item_id = int(item["id"])
    asset_id = str(item["asset_id"])
    removal_operation_id = item.get("removal_operation_id")
    card_saved = bool(removal_operation_id)
    client = MpVmClient(auth)
    context = {
        "postprocess_run_id": item.get("postprocess_run_id"),
        "item_id": item_id,
        "job_id": item.get("mp_job_id"),
        "target": item.get("target"),
        "asset_id": asset_id,
    }
    scan_log(
        logging.INFO,
        "asset_processing_started",
        **context,
        resumed_removal_operation_id=removal_operation_id,
    )
    try:
        if not removal_operation_id:
            scan_log(logging.INFO, "asset_card_build_starting", **context)
            build_job_id = build_scanned_asset_card(
                item_id=item_id,
                asset_id=asset_id,
                auth=auth,
                token=token,
                parent_operation_id=str(item.get("postprocess_run_id") or ""),
            )
            item = db.update_scan_postprocess_item(
                item_id,
                status="card_saved",
                stage="card_saved",
                build_job_id=build_job_id,
                message="Asset card saved locally.",
                error=None,
            ) or item
            card_saved = True
            scan_log(logging.INFO, "asset_card_saved", **context, build_job_id=build_job_id)
            removal_operation_id = client.remove_assets(token, [asset_id])
            db.update_scan_postprocess_item(
                item_id,
                status="deleting",
                stage="deleting_in_mpvm",
                removal_operation_id=removal_operation_id,
                message="MP VM asset removal started.",
            )
            scan_log(
                logging.INFO,
                "mpvm_removal_started",
                **context,
                removal_operation_id=removal_operation_id,
            )
        else:
            scan_log(
                logging.INFO,
                "mpvm_removal_resumed",
                **context,
                removal_operation_id=removal_operation_id,
            )
        ok, message, _raw = client.wait_for_asset_removal(
            token,
            str(removal_operation_id),
            timeout_seconds=SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS,
            poll_seconds=SCAN_ASSET_REMOVAL_POLL_SECONDS,
        )
        if not ok:
            db.update_scan_postprocess_item(
                item_id,
                status="removal_failed",
                stage="removal_failed",
                message=message,
                error=message,
                finished_at=db.now_utc(),
            )
            scan_log(
                logging.ERROR,
                "mpvm_removal_failed",
                **context,
                removal_operation_id=removal_operation_id,
                message=message,
                raw_response=_raw,
            )
            return
        db.update_scan_postprocess_item(
            item_id,
            status="completed",
            stage="completed",
            message=message,
            error=None,
            finished_at=db.now_utc(),
        )
        scan_log(
            logging.INFO,
            "asset_processing_completed",
            **context,
            removal_operation_id=removal_operation_id,
            message=message,
        )
    except Exception as exc:
        status = "removal_failed" if card_saved else "build_failed"
        db.update_scan_postprocess_item(
            item_id,
            status=status,
            stage=status,
            error=str(exc)[:4000],
            finished_at=db.now_utc(),
        )
        SCAN_LOG.exception(
            "[scan-postprocess] asset processing failed status=%s context=%s",
            status,
            json.dumps(context, ensure_ascii=False, default=str),
        )
    finally:
        client.session.close()


def process_scanned_asset_item_with_progress(
    *,
    item: dict[str, Any],
    auth: AuthConfig,
    token: str,
    postprocess_run_id: str,
) -> None:
    process_scanned_asset_item(item=item, auth=auth, token=token)
    db.refresh_scan_postprocess_counts(postprocess_run_id)


def build_scanned_asset_card(
    *,
    item_id: int,
    asset_id: str,
    auth: AuthConfig,
    token: str,
    parent_operation_id: str,
) -> str:
    request = {
        "asset_id": asset_id,
        "timeline_timestamp": None,
        "limit_per_collection": 5000,
        "max_items_per_collection": 5000,
        "max_depth": 8,
        "parent_operation_id": parent_operation_id,
    }
    logged_active_job_id: str | None = None
    while True:
        active = db.get_active_asset_card_build_job()
        if active:
            active_job_id = str(active.get("job_id") or "")
            if logged_active_job_id != active_job_id:
                logged_active_job_id = active_job_id
                scan_log(
                    logging.INFO,
                    "asset_card_waiting_for_slot",
                    item_id=item_id,
                    asset_id=asset_id,
                    active_build_job_id=active_job_id,
                    active_asset_id=active.get("asset_id"),
                    active_status=active.get("status"),
                )
            time.sleep(2)
            continue
        build_job_id = str(uuid.uuid4())
        build_trace_id = new_trace_id()
        try:
            job = db.create_asset_card_build_job(
                build_job_id,
                trace_id=build_trace_id,
                asset_id=asset_id,
                operation="refresh" if db.asset_card_exists(asset_id) else "create",
                request=request,
            )
            if job is None:
                scan_log(
                    logging.INFO,
                    "asset_card_slot_busy_retry",
                    item_id=item_id,
                    asset_id=asset_id,
                )
                time.sleep(2)
                continue
            scan_log(
                logging.INFO,
                "asset_card_build_job_created",
                item_id=item_id,
                asset_id=asset_id,
                build_job_id=build_job_id,
            )
            break
        except psycopg.errors.UniqueViolation:
            scan_log(
                logging.INFO,
                "asset_card_slot_race_retry",
                item_id=item_id,
                asset_id=asset_id,
            )
            time.sleep(2)
    db.update_scan_postprocess_item(
        item_id,
        status="building",
        stage="building_card",
        build_job_id=build_job_id,
        started_at=db.now_utc(),
    )
    cancel_event = register_asset_card_build_job(build_job_id)
    run_asset_card_build_job(
        job_id=build_job_id,
        auth=auth,
        token=token,
        request=request,
        cancel_event=cancel_event,
        trace_id=build_trace_id,
    )
    job = db.get_asset_card_build_job(build_job_id)
    if not job or job.get("status") != "completed":
        scan_log(
            logging.ERROR,
            "asset_card_build_job_failed",
            item_id=item_id,
            asset_id=asset_id,
            build_job_id=build_job_id,
            build_status=(job or {}).get("status"),
            message=(job or {}).get("message"),
        )
        raise RuntimeError((job or {}).get("message") or "Asset card build did not complete.")
    if not db.asset_card_exists(asset_id):
        scan_log(
            logging.ERROR,
            "asset_card_missing_after_build",
            item_id=item_id,
            asset_id=asset_id,
            build_job_id=build_job_id,
        )
        raise RuntimeError("Asset card build completed without a saved local card.")
    scan_log(
        logging.INFO,
        "asset_card_build_job_completed",
        item_id=item_id,
        asset_id=asset_id,
        build_job_id=build_job_id,
    )
    return build_job_id


def delete_scanner_task_impl(task_id: str, payload: DeleteScannerTaskRequest) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        response = client.delete_scanner_task(
            token,
            task_id,
            mode=payload.mode,
            put_payload=payload.put_payload,
        )
        db.delete_scan_task(task_id)
        return response
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


def remove_assets_after_export(
    *,
    client: MpVmClient,
    token: str,
    csv_text: str,
    import_run_id: int | None,
    utc_offset: str | None,
    group_ids: list[str],
    include_nested_groups: bool,
    asset_ids: list[str],
    timeout_minutes: float,
    poll_seconds: float,
) -> dict[str, Any]:
    resolved_asset_ids = extract_asset_ids_from_csv(csv_text)
    resolution_source = "export_csv"
    if not resolved_asset_ids:
        resolved_asset_ids = list(asset_ids)
        resolution_source = "request_asset_ids"
    if not resolved_asset_ids:
        ips = extract_ips_from_csv(csv_text)
        resolved_asset_ids = resolve_asset_ids_by_ips(
            client=client,
            token=token,
            ips=ips,
            utc_offset=utc_offset,
            group_ids=group_ids,
            include_nested_groups=include_nested_groups,
        )
        resolution_source = "ip_resolution_pdql"

    if not resolved_asset_ids:
        db.record_asset_removal(
            import_run_id=import_run_id,
            operation_id=None,
            asset_ids=[],
            status="skipped",
            message="No asset IDs found in CSV or via IP resolution.",
        )
        return {"status": "skipped", "message": "No asset IDs found.", "asset_count": 0}

    operation_id = client.remove_assets(token, resolved_asset_ids)
    ok, message, raw_response = client.wait_for_asset_removal(
        token,
        operation_id,
        timeout_seconds=timeout_minutes * 60,
        poll_seconds=poll_seconds,
    )
    status = "completed" if ok else "failed"
    db.record_asset_removal(
        import_run_id=import_run_id,
        operation_id=operation_id,
        asset_ids=resolved_asset_ids,
        status=status,
        message=message,
        raw_response=raw_response,
    )
    return {
        "status": status,
        "operation_id": operation_id,
        "asset_count": len(resolved_asset_ids),
        "resolution_source": resolution_source,
        "message": message,
    }


def resolve_asset_ids_by_ips(
    *,
    client: MpVmClient,
    token: str,
    ips: list[str],
    utc_offset: str | None,
    group_ids: list[str],
    include_nested_groups: bool,
) -> list[str]:
    ids: list[str] = []
    for chunk in chunks(ips, 100):
        pdql = build_asset_id_pdql_for_ips(chunk)
        pdql_token = client.create_pdql_token(
            token,
            pdql,
            utc_offset=utc_offset,
            selected_group_ids=group_ids,
            include_nested_groups=include_nested_groups,
            asset_ids=[],
        )
        ids.extend(extract_asset_ids_from_csv(client.fetch_csv(token, pdql_token)))
    seen: set[str] = set()
    result: list[str] = []
    for item in ids:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def simplify_named_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        result.append(
            {
                "id": item.get("id") or item.get("uuid") or item.get("value"),
                "name": item.get("name") or item.get("displayName") or item.get("title") or item.get("id"),
                "raw": item,
            }
        )
    return result


def fetch_asset_grid_records(
    *,
    client: MpVmClient,
    token: str,
    pdql_token: str,
    limit: int | None,
    batch_size: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    batches: list[dict[str, Any]] = []
    first_response: dict[str, Any] | None = None
    expected_total: int | None = None
    offset = 0

    while limit is None or offset < limit:
        current_limit = batch_size if limit is None else min(batch_size, limit - offset)
        raw_response = client.fetch_asset_grid_data(
            token,
            pdql_token,
            limit=current_limit,
            offset=offset,
        )
        if first_response is None:
            first_response = raw_response
        batch_records = extract_asset_grid_records(raw_response)
        batch_total = extract_asset_grid_total(raw_response)
        if batch_total is not None:
            expected_total = batch_total
        records.extend(batch_records)
        batches.append(
            {
                "offset": offset,
                "limit": current_limit,
                "records": len(batch_records),
                "reported_total": batch_total,
            }
        )
        if len(batch_records) < current_limit:
            break
        offset += current_limit
        if expected_total is not None and len(records) >= expected_total:
            break

    summary: dict[str, Any] = {
        "pdqlToken": pdql_token,
        "requestedLimit": limit,
        "batchSize": batch_size,
        "recordCount": len(records),
        "reportedTotal": expected_total,
        "batches": batches,
    }
    if not records and first_response is not None:
        summary["firstResponse"] = first_response
    return records, summary


def extract_asset_grid_records(raw_response: Any) -> list[dict[str, Any]]:
    if isinstance(raw_response, list):
        return [item if isinstance(item, dict) else {"value": item} for item in raw_response]
    if not isinstance(raw_response, dict):
        return []

    for key in ("records", "items", "rows", "values"):
        value = raw_response.get(key)
        if isinstance(value, list):
            return [item if isinstance(item, dict) else {"value": item} for item in value]

    data = raw_response.get("data")
    if isinstance(data, list):
        return [item if isinstance(item, dict) else {"value": item} for item in data]
    if isinstance(data, dict):
        return extract_asset_grid_records(data)

    return []


def extract_asset_grid_total(raw_response: Any) -> int | None:
    if not isinstance(raw_response, dict):
        return None
    for key in ("totalCount", "total", "count"):
        value = raw_response.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    data = raw_response.get("data")
    if isinstance(data, dict):
        return extract_asset_grid_total(data)
    return None


def build_asset_card(
    *,
    client: MpVmClient | None,
    token: str,
    asset_id: str,
    timeline_timestamp: int | None,
    limit_per_collection: int,
    max_items_per_collection: int,
    max_depth: int,
    request_executor: AssetCardRequestExecutor | None = None,
    stage_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    build_started = time.perf_counter()
    timestamp = timeline_timestamp or int(datetime.now(timezone.utc).timestamp())
    log_event(
        "asset-card-build",
        "build.snapshot.started",
        asset_id=asset_id,
        timeline_timestamp=timestamp,
        limit_per_collection=limit_per_collection,
        max_items_per_collection=max_items_per_collection,
        max_depth=max_depth,
    )

    def remote_call(operation: Callable[[MpVmClient], Any], *, label: str = "request") -> Any:
        if request_executor:
            return request_executor.call(operation, label=label)
        if client is None:
            raise RuntimeError("A direct MP VM client is required for synchronous asset card builds.")
        return operation(client)

    api_url = request_executor.auth.api_url if request_executor else client.auth.api_url if client else ""

    if stage_callback:
        stage_callback("timeline")
    timeline_token = remote_call(
        lambda remote: remote.create_asset_timeline_token(token, asset_id, timestamp),
        label="timeline",
    )
    if stage_callback:
        stage_callback("root")
    root = remote_call(lambda remote: remote.get_asset_tree_root(token, timeline_token), label="tree_root")
    root_asset_id = str(first_present(root.get("objectId"), asset_id))

    metadata_cache: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    collections: list[dict[str, Any]] = []
    table_rows: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_collections: set[str] = set()
    node_cache: dict[str, dict[str, Any]] = {}
    stats: dict[str, Any] = {
        "metadata_requests": 0,
        "node_requests": 0,
        "collection_requests": 0,
        "vulnerability_header_requests": 0,
        "vulnerability_group_requests": 0,
        "vulnerability_collection_requests": 0,
        "nodes": 0,
        "collections": 0,
        "table_rows": 0,
        "warnings": [],
    }

    def warn(message: str) -> None:
        stats["warnings"].append(message)
        log_event("asset-card-build", "build.warning", level=logging.WARNING, warning=message)

    def metadata_for_types(asset_types: list[str]) -> None:
        ordered_types = list(dict.fromkeys(item for item in asset_types if item and item not in metadata_cache))
        owned: list[tuple[str, tuple[str, str], threading.Event]] = []
        waiting: list[tuple[str, tuple[str, str], threading.Event]] = []
        now = time.monotonic()
        with ASSET_METADATA_CACHE_LOCK:
            for asset_type in ordered_types:
                cache_key = (api_url, asset_type)
                cached = ASSET_METADATA_CACHE.get(cache_key)
                if ASSET_METADATA_TTL_SECONDS and cached and now - cached[0] <= ASSET_METADATA_TTL_SECONDS:
                    metadata_cache[asset_type] = cached[1]
                    continue
                event = ASSET_METADATA_INFLIGHT.get(cache_key)
                if event is None:
                    event = threading.Event()
                    ASSET_METADATA_INFLIGHT[cache_key] = event
                    owned.append((asset_type, cache_key, event))
                else:
                    waiting.append((asset_type, cache_key, event))

        operations = [
            (
                "metadata",
                lambda remote, asset_type=asset_type: remote.get_asset_metadata(token, asset_type),
            )
            for asset_type, _cache_key, _event in owned
        ]
        try:
            if request_executor and operations:
                settled = request_executor.map_labeled_settled(operations)
            else:
                settled = []
                for _label, operation in operations:
                    try:
                        if client is None:
                            raise RuntimeError("A direct MP VM client is required for metadata loading.")
                        settled.append((operation(client), None))
                    except Exception as exc:
                        settled.append((None, exc))
        except BaseException:
            with ASSET_METADATA_CACHE_LOCK:
                for _asset_type, cache_key, event in owned:
                    ASSET_METADATA_INFLIGHT.pop(cache_key, None)
                    event.set()
            raise

        for (asset_type, cache_key, event), (value, error) in zip(owned, settled):
            metadata = value if isinstance(value, dict) else {}
            if error is not None:
                warn(f"metadata {asset_type}: {error}")
            else:
                stats["metadata_requests"] += 1
            metadata_cache[asset_type] = metadata
            with ASSET_METADATA_CACHE_LOCK:
                if metadata and ASSET_METADATA_TTL_SECONDS:
                    ASSET_METADATA_CACHE[cache_key] = (time.monotonic(), metadata)
                    if len(ASSET_METADATA_CACHE) > 128:
                        oldest_key = min(ASSET_METADATA_CACHE, key=lambda key: ASSET_METADATA_CACHE[key][0])
                        ASSET_METADATA_CACHE.pop(oldest_key, None)
                ASSET_METADATA_INFLIGHT.pop(cache_key, None)
                event.set()

        for asset_type, cache_key, event in waiting:
            event.wait()
            with ASSET_METADATA_CACHE_LOCK:
                cached = ASSET_METADATA_CACHE.get(cache_key)
            metadata_cache[asset_type] = cached[1] if cached else {}

    def add_table_row(
        *,
        path: str,
        name: str,
        title: str | None,
        value: Any,
        value_type: str | None = None,
        kind: str | None = None,
        parent_type: str | None = None,
        parent_object_id: str | None = None,
    ) -> None:
        table_rows.append(
            {
                "path": path,
                "name": name,
                "title": title or name,
                "type": value_type,
                "kind": kind,
                "value": asset_value_to_text(value),
                "parent_type": parent_type,
                "parent_object_id": parent_object_id,
            }
        )

    def add_value_rows(
        *,
        path: str,
        name: str,
        title: str | None,
        value: Any,
        value_type: str | None = None,
        kind: str | None = None,
        parent_type: str | None = None,
        parent_object_id: str | None = None,
    ) -> None:
        add_table_row(
            path=path,
            name=name,
            title=title,
            value=value,
            value_type=value_type,
            kind=kind,
            parent_type=parent_type,
            parent_object_id=parent_object_id,
        )
        add_embedded_value_rows(
            value=value,
            path=path,
            name=name,
            title=title or name,
            parent_type=parent_type,
            parent_object_id=parent_object_id,
        )

    def add_embedded_value_rows(
        *,
        value: Any,
        path: str,
        name: str,
        title: str,
        parent_type: str | None,
        parent_object_id: str | None,
        depth: int = 1,
    ) -> None:
        if depth > 4 or value is None:
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                child_path = f"{path}[{index}]"
                child_name = f"{name}[{index}]"
                child_title = f"{title} {index + 1}"
                add_table_row(
                    path=child_path,
                    name=child_name,
                    title=child_title,
                    value=item,
                    kind="item",
                    parent_type=parent_type,
                    parent_object_id=parent_object_id,
                )
                add_embedded_value_rows(
                    value=item,
                    path=child_path,
                    name=child_name,
                    title=child_title,
                    parent_type=parent_type,
                    parent_object_id=parent_object_id,
                    depth=depth + 1,
                )
            return
        if not isinstance(value, dict) or "hasItems" in value:
            return

        nested = value.get("data") if isinstance(value.get("data"), dict) else value
        for key, item in nested.items():
            if is_hidden_asset_technical_field(key):
                continue
            child_path = f"{path}.{key}"
            child_name = f"{name}.{key}"
            child_title = labelize_asset_key(key)
            add_table_row(
                path=child_path,
                name=child_name,
                title=child_title,
                value=item,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
            )
            add_embedded_value_rows(
                value=item,
                path=child_path,
                name=child_name,
                title=child_title,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
                depth=depth + 1,
            )

    def add_embedded_data_rows(item: dict[str, Any], path: str, parent_type: str, parent_object_id: str) -> None:
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        for key, embedded_value in data.items():
            if is_hidden_asset_technical_field(key):
                continue
            add_value_rows(
                path=f"{path}.{key}",
                name=key,
                title=labelize_asset_key(key),
                value=embedded_value,
                value_type=None,
                kind=None,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
            )

    def run_operations(
        operations: list[tuple[str, Callable[[MpVmClient], Any]]],
    ) -> list[tuple[Any | None, Exception | None]]:
        if request_executor:
            return request_executor.map_labeled_settled(operations)
        settled: list[tuple[Any | None, Exception | None]] = []
        for _label, operation in operations:
            try:
                if client is None:
                    raise RuntimeError("A direct MP VM client is required for asset tree loading.")
                settled.append((operation(client), None))
            except Exception as exc:
                settled.append((None, exc))
        return settled

    def fetch_node_specs(specs: list[dict[str, Any]]) -> None:
        unique: list[dict[str, Any]] = []
        scheduled: set[str] = set()
        for spec in specs:
            key = f"{spec['type']}|{spec['id']}"
            if key in node_cache or key in scheduled:
                continue
            scheduled.add(key)
            unique.append(spec)
        operations = [
            (
                "tree_node",
                lambda remote, spec=spec: remote.get_asset_tree_node(
                    token, spec["type"], spec["id"], timeline_token
                ),
            )
            for spec in unique
        ]
        for spec, (value, error) in zip(unique, run_operations(operations)):
            key = f"{spec['type']}|{spec['id']}"
            if error is not None:
                warn(f"node {spec['path']} ({spec['type']}/{spec['id']}): {error}")
                continue
            if isinstance(value, dict):
                node_cache[key] = value
                stats["node_requests"] += 1

    def fetch_collection_specs(specs: list[dict[str, Any]]) -> None:
        if not specs:
            return
        page_size = max(1, min(limit_per_collection, max_items_per_collection))
        first_operations = [
            (
                "tree_collection",
                lambda remote, spec=spec: remote.get_asset_tree_collection(
                    token,
                    spec["parent_type"],
                    spec["object_id"],
                    spec["name"],
                    timeline_token,
                    full=True,
                    limit=page_size,
                    offset=0,
                ),
            )
            for spec in specs
        ]
        for spec, (response, error) in zip(specs, run_operations(first_operations)):
            spec["pages"] = {}
            spec["reported_count"] = None
            spec["next_offset"] = 0
            spec["done"] = True
            if error is not None:
                warn(
                    f"collection {spec['path']} ({spec['parent_type']}/{spec['object_id']}/{spec['name']}): {error}"
                )
                continue
            stats["collection_requests"] += 1
            batch = extract_collection_items(response)
            spec["pages"][0] = batch
            spec["reported_count"] = extract_collection_count(response)
            spec["next_offset"] = len(batch)
            spec["done"] = not batch or len(batch) < page_size

        while True:
            page_specs: list[tuple[dict[str, Any], int, int]] = []
            for spec in specs:
                if spec.get("done"):
                    continue
                offset = int(spec["next_offset"])
                reported_count = spec.get("reported_count")
                target = min(max_items_per_collection, reported_count) if reported_count is not None else max_items_per_collection
                if offset >= target:
                    spec["done"] = True
                    continue
                if reported_count is not None:
                    while offset < target:
                        current_limit = min(limit_per_collection, target - offset)
                        page_specs.append((spec, offset, current_limit))
                        offset += current_limit
                    spec["done"] = True
                else:
                    current_limit = min(limit_per_collection, target - offset)
                    page_specs.append((spec, offset, current_limit))
            if not page_specs:
                break
            operations = [
                (
                    "tree_collection",
                    lambda remote, spec=spec, offset=offset, current_limit=current_limit:
                        remote.get_asset_tree_collection(
                            token,
                            spec["parent_type"],
                            spec["object_id"],
                            spec["name"],
                            timeline_token,
                            full=True,
                            limit=current_limit,
                            offset=offset,
                        ),
                )
                for spec, offset, current_limit in page_specs
            ]
            for (spec, offset, current_limit), (response, error) in zip(page_specs, run_operations(operations)):
                if error is not None:
                    warn(f"collection {spec['path']} offset {offset}: {error}")
                    spec["done"] = True
                    continue
                stats["collection_requests"] += 1
                batch = extract_collection_items(response)
                spec["pages"][offset] = batch
                count = extract_collection_count(response)
                if count is not None:
                    spec["reported_count"] = count
                spec["next_offset"] = offset + len(batch)
                if not batch or len(batch) < current_limit:
                    spec["done"] = True

        for spec in specs:
            spec["items"] = [
                item
                for offset in sorted(spec.get("pages", {}))
                for item in spec["pages"][offset]
            ][:max_items_per_collection]
            reported_count = spec.get("reported_count")
            spec["truncated"] = (
                len(spec["items"]) < reported_count
                if reported_count is not None
                else len(spec["items"]) >= max_items_per_collection
            )
            if spec["truncated"]:
                warn(
                    f"collection {spec['path']}: fetched {len(spec['items'])} item(s), "
                    f"reported count {reported_count or 'unknown'}"
                )

    def traverse_tree() -> None:
        pending_nodes: list[dict[str, Any]] = [
            {"node": root, "path": "asset", "depth": 0, "title": root.get("displayName")}
        ]
        while pending_nodes:
            current_nodes: list[dict[str, Any]] = []
            for entry in sorted(pending_nodes, key=lambda item: item["path"]):
                node = entry["node"]
                node_type = clean_text(first_present(node.get("type"), ""))
                object_id = clean_text(first_present(node.get("objectId"), ""))
                key = f"{node_type}|{object_id}"
                if object_id and key in seen_nodes:
                    continue
                if object_id:
                    seen_nodes.add(key)
                    node_cache[key] = node
                entry["type"] = node_type
                entry["id"] = object_id
                current_nodes.append(entry)
                if entry["path"] != "asset":
                    nodes.append(
                        {
                            "path": entry["path"],
                            "title": entry.get("title") or node.get("displayName") or entry["path"],
                            "display_name": node.get("displayName"),
                            "object_id": object_id,
                            "type": node_type,
                            "vulnerability_level": node.get("vulnerabilityLevel"),
                            "data": node.get("data") if isinstance(node.get("data"), dict) else {},
                        }
                    )
                    stats["nodes"] += 1
            if not current_nodes:
                break

            metadata_for_types([entry["type"] for entry in current_nodes])
            collection_specs: list[dict[str, Any]] = []
            direct_refs: list[dict[str, Any]] = []
            for entry in current_nodes:
                node = entry["node"]
                node_type = entry["type"]
                object_id = entry["id"]
                depth = int(entry["depth"])
                path = entry["path"]
                metadata = metadata_cache.get(node_type) or {}
                properties = metadata_properties_by_name(metadata)
                data = node.get("data") if isinstance(node.get("data"), dict) else {}
                for name, value in data.items():
                    prop = metadata_property_for_name(properties, name)
                    title = clean_text(first_present(prop.get("title"), name))
                    value_type = clean_text(
                        first_present(prop.get("type"), value.get("type") if isinstance(value, dict) else None)
                    )
                    kind = clean_text(prop.get("kind"))
                    current_path = f"{path}.{name}"
                    if should_fetch_collection(prop, value):
                        add_table_row(
                            path=current_path, name=name, title=title, value=value,
                            value_type=value_type, kind=kind or "collection",
                            parent_type=node_type, parent_object_id=object_id,
                        )
                        if depth >= max_depth:
                            warn(f"max depth reached before collection {current_path}")
                        else:
                            collection_specs.append(
                                {
                                    "parent_type": node_type,
                                    "object_id": object_id or root_asset_id,
                                    "name": metadata_collection_name(prop, name),
                                    "prop": prop,
                                    "path": current_path,
                                    "depth": depth + 1,
                                }
                            )
                        continue
                    if is_object_ref(value):
                        add_table_row(
                            path=current_path, name=name, title=title, value=value,
                            value_type=value_type, kind=kind or "node",
                            parent_type=node_type, parent_object_id=object_id,
                        )
                        if depth >= max_depth:
                            warn(f"max depth reached before node {current_path}")
                        else:
                            child_type = clean_text(value.get("type"))
                            child_id = clean_text(value.get("objectId"))
                            if child_type and child_id:
                                direct_refs.append(
                                    {"type": child_type, "id": child_id, "path": current_path,
                                     "depth": depth + 1, "title": title}
                                )
                        continue
                    add_value_rows(
                        path=current_path, name=name, title=title, value=value,
                        value_type=value_type, kind=kind,
                        parent_type=node_type, parent_object_id=object_id,
                    )

                for prop in metadata_collection_properties(metadata):
                    name = metadata_collection_name(prop)
                    if not name or metadata_data_has_property(data, name):
                        continue
                    current_path = f"{path}.{name}"
                    if depth >= max_depth:
                        warn(f"max depth reached before collection {current_path}")
                    else:
                        collection_specs.append(
                            {"parent_type": node_type, "object_id": object_id or root_asset_id,
                             "name": name, "prop": prop, "path": current_path, "depth": depth + 1}
                        )

            unique_collections: list[dict[str, Any]] = []
            for spec in sorted(collection_specs, key=lambda item: item["path"]):
                key = f"{spec['parent_type']}|{spec['object_id']}|{spec['name']}"
                if not spec["parent_type"] or not spec["object_id"]:
                    warn(f"collection {spec['path']}: parent type or object id is empty")
                elif key not in seen_collections:
                    seen_collections.add(key)
                    unique_collections.append(spec)

            fetch_collection_specs(unique_collections)
            child_refs = list(direct_refs)
            for spec in unique_collections:
                items = spec.get("items") or []
                prop = spec["prop"]
                collection_doc: dict[str, Any] = {
                    "path": spec["path"], "name": spec["name"],
                    "title": clean_text(first_present(prop.get("title"), spec["name"])),
                    "type": prop.get("type"), "kind": prop.get("kind"),
                    "parent_type": spec["parent_type"], "parent_object_id": spec["object_id"],
                    "count": spec.get("reported_count") if spec.get("reported_count") is not None else len(items),
                    "fetched_count": len(items), "truncated": bool(spec.get("truncated")), "items": [],
                }
                collections.append(collection_doc)
                stats["collections"] += 1
                for index, item in enumerate(items):
                    item_path = f"{spec['path']}[{index}]"
                    if not isinstance(item, dict):
                        collection_doc["items"].append({"path": item_path, "value": item})
                        add_table_row(
                            path=item_path, name=spec["name"], title=collection_doc["title"], value=item,
                            value_type=prop.get("type"), kind=prop.get("kind"),
                            parent_type=spec["parent_type"], parent_object_id=spec["object_id"],
                        )
                        continue
                    item_doc = {
                        "path": item_path, "display_name": item.get("displayName"),
                        "object_id": item.get("objectId"), "type": item.get("type"),
                        "vulnerability_level": item.get("vulnerabilityLevel"),
                        "data": item.get("data") if isinstance(item.get("data"), dict) else {},
                    }
                    collection_doc["items"].append(item_doc)
                    add_table_row(
                        path=item_path, name=spec["name"], title=collection_doc["title"], value=item,
                        value_type=item.get("type") or prop.get("type"), kind=prop.get("kind"),
                        parent_type=spec["parent_type"], parent_object_id=spec["object_id"],
                    )
                    if int(spec["depth"]) <= max_depth and is_object_ref(item):
                        child_type = clean_text(item.get("type"))
                        child_id = clean_text(item.get("objectId"))
                        if child_type and child_id:
                            child_refs.append(
                                {"type": child_type, "id": child_id, "path": item_path,
                                 "depth": spec["depth"], "title": item_doc.get("display_name"),
                                 "item": item, "item_doc": item_doc,
                                 "parent_type": spec["parent_type"], "parent_object_id": spec["object_id"]}
                            )
                            continue
                    if int(spec["depth"]) > max_depth:
                        warn(f"max depth reached inside collection {item_path}")
                    add_embedded_data_rows(item, item_path, spec["parent_type"], spec["object_id"])

            fetch_node_specs(child_refs)
            pending_nodes = []
            for ref in sorted(child_refs, key=lambda item: item["path"]):
                child = node_cache.get(f"{ref['type']}|{ref['id']}")
                if child:
                    if ref.get("item_doc") is not None:
                        ref["item_doc"]["node"] = child
                    pending_nodes.append(
                        {"node": child, "path": ref["path"], "depth": ref["depth"], "title": ref.get("title")}
                    )
                elif ref.get("item") is not None:
                    add_embedded_data_rows(
                        ref["item"], ref["path"], ref["parent_type"], ref["parent_object_id"]
                    )

        nodes.sort(key=lambda item: item.get("path") or "")
        collections.sort(key=lambda item: item.get("path") or "")
        table_rows.sort(key=lambda item: item.get("path") or "")

    vulnerability_args = {
        "client": client,
        "token": token,
        "timeline_token": timeline_token,
        "limit_per_collection": min(limit_per_collection, 1000),
        "max_items_per_collection": max_items_per_collection,
        "stats": stats,
        "request_executor": request_executor,
    }
    phase_duration_ms: dict[str, float] = {}

    def timed_tree() -> None:
        started = time.perf_counter()
        try:
            traverse_tree()
        finally:
            phase_duration_ms["tree"] = round((time.perf_counter() - started) * 1000, 2)

    def timed_vulnerabilities() -> dict[str, Any]:
        started = time.perf_counter()
        try:
            return build_asset_vulnerability_snapshot(**vulnerability_args)
        finally:
            phase_duration_ms["vulnerabilities"] = round((time.perf_counter() - started) * 1000, 2)

    if stage_callback:
        stage_callback("tree_and_vulnerabilities")
    if request_executor:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="asset-card-coordinator") as coordinators:
            tree_future = coordinators.submit(timed_tree)
            vulnerability_future = coordinators.submit(timed_vulnerabilities)
            first_done, _ = wait((tree_future, vulnerability_future), return_when=FIRST_COMPLETED)
            if vulnerability_future in first_done and tree_future not in first_done:
                vulnerabilities = vulnerability_future.result()
                if stage_callback:
                    stage_callback("vulnerabilities_ready")
                tree_future.result()
            else:
                tree_future.result()
                if stage_callback:
                    stage_callback("tree_ready")
                vulnerabilities = vulnerability_future.result()
    else:
        timed_tree()
        vulnerabilities = timed_vulnerabilities()
    stats["table_rows"] = len(table_rows)
    stats["elapsed_ms"] = round((time.perf_counter() - build_started) * 1000)
    stats["network_requests"] = sum(
        int(stats.get(key) or 0)
        for key in (
            "metadata_requests",
            "node_requests",
            "collection_requests",
            "vulnerability_header_requests",
            "vulnerability_group_requests",
            "vulnerability_collection_requests",
        )
    ) + 2
    stats["stage_duration_ms"] = dict(sorted(phase_duration_ms.items()))
    if request_executor:
        stats.update(request_executor.telemetry())
    stats["warnings"].sort()
    if stage_callback:
        stage_callback("assembling")

    result = {
        "asset_id": root_asset_id,
        "requested_asset_id": asset_id,
        "display_name": root.get("displayName"),
        "asset_type": root.get("type"),
        "vulnerability_level": root.get("vulnerabilityLevel"),
        "timeline_timestamp": timestamp,
        "timeline_token": timeline_token,
        "root": root,
        "metadata": metadata_cache,
        "nodes": nodes,
        "collections": collections,
        "table_rows": table_rows,
        "vulnerabilities": vulnerabilities,
        "stats": stats,
    }
    log_event(
        "asset-card-build",
        "build.snapshot.completed",
        duration_ms=stats["elapsed_ms"],
        stats=stats,
    )
    return result


def extract_collection_items(response: Any) -> list[Any]:
    if isinstance(response, dict):
        items = response.get("items")
        if isinstance(items, list):
            return items
        data = response.get("data")
        if isinstance(data, list):
            return data
    if isinstance(response, list):
        return response
    return []


def extract_collection_count(response: Any) -> int | None:
    if not isinstance(response, dict):
        return None
    for key in ("count", "total", "totalCount", "totalItems"):
        try:
            if response.get(key) is not None:
                return int(response[key])
        except (TypeError, ValueError):
            return None
    return None


def build_asset_vulnerability_snapshot(
    *,
    client: MpVmClient,
    token: str,
    timeline_token: str,
    limit_per_collection: int,
    max_items_per_collection: int,
    stats: dict[str, Any],
    request_executor: AssetCardRequestExecutor | None = None,
) -> dict[str, Any]:
    """Load the two widget trees and expand every software/OS vulnerability collection.

    The widgets are intentionally handled apart from the generic asset-tree API: their
    collection identifiers and payloads are a different contract and are what lets the
    UI show the compact hierarchy from the MP VM asset card.
    """

    snapshot: dict[str, Any] = {
        "header": {},
        "sources": [],
        "stats": {"groups": 0, "findings": 0, "truncated_groups": 0, "warnings": []},
    }

    def warn(message: str) -> None:
        snapshot["stats"]["warnings"].append(message)
        stats["warnings"].append(message)

    widget_sources = (
        ("os", "HostOSVulnerabilities", "Уязвимости ОС"),
        ("software", "HostSoftVulnerabilities", "Уязвимости программного обеспечения"),
    )
    page_size = max(1, min(limit_per_collection, 1000))
    max_items = max(1, max_items_per_collection)

    initial_operations: list[Callable[[MpVmClient], Any]] = [
        lambda remote: remote.get_asset_vulnerabilities_header(token, timeline_token),
        *[
            (
                lambda remote, collection_type=collection_type:
                    remote.get_asset_vulnerability_groups(token, collection_type, timeline_token)
            )
            for _source, collection_type, _title in widget_sources
        ],
    ]
    if request_executor:
        initial_results = request_executor.map_labeled_settled(
            [
                ("vulnerability_header" if index == 0 else "vulnerability_groups", operation)
                for index, operation in enumerate(initial_operations)
            ]
        )
    else:
        initial_results = []
        for operation in initial_operations:
            try:
                initial_results.append((operation(client), None))
            except Exception as exc:
                initial_results.append((None, exc))

    header, header_error = initial_results[0]
    if header_error is not None:
        warn(f"vulnerabilities header: {header_error}")
    elif isinstance(header, dict):
        stats["vulnerability_header_requests"] += 1
        snapshot["header"] = normalize_asset_vulnerabilities_header(header)

    group_loads: list[dict[str, Any]] = []
    for source_index, (source, collection_type, title) in enumerate(widget_sources):
        source_doc: dict[str, Any] = {
            "source": source,
            "collection_type": collection_type,
            "title": title,
            "level": None,
            "vulnerabilities_count": 0,
            "cvss_score": None,
            "groups": [],
        }
        snapshot["sources"].append(source_doc)
        response, response_error = initial_results[source_index + 1]
        if response_error is not None:
            warn(f"{collection_type}: {response_error}")
            continue
        if not isinstance(response, dict):
            warn(f"{collection_type}: unexpected group response")
            continue
        stats["vulnerability_group_requests"] += 1
        source_doc["level"] = response.get("level")
        source_doc["vulnerabilities_count"] = number_or_zero(response.get("vulnerabilitiesCount"))
        source_doc["cvss_score"] = number_or_none(response.get("cvssScore"))
        for group_index, item in enumerate(extract_collection_items(response)):
            if not isinstance(item, dict):
                continue
            collection_id = vulnerability_collection_id(item)
            group: dict[str, Any] = {
                "source": source,
                "collection_type": collection_type,
                "collection_id": collection_id,
                "name": clean_text(item.get("name")),
                "level": item.get("level"),
                "vulnerabilities_count": number_or_zero(item.get("vulnerabilitiesCount")),
                "cvss_score": number_or_none(item.get("cvssScore")),
                "order": group_index,
                "items": [],
                "truncated": False,
            }
            source_doc["groups"].append(group)
            if not collection_id:
                warn(f"{collection_type} group '{group['name'] or group_index}' does not contain collection id")
                continue
            group_loads.append({"group": group, "collection_type": collection_type, "collection_id": collection_id})

    def load_group(remote: MpVmClient, spec: dict[str, Any]) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        offset = 0
        request_count = 0
        error: Exception | None = None
        while len(items) < max_items:
            if request_executor and request_executor.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            current_limit = min(page_size, max_items - len(items))
            if request_executor:
                request_executor.record_request_started()
            page_started = time.perf_counter()
            try:
                batch = remote.get_asset_vulnerability_collection(
                    token,
                    spec["collection_type"],
                    timeline_token,
                    spec["collection_id"],
                    limit=current_limit,
                    offset=offset,
                )
                request_count += 1
            except (MpVmApiError, requests.RequestException) as exc:
                error = exc
                break
            finally:
                if request_executor:
                    request_executor.record_request_completed()
            items.extend(normalize_asset_vulnerability_item(entry) for entry in batch)
            log_event(
                "asset-card-build",
                "vulnerability.page.loaded",
                level=logging.DEBUG,
                collection_type=spec["collection_type"],
                collection_id=spec["collection_id"],
                offset=offset,
                limit=current_limit,
                item_count=len(batch),
                duration_ms=round((time.perf_counter() - page_started) * 1000, 2),
            )
            if not batch or len(batch) < current_limit:
                break
            offset += len(batch)
        return {"items": items, "request_count": request_count, "error": error}

    group_operations = [
        (lambda remote, spec=spec: load_group(remote, spec))
        for spec in group_loads
    ]
    if request_executor:
        group_results = request_executor.map_settled(
            group_operations,
            count_progress=False,
            label="vulnerability_collection",
        )
    else:
        group_results = []
        for operation in group_operations:
            try:
                group_results.append((operation(client), None))
            except Exception as exc:
                group_results.append((None, exc))

    for spec, (result, operation_error) in zip(group_loads, group_results):
        group = spec["group"]
        if operation_error is not None:
            warn(f"{spec['collection_type']} collection {spec['collection_id']}: {operation_error}")
            continue
        if not isinstance(result, dict):
            continue
        group["items"] = result.get("items") or []
        stats["vulnerability_collection_requests"] += int(result.get("request_count") or 0)
        if result.get("error") is not None:
            warn(f"{spec['collection_type']} collection {spec['collection_id']}: {result['error']}")
        reported_count = group["vulnerabilities_count"]
        group["truncated"] = (
            len(group["items"]) < reported_count
            if reported_count
            else len(group["items"]) >= max_items
        )
        if group["truncated"]:
            snapshot["stats"]["truncated_groups"] += 1
            warn(
                f"{spec['collection_type']} collection {spec['collection_id']}: loaded {len(group['items'])} of "
                f"{reported_count or 'unknown'} vulnerability item(s)"
            )

    snapshot["stats"]["groups"] = sum(len(source["groups"]) for source in snapshot["sources"])
    snapshot["stats"]["findings"] = sum(
        len(group["items"])
        for source in snapshot["sources"]
        for group in source["groups"]
    )
    return snapshot


def normalize_asset_vulnerabilities_header(header: dict[str, Any]) -> dict[str, Any]:
    return {
        "os_soft_vulnerabilities_count": number_or_zero(header.get("osSoftVulnerabilitiesCount")),
        "network_services_vulnerabilities_count": number_or_zero(header.get("networkServicesVulnerabilitiesCount")),
    }


def vulnerability_collection_id(item: dict[str, Any]) -> str:
    vulnerabilities = item.get("vulnerabilities") if isinstance(item.get("vulnerabilities"), dict) else {}
    return clean_text(first_present(vulnerabilities.get("key"), item.get("id"), item.get("key"))).strip()


def normalize_asset_vulnerability_item(item: dict[str, Any]) -> dict[str, Any]:
    description = item.get("description") if isinstance(item.get("description"), dict) else {}
    return {
        "level": item.get("level"),
        "name": clean_text(item.get("name")),
        "cve_name": clean_text(first_present(item.get("cveName"), item.get("cve"))),
        "description_key": clean_text(first_present(description.get("key"), item.get("descriptionKey"))),
        "cvss_score": number_or_none(item.get("cvssScore")),
        "object_id": clean_text(item.get("objectId")),
        "vulnerability_id": clean_text(first_present(item.get("vulnerId"), item.get("vulnerabilityId"))),
        "vulnerability_instance_id": clean_text(first_present(item.get("vulnerabilityInstanceId"), item.get("id"))),
    }


def number_or_none(value: Any) -> int | float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def number_or_zero(value: Any) -> int | float:
    return number_or_none(value) or 0


def metadata_properties_by_name(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    properties = metadata.get("properties")
    if not isinstance(properties, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name"):
            result[str(prop["name"])] = prop
    return result


def metadata_property_for_name(properties: dict[str, dict[str, Any]], name: Any) -> dict[str, Any]:
    if name in properties:
        return properties[name]
    normalized_name = normalize_asset_metadata_key(name)
    for prop_name, prop in properties.items():
        if normalize_asset_metadata_key(prop_name) == normalized_name:
            return prop
    return {}


def metadata_collection_properties(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(prop: Any, *, known_collection: bool = False) -> None:
        if isinstance(prop, str):
            prop = {"name": prop}
        if not isinstance(prop, dict):
            return
        if not known_collection and not metadata_property_is_collection(prop):
            return
        name = metadata_collection_name(prop)
        if not name:
            return
        key = normalize_asset_metadata_key(name)
        if key in seen:
            return
        seen.add(key)
        result.append(prop)

    properties = metadata.get("properties")
    if isinstance(properties, list):
        for prop in properties:
            add(prop)

    for key in ("collections", "collectionProperties", "collection_properties"):
        collection_props = metadata.get(key)
        if isinstance(collection_props, list):
            for prop in collection_props:
                add(prop, known_collection=True)
        elif isinstance(collection_props, dict):
            for name, prop in collection_props.items():
                if isinstance(prop, dict):
                    add({"name": name, **prop}, known_collection=True)
                else:
                    add({"name": name, "title": prop}, known_collection=True)

    return result


def metadata_property_is_collection(prop: dict[str, Any]) -> bool:
    for key in (
        "isCollection",
        "is_collection",
        "collection",
        "hasItems",
        "has_items",
        "isArray",
        "is_array",
        "isList",
        "is_list",
        "multiple",
    ):
        value = prop.get(key)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}:
            return True

    for key in ("kind", "valueKind", "propertyKind", "relationKind", "cardinality", "multiplicity"):
        value = prop.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        if "collection" in normalized or normalized in {"array", "list", "many", "multiple"}:
            return True

    for key in ("type", "valueType", "dataType", "propertyType"):
        value = prop.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        if normalized in {"collection", "array", "list"}:
            return True
        if normalized.endswith("[]") or normalized.startswith(("collection<", "list<", "array<")):
            return True

    return False


def metadata_collection_name(prop: dict[str, Any], fallback: Any = None) -> str:
    return clean_text(
        first_present(
            prop.get("collectionName"),
            prop.get("collection_name"),
            prop.get("name"),
            prop.get("propertyName"),
            fallback,
        )
    )


def metadata_data_has_property(data: dict[str, Any], name: Any) -> bool:
    normalized_name = normalize_asset_metadata_key(name)
    return any(normalize_asset_metadata_key(key) == normalized_name for key in data)


def normalize_asset_metadata_key(value: Any) -> str:
    return str(value or "").replace("_", "").replace("-", "").lower()


def should_fetch_collection(prop: dict[str, Any], value: Any) -> bool:
    if isinstance(value, dict) and "hasItems" in value:
        return True
    return metadata_property_is_collection(prop)


def is_object_ref(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("objectId")) and bool(value.get("type"))


def asset_value_to_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "hasItems" in value:
            return "есть элементы" if value.get("hasItems") else "нет элементов"
        label = first_present(value.get("displayName"), value.get("name"), value.get("title"), value.get("objectId"))
        if label:
            return str(label)
    try:
        return json_dumps_compact(value)
    except TypeError:
        return str(value)


def json_dumps_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def normalize_asset_candidate_record(record: dict[str, Any]) -> dict[str, Any]:
    host = record.get("@Host") if isinstance(record.get("@Host"), dict) else {}
    host_value = record.get("@Host")
    asset_id = first_present(
        host.get("internalId"),
        host.get("id"),
        host.get("objectId"),
        record.get("Host.@Id"),
        record.get("AssetId"),
        record.get("assetId"),
    )
    if not asset_id and isinstance(host_value, str):
        asset_id = extract_uuid(host_value)
    display_name = first_present(
        host.get("displayName"),
        host.get("name"),
        host.get("title"),
        record.get("HostName"),
        host_value if isinstance(host_value, str) else None,
    )
    return {
        "asset_id": asset_id,
        "display_name": display_name,
        "os_name": first_present(record.get("Host.OsName"), host.get("osName")),
        "creation_time": first_present(record.get("Host.@CreationTime"), host.get("creationTime")),
        "update_time": first_present(record.get("Host.@UpdateTime"), host.get("updateTime")),
        "raw_record": record,
    }


def dedupe_asset_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for candidate in candidates:
        key = candidate.get("asset_id") or candidate.get("display_name")
        if key is None:
            result.append(candidate)
            continue
        key_text = str(key)
        if key_text in seen:
            continue
        seen.add(key_text)
        result.append(candidate)
    return result


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def is_hidden_asset_technical_field(key: Any) -> bool:
    normalized = str(key or "").replace("_", "").replace("-", "").lower()
    return normalized in {"type", "objectid"}


def labelize_asset_key(key: Any) -> str:
    labels = {
        "ipAddress": "IP-адрес",
        "fqdn": "Полное имя узла",
        "hostname": "Имя узла",
        "hostType": "Тип узла",
        "macAddress": "MAC-адрес",
        "osName": "Название ОС",
        "osVersion": "Версия ОС",
        "isVirtual": "Виртуальное устройство",
        "displayName": "Название",
        "vulnerabilityLevel": "Уровень уязвимости",
    }
    text = str(key or "")
    return labels.get(text) or re.sub(r"([a-zа-яё])([A-ZА-ЯЁ])", r"\1 \2", text)


def sanitize_asset_card_for_response(card: dict[str, Any]) -> dict[str, Any]:
    cleaned = strip_raw_asset_values(card)
    if isinstance(cleaned, dict):
        cleaned.pop("timeline_token", None)
        cleaned.pop("asset_token", None)
    return cleaned if isinstance(cleaned, dict) else {}


def strip_raw_asset_values(value: Any) -> Any:
    raw_keys = {"raw", "raw_card", "raw_record", "raw_detail", "raw_value"}
    if isinstance(value, list):
        return [strip_raw_asset_values(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_raw_asset_values(item)
            for key, item in value.items()
            if key not in raw_keys
        }
    return value


def normalize_vulnerability_passport_record(record: dict[str, Any]) -> dict[str, Any]:
    passport = record.get("@VulnerPassport") if isinstance(record.get("@VulnerPassport"), dict) else {}
    cves = normalize_compact_items(
        first_present(
            record.get("compact(VulnerPassport.CVEs)"),
            record.get("VulnerPassport.CVEs"),
            passport.get("cves"),
            passport.get("CVEs"),
        )
    )
    metrics = first_present(record.get("VulnerPassport.Metrics"), passport.get("metrics"), passport.get("Metrics"))
    internal_id = first_present(passport.get("internalId"), record.get("internalId"), record.get("VulnerPassport.InternalId"))
    return {
        "internal_id": internal_id,
        "name": first_present(passport.get("name"), passport.get("displayName"), record.get("VulnerPassport.Name")),
        "external_id": first_present(passport.get("id"), record.get("VulnerPassport.Id")),
        "severity": first_present(record.get("VulnerPassport.SeverityRating"), passport.get("severityRating")),
        "score": first_present(record.get("VulnerPassport.Score"), passport.get("score")),
        "issue_time": first_present(record.get("VulnerPassport.IssueTime"), passport.get("issueTime")),
        "package_id": first_present(record.get("VulnerPassport.PackageId"), passport.get("packageId")),
        "package_version": first_present(record.get("VulnerPassport.PackageVersion"), passport.get("packageVersion")),
        "metrics": metrics if isinstance(metrics, dict) else {},
        "cves": cves,
        "raw_record": record,
    }


def vulnerability_passport_summary(passport: dict[str, Any]) -> dict[str, Any]:
    return {
        "internal_id": passport.get("internal_id"),
        "external_id": passport.get("external_id"),
        "name": passport.get("name"),
        "severity": passport.get("severity"),
        "score": passport.get("score"),
        "issue_time": passport.get("issue_time"),
        "package_id": passport.get("package_id"),
        "package_version": passport.get("package_version"),
        "cves": passport.get("cves") if isinstance(passport.get("cves"), list) else [],
        "metrics": passport.get("metrics") if isinstance(passport.get("metrics"), dict) else {},
        "has_detail": False,
    }


def dedupe_vulnerability_passports(passports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for passport in passports:
        key = passport.get("internal_id") or passport.get("external_id") or passport.get("name")
        if key is None:
            result.append(passport)
            continue
        key_text = str(key)
        if key_text in seen:
            continue
        seen.add(key_text)
        result.append(passport)
    return result


def normalize_compact_items(value: Any) -> list[dict[str, Any]]:
    items: list[Any] = []
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        items = value["data"]
    elif isinstance(value, list):
        items = value

    result: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            result.append(
                {
                    "display_name": first_present(item.get("displayName"), item.get("name"), item.get("id")),
                    "url": item.get("url"),
                    "raw": item,
                }
            )
        elif item:
            result.append({"display_name": str(item), "url": None, "raw": item})
    return result


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def decode_csv_bytes(content: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def http_error(exc: Exception) -> HTTPException:
    return HTTPException(status_code=502, detail=str(exc))


def run_background_tasks(background_tasks: BackgroundTasks) -> None:
    if background_tasks.tasks:
        asyncio.run(background_tasks())


def wait_for_automation_operation(operation_id: str, timeout_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    terminal = {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}
    while time.monotonic() < deadline:
        operation = db.get_operation(operation_id)
        if operation and operation.get("status") in terminal:
            if operation["status"] not in {"completed", "completed_with_errors"}:
                raise RuntimeError(operation.get("message") or f"Operation {operation_id} failed.")
            return operation
        time.sleep(2)
    raise TimeoutError(f"Operation {operation_id} did not finish within {timeout_seconds} seconds.")


def execute_automation_step(
    step_type: str,
    config: dict[str, Any],
    _context: dict[str, Any],
    run_id: str,
    step_index: int,
) -> dict[str, Any]:
    idempotency_key = f"automation:{run_id}:{step_index}"
    if step_type == "scanner_task_start":
        task_id = str(config.get("task_id") or "").strip()
        if not task_id:
            raise ValueError("scanner_task_start requires task_id.")
        background = BackgroundTasks()
        options = StartScannerTaskRequest(**(config.get("options") or {}))
        result = start_scanner_task(task_id, background, options, idempotency_key=idempotency_key)
        run_background_tasks(background)
        operation_id = result.get("operation_id") or result.get("postprocess_run_id")
        if operation_id and bool(config.get("wait", True)):
            operation = wait_for_automation_operation(str(operation_id), float(config.get("timeout_seconds") or 7200))
            return {**result, "operation_id": operation_id, "operation": operation}
        return {**result, "operation_id": operation_id}
    if step_type == "pdql_export":
        return export_pdql(PdqlExportRequest(**config))
    if step_type == "passport_sync":
        background = BackgroundTasks()
        result = query_vulnerability_passports(VulnerabilityPassportQueryRequest(**config), background)
        run_background_tasks(background)
        operation_id = (result.get("detail_job") or {}).get("job_id")
        return {**result, "operation_id": operation_id}
    if step_type == "asset_card_build":
        background = BackgroundTasks()
        result = create_asset_card_build_job(
            AssetCardBuildJobRequest(**config), background, idempotency_key=idempotency_key
        )
        run_background_tasks(background)
        operation_id = result.get("operation_id") or (result.get("job") or {}).get("job_id")
        return {**result, "operation_id": operation_id}
    if step_type == "asset_query":
        return asset_card_query(AssetCardFieldQueryRequest(**config))
    raise ValueError(f"Unsupported automation step: {step_type}")


AUTOMATION_TEMPLATES = [
    {
        "template_id": "daily-scan",
        "name": "Ежедневное сканирование",
        "description": "Запуск существующей задачи и ожидание постобработки.",
        "steps": [{"step_id": "scan", "type": "scanner_task_start", "config": {"task_id": ""}, "on_error": "stop", "max_retries": 1}],
    },
    {
        "template_id": "passport-sync",
        "name": "Синхронизация паспортов",
        "description": "Обновление списка и деталей паспортов уязвимостей.",
        "steps": [{"step_id": "passports", "type": "passport_sync", "config": {}, "on_error": "stop", "max_retries": 1}],
    },
    {
        "template_id": "asset-card-refresh",
        "name": "Обновление карточки актива",
        "description": "Построение и сохранение карточки выбранного актива.",
        "steps": [{"step_id": "asset-card", "type": "asset_card_build", "config": {"asset_id": ""}, "on_error": "stop", "max_retries": 1}],
    },
    {
        "template_id": "weekly-export",
        "name": "Еженедельный PDQL экспорт",
        "description": "Безопасный экспорт и импорт без удаления активов.",
        "steps": [{"step_id": "export", "type": "pdql_export", "config": {"delete_assets_after_export": False}, "on_error": "stop", "max_retries": 1}],
    },
]


@automations_router.get("/templates")
def automation_templates() -> dict[str, Any]:
    return {"rows": AUTOMATION_TEMPLATES}


@automations_router.get("/runbooks")
def automation_runbooks() -> dict[str, Any]:
    return {"rows": AUTOMATION_REPOSITORY.list_runbooks()}


@automations_router.post("/runbooks", status_code=201)
def create_automation_runbook(payload: AutomationRunbookRequest) -> dict[str, Any]:
    try:
        return get_automation_service().create_runbook(
            payload.name, payload.description, {"steps": [step.model_dump() for step in payload.steps]}
        )
    except (ValueError, psycopg.errors.UniqueViolation) as exc:
        raise HTTPException(status_code=409 if isinstance(exc, psycopg.errors.UniqueViolation) else 422, detail=str(exc)) from exc


@automations_router.get("/runbooks/{runbook_id}")
def automation_runbook(runbook_id: str) -> dict[str, Any]:
    result = AUTOMATION_REPOSITORY.get_runbook(runbook_id)
    if not result:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return result


@automations_router.put("/runbooks/{runbook_id}")
def update_automation_runbook(runbook_id: str, payload: AutomationRunbookRequest) -> dict[str, Any]:
    try:
        result = get_automation_service().update_runbook(
            runbook_id, payload.name, payload.description, {"steps": [step.model_dump() for step in payload.steps]}
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return result


@automations_router.delete("/runbooks/{runbook_id}")
def delete_automation_runbook(runbook_id: str) -> dict[str, Any]:
    if not AUTOMATION_REPOSITORY.delete_runbook(runbook_id):
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return {"runbook_id": runbook_id, "deleted": True}


@automations_router.post("/runbooks/{runbook_id}/clone", status_code=201)
def clone_automation_runbook(runbook_id: str) -> dict[str, Any]:
    source = AUTOMATION_REPOSITORY.get_runbook(runbook_id)
    if not source:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return get_automation_service().create_runbook(
        f"{source['name']} — копия", source.get("description") or "", source["draft"]
    )


@automations_router.post("/runbooks/{runbook_id}/publish")
def publish_automation_runbook(runbook_id: str, payload: AutomationPublishRequest) -> dict[str, Any]:
    try:
        result = get_automation_service().publish(runbook_id, payload.confirm_name)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return result


@automations_router.post("/runbooks/{runbook_id}/run", status_code=202)
def run_automation_runbook(
    runbook_id: str,
    payload: AutomationRunRequest,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    try:
        return get_automation_service().start_run(
            runbook_id, dry_run=payload.dry_run,
            idempotency_key=idempotency_key if isinstance(idempotency_key, str) else None,
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@automations_router.get("/schedules")
def automation_schedules() -> dict[str, Any]:
    return {"rows": AUTOMATION_REPOSITORY.list_schedules()}


@automations_router.post("/schedules", status_code=201)
def create_automation_schedule(payload: AutomationScheduleRequest) -> dict[str, Any]:
    if not AUTOMATION_REPOSITORY.get_version(payload.runbook_id):
        raise HTTPException(status_code=409, detail="Runbook must be published before scheduling.")
    try:
        next_run_at = get_automation_service().next_run(payload.cron_expression, payload.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return AUTOMATION_REPOSITORY.create_schedule(
        runbook_id=payload.runbook_id, name=payload.name, cron_expression=payload.cron_expression,
        timezone=payload.timezone, enabled=payload.enabled, next_run_at=next_run_at,
    )


@automations_router.put("/schedules/{schedule_id}")
def update_automation_schedule(schedule_id: str, payload: AutomationScheduleRequest) -> dict[str, Any]:
    try:
        next_run_at = get_automation_service().next_run(payload.cron_expression, payload.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = AUTOMATION_REPOSITORY.update_schedule(
        schedule_id, name=payload.name, cron_expression=payload.cron_expression,
        timezone=payload.timezone, enabled=payload.enabled, next_run_at=next_run_at,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return result


@automations_router.delete("/schedules/{schedule_id}")
def delete_automation_schedule(schedule_id: str) -> dict[str, Any]:
    if not AUTOMATION_REPOSITORY.delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"schedule_id": schedule_id, "deleted": True}


@automations_router.get("/runs")
def automation_runs(limit: int = 100) -> dict[str, Any]:
    return {"rows": AUTOMATION_REPOSITORY.list_runs(limit=max(1, min(limit, 500)))}


@automations_router.get("/runs/{run_id}")
def automation_run(run_id: str) -> dict[str, Any]:
    result = AUTOMATION_REPOSITORY.get_run(run_id)
    if not result:
        raise HTTPException(status_code=404, detail="Automation run not found.")
    return result


@automations_router.post("/runs/{run_id}/cancel")
def cancel_automation_run(run_id: str) -> dict[str, Any]:
    if not AUTOMATION_REPOSITORY.request_cancel(run_id):
        raise HTTPException(status_code=409, detail="Automation run is not active.")
    current = AUTOMATION_REPOSITORY.get_run(run_id)
    for step in (current or {}).get("steps") or []:
        child_id = step.get("child_operation_id")
        child = db.get_operation(child_id) if child_id else None
        if child and child.get("can_cancel"):
            cancel_operation(child_id)
            break
    return current or {"run_id": run_id, "status": "cancelling"}


@automations_router.post("/runs/{run_id}/retry", status_code=202)
def retry_automation_run(run_id: str) -> dict[str, Any]:
    source = AUTOMATION_REPOSITORY.get_run(run_id, include_steps=False)
    if not source:
        raise HTTPException(status_code=404, detail="Automation run not found.")
    return get_automation_service().start_run(source["runbook_id"], trigger_type="retry")


@notifications_router.get("")
def notifications(unread_only: bool = False, limit: int = 100) -> dict[str, Any]:
    return AUTOMATION_REPOSITORY.list_notifications(unread_only=unread_only, limit=max(1, min(limit, 500)))


@notifications_router.post("/{notification_id}/read")
def mark_notification_read(notification_id: str) -> dict[str, Any]:
    if not AUTOMATION_REPOSITORY.mark_notification_read(notification_id):
        raise HTTPException(status_code=404, detail="Notification not found.")
    return {"notification_id": notification_id, "is_read": True}


for api_router in API_ROUTERS:
    app.include_router(api_router)


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str) -> FileResponse:
    if full_path.startswith(("api/", "static/")):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(STATIC_DIR / "index.html")
