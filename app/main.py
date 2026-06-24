from __future__ import annotations

import os
import copy
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import requests
import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

from . import db
from .mpvm_client import (
    ASSET_CARD_PDQL,
    SOFTWARE_VULN_PDQL,
    VULNER_PASSPORT_PDQL,
    AuthConfig,
    MpVmApiError,
    MpVmClient,
    build_asset_id_pdql_for_ips,
    build_default_token_url,
    build_scanner_task_payload,
    extract_asset_ids_from_csv,
    extract_uuid,
    extract_ips_from_csv,
    normalize_url,
)


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
EXPORTS_DIR = Path(os.getenv("MPVM_EXPORTS_DIR", "exports"))
SAMPLE_CSV = Path("host_software_vulnerabilities_10.104.103.0_24.csv")


@dataclass
class RuntimeSession:
    client: MpVmClient | None = None
    access_token: str | None = None
    api_url: str | None = None
    token_url: str | None = None
    username: str | None = None
    verify_tls: bool = True


SESSION = RuntimeSession()
DATABASE_STARTUP_ERROR: str | None = None


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
    limit: int = Field(default=1001, ge=1, le=50000)
    batch_size: int = Field(default=5000, ge=1, le=10000)
    save_to_db: bool = True


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
    limit_per_collection: int = Field(default=500, ge=1, le=1000)
    max_items_per_collection: int = Field(default=500, ge=1, le=50000)
    max_depth: int = Field(default=4, ge=0, le=8)
    save_to_db: bool = True


app = FastAPI(title="MP VM REST API Client", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def startup() -> None:
    global DATABASE_STARTUP_ERROR
    try:
        db.init_db()
        DATABASE_STARTUP_ERROR = None
    except psycopg.Error as exc:
        DATABASE_STARTUP_ERROR = str(exc)
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    configure_session_from_env()


@app.exception_handler(psycopg.Error)
def database_error_handler(_request, exc: psycopg.Error) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": f"Database is unavailable: {exc}"},
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "app": "mpvm-rest-client",
        "database": db.database_label(),
        "database_ready": DATABASE_STARTUP_ERROR is None,
        "database_error": DATABASE_STARTUP_ERROR,
        "connected": SESSION.client is not None and SESSION.access_token is not None,
        "api_url": SESSION.api_url,
    }


@app.get("/api/defaults")
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


@app.post("/api/session/connect")
def connect_session(payload: ConnectionRequest) -> dict[str, Any]:
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
    return {
        "connected": True,
        "api_url": api_url,
        "token_url": token_url,
        "username": payload.username,
        "verify_tls": payload.verify_tls,
    }


@app.post("/api/session/disconnect")
def disconnect_session() -> dict[str, Any]:
    SESSION.client = None
    SESSION.access_token = None
    SESSION.api_url = None
    SESSION.token_url = None
    SESSION.username = None
    return {"connected": False}


@app.get("/api/session")
def session_info() -> dict[str, Any]:
    return {
        "connected": SESSION.client is not None and SESSION.access_token is not None,
        "api_url": SESSION.api_url,
        "token_url": SESSION.token_url,
        "username": SESSION.username,
        "verify_tls": SESSION.verify_tls,
    }


@app.get("/api/mpvm/lookups")
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


@app.get("/api/mpvm/scanner-tasks/remote")
def remote_scanner_tasks(offset: int = 0, limit: int = 50, main_filter: str | None = None) -> Any:
    client, token = require_mpvm()
    try:
        return client.list_remote_scanner_tasks(token, offset=offset, limit=limit, main_filter=main_filter)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@app.get("/api/scanner-tasks")
def local_scanner_tasks() -> list[dict[str, Any]]:
    return db.list_scan_tasks()


@app.post("/api/scanner-tasks")
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


@app.put("/api/scanner-tasks/{task_id}")
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


@app.post("/api/scanner-tasks/{task_id}/validate")
def validate_scanner_task(task_id: str) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        valid, error = client.validate_scanner_task(token, task_id)
        db.update_scan_task_status(task_id, "valid" if valid else "validation_failed", {"error": error})
        return {"id": task_id, "valid": valid, "error": error}
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@app.post("/api/scanner-tasks/{task_id}/start")
def start_scanner_task(task_id: str, payload: StartScannerTaskRequest | None = None) -> dict[str, Any]:
    client, token = require_mpvm()
    options = payload or StartScannerTaskRequest()
    try:
        result = start_scanner_task_impl(client=client, token=token, task_id=task_id, options=options)
        return result
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@app.post("/api/scanner-tasks/{task_id}/stop")
def stop_scanner_task(task_id: str) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        response = client.stop_scanner_task(token, task_id)
        db.update_scan_task_status(task_id, "stop_requested", response)
        return response
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@app.post("/api/scanner-tasks/{task_id}/delete")
def delete_scanner_task_post(task_id: str, payload: DeleteScannerTaskRequest | None = None) -> dict[str, Any]:
    return delete_scanner_task_impl(task_id, payload or DeleteScannerTaskRequest())


@app.delete("/api/scanner-tasks/{task_id}")
def delete_scanner_task_delete(task_id: str, payload: DeleteScannerTaskRequest | None = None) -> dict[str, Any]:
    return delete_scanner_task_impl(task_id, payload or DeleteScannerTaskRequest())


@app.post("/api/exports/pdql")
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


@app.post("/api/import/csv-text")
def import_csv_text(payload: CsvTextImportRequest) -> dict[str, Any]:
    return db.import_csv_text(
        payload.csv_text,
        source=payload.source,
        pdql=payload.pdql,
        csv_filename=payload.csv_filename,
    )


@app.post("/api/import/csv-file")
async def import_csv_file(file: UploadFile = File(...)) -> dict[str, Any]:
    content = await file.read()
    text = decode_csv_bytes(content)
    return db.import_csv_text(text, source="uploaded_csv", csv_filename=file.filename)


@app.post("/api/import/sample")
def import_sample() -> dict[str, Any]:
    if not SAMPLE_CSV.exists():
        raise HTTPException(status_code=404, detail=f"Sample CSV not found: {SAMPLE_CSV}")
    return db.import_csv_text(
        SAMPLE_CSV.read_text(encoding="utf-8-sig"),
        source="sample_csv",
        csv_filename=SAMPLE_CSV.name,
    )


@app.get("/api/assets")
def assets(q: str | None = None, severity: str | None = None, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    return db.list_asset_findings(q=q, severity=severity, limit=limit, offset=offset)


@app.get("/api/assets/summary")
def assets_summary() -> dict[str, Any]:
    return db.get_summary()


@app.post("/api/asset-cards/query-assets")
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


@app.post("/api/asset-cards/build")
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
    return {
        "asset_id": asset_id,
        "card": saved_card or sanitize_asset_card_for_response(card),
        "saved": saved_card is not None,
    }


@app.get("/api/asset-cards/local")
def local_asset_cards(q: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    return db.list_asset_cards(q=q, limit=limit, offset=offset)


@app.get("/api/asset-cards/{asset_id}")
def local_asset_card(asset_id: str) -> dict[str, Any]:
    card = db.get_asset_card(asset_id)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return card


@app.post("/api/vulnerability-passports/query")
def query_vulnerability_passports(payload: VulnerabilityPassportQueryRequest) -> dict[str, Any]:
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

    normalized = dedupe_vulnerability_passports(
        [normalize_vulnerability_passport_record(record) for record in records]
    )
    db_result = (
        db.upsert_vulnerability_passports(normalized, source_pdql=payload.pdql, pdql_token=pdql_token)
        if payload.save_to_db
        else None
    )
    return {
        "pdql": payload.pdql,
        "pdql_token": pdql_token,
        "limit": payload.limit,
        "batch_size": payload.batch_size,
        "total": len(normalized),
        "records": normalized,
        "db": db_result,
        "raw": raw_response,
    }


@app.get("/api/vulnerability-passports/local")
def local_vulnerability_passports(
    q: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    return db.list_vulnerability_passports(q=q, severity=severity, limit=limit, offset=offset)


@app.get("/api/vulnerability-passports/{passport_id}")
def vulnerability_passport(passport_id: str) -> dict[str, Any]:
    client, token = require_mpvm()
    try:
        raw_response = client.get_vulnerability_passport(token, passport_id)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
    db.upsert_vulnerability_passport_detail(passport_id, raw_response)
    return {"id": passport_id, "raw": raw_response}


@app.get("/api/exports/{filename}")
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

    if not options.wait_for_finish:
        return {**result, "status": "started"}

    ok, message = client.wait_for_task_success(
        token,
        task_id,
        time_from=started_from,
        timeout_seconds=options.task_timeout_minutes * 60,
        poll_seconds=options.task_poll_seconds,
        require_clean_jobs=options.require_clean_jobs,
        stop_on_timeout=True,
    )
    finish_status = "finished" if ok else ("timeout_stop_requested" if "timeout" in message else "failed")
    finish_payload = {"ok": ok, "message": message}
    result["finish"] = finish_payload
    db.update_scan_task_status(task_id, finish_status, finish_payload)
    return {**result, "status": finish_status}


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
    limit: int,
    batch_size: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    batches: list[dict[str, Any]] = []
    first_response: dict[str, Any] | None = None
    expected_total: int | None = None
    offset = 0

    while offset < limit:
        current_limit = min(batch_size, limit - offset)
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
    client: MpVmClient,
    token: str,
    asset_id: str,
    timeline_timestamp: int | None,
    limit_per_collection: int,
    max_items_per_collection: int,
    max_depth: int,
) -> dict[str, Any]:
    timestamp = timeline_timestamp or int(datetime.now(timezone.utc).timestamp())
    timeline_token = client.create_asset_timeline_token(token, asset_id, timestamp)
    root = client.get_asset_tree_root(token, timeline_token)
    root_asset_id = str(first_present(root.get("objectId"), asset_id))

    metadata_cache: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    collections: list[dict[str, Any]] = []
    table_rows: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_collections: set[str] = set()
    stats: dict[str, Any] = {
        "metadata_requests": 0,
        "node_requests": 0,
        "collection_requests": 0,
        "nodes": 0,
        "collections": 0,
        "table_rows": 0,
        "warnings": [],
    }

    def warn(message: str) -> None:
        stats["warnings"].append(message)

    def metadata_for(asset_type: str | None) -> dict[str, Any]:
        if not asset_type:
            return {}
        if asset_type in metadata_cache:
            return metadata_cache[asset_type]
        try:
            metadata = client.get_asset_metadata(token, asset_type)
            stats["metadata_requests"] += 1
        except (MpVmApiError, requests.RequestException) as exc:
            warn(f"metadata {asset_type}: {exc}")
            metadata = {}
        metadata_cache[asset_type] = metadata
        return metadata

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

    def fetch_node(asset_type: str, object_id: str, path: str) -> dict[str, Any] | None:
        try:
            node = client.get_asset_tree_node(token, asset_type, object_id, timeline_token)
            stats["node_requests"] += 1
            return node
        except (MpVmApiError, requests.RequestException) as exc:
            warn(f"node {path} ({asset_type}/{object_id}): {exc}")
            return None

    def fetch_collection(parent_type: str, object_id: str, name: str, path: str) -> tuple[list[Any], int | None, bool]:
        items: list[Any] = []
        reported_count: int | None = None
        offset = 0
        while len(items) < max_items_per_collection:
            current_limit = min(limit_per_collection, max_items_per_collection - len(items))
            if current_limit <= 0:
                break
            try:
                response = client.get_asset_tree_collection(
                    token,
                    parent_type,
                    object_id,
                    name,
                    timeline_token,
                    full=True,
                    limit=current_limit,
                    offset=offset,
                )
                stats["collection_requests"] += 1
            except (MpVmApiError, requests.RequestException) as exc:
                warn(f"collection {path} ({parent_type}/{object_id}/{name}): {exc}")
                break

            batch = extract_collection_items(response)
            count = extract_collection_count(response)
            if count is not None:
                reported_count = count
            items.extend(batch)
            if not batch or len(batch) < current_limit:
                break
            offset += len(batch)
            if reported_count is not None and offset >= reported_count:
                break

        truncated = False
        if reported_count is not None:
            truncated = len(items) < reported_count
        elif len(items) >= max_items_per_collection:
            truncated = True
        if truncated:
            warn(f"collection {path}: fetched {len(items)} item(s), reported count {reported_count or 'unknown'}")
        return items, reported_count, truncated

    def traverse_node(node: dict[str, Any], path: str, depth: int, relation_title: str | None = None) -> None:
        node_type = clean_text(first_present(node.get("type"), ""))
        object_id = clean_text(first_present(node.get("objectId"), ""))
        node_key = f"{node_type}|{object_id}"
        if object_id and node_key in seen_nodes:
            return
        if object_id:
            seen_nodes.add(node_key)
        if path != "asset":
            nodes.append(
                {
                    "path": path,
                    "title": relation_title or node.get("displayName") or path,
                    "display_name": node.get("displayName"),
                    "object_id": object_id,
                    "type": node_type,
                    "vulnerability_level": node.get("vulnerabilityLevel"),
                    "data": node.get("data") if isinstance(node.get("data"), dict) else {},
                }
            )
            stats["nodes"] += 1

        metadata = metadata_for(node_type)
        properties = metadata_properties_by_name(metadata)
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        for name, value in data.items():
            prop = properties.get(name, {})
            title = clean_text(first_present(prop.get("title"), name))
            value_type = clean_text(first_present(prop.get("type"), value.get("type") if isinstance(value, dict) else None))
            kind = clean_text(prop.get("kind"))
            current_path = f"{path}.{name}"

            if should_fetch_collection(prop, value):
                add_table_row(
                    path=current_path,
                    name=name,
                    title=title,
                    value=value,
                    value_type=value_type,
                    kind=kind or "collection",
                    parent_type=node_type,
                    parent_object_id=object_id,
                )
                if not collection_has_items(value):
                    continue
                if depth >= max_depth:
                    warn(f"max depth reached before collection {current_path}")
                    continue
                collect_collection(
                    parent_type=node_type,
                    object_id=object_id or root_asset_id,
                    name=name,
                    prop=prop,
                    path=current_path,
                    depth=depth + 1,
                )
                continue

            if is_object_ref(value):
                add_table_row(
                    path=current_path,
                    name=name,
                    title=title,
                    value=value,
                    value_type=value_type,
                    kind=kind or "node",
                    parent_type=node_type,
                    parent_object_id=object_id,
                )
                if depth >= max_depth:
                    warn(f"max depth reached before node {current_path}")
                    continue
                child_type = clean_text(value.get("type"))
                child_id = clean_text(value.get("objectId"))
                if child_type and child_id:
                    child = fetch_node(child_type, child_id, current_path)
                    if child:
                        traverse_node(child, current_path, depth + 1, title)
                continue

            add_table_row(
                path=current_path,
                name=name,
                title=title,
                value=value,
                value_type=value_type,
                kind=kind,
                parent_type=node_type,
                parent_object_id=object_id,
            )

    def collect_collection(
        *,
        parent_type: str,
        object_id: str,
        name: str,
        prop: dict[str, Any],
        path: str,
        depth: int,
    ) -> None:
        if not parent_type or not object_id:
            warn(f"collection {path}: parent type or object id is empty")
            return
        collection_key = f"{parent_type}|{object_id}|{name}"
        if collection_key in seen_collections:
            return
        seen_collections.add(collection_key)

        items, reported_count, truncated = fetch_collection(parent_type, object_id, name, path)
        collection_doc: dict[str, Any] = {
            "path": path,
            "name": name,
            "title": clean_text(first_present(prop.get("title"), name)),
            "type": prop.get("type"),
            "kind": prop.get("kind"),
            "parent_type": parent_type,
            "parent_object_id": object_id,
            "count": reported_count if reported_count is not None else len(items),
            "fetched_count": len(items),
            "truncated": truncated,
            "items": [],
        }
        collections.append(collection_doc)
        stats["collections"] += 1

        for index, item in enumerate(items):
            item_path = f"{path}[{index}]"
            if isinstance(item, dict):
                item_doc = {
                    "path": item_path,
                    "display_name": item.get("displayName"),
                    "object_id": item.get("objectId"),
                    "type": item.get("type"),
                    "vulnerability_level": item.get("vulnerabilityLevel"),
                    "data": item.get("data") if isinstance(item.get("data"), dict) else {},
                }
                collection_doc["items"].append(item_doc)
                add_table_row(
                    path=item_path,
                    name=name,
                    title=collection_doc["title"],
                    value=item,
                    value_type=item.get("type") or prop.get("type"),
                    kind=prop.get("kind"),
                    parent_type=parent_type,
                    parent_object_id=object_id,
                )
                if depth <= max_depth and is_object_ref(item):
                    child_type = clean_text(item.get("type"))
                    child_id = clean_text(item.get("objectId"))
                    if child_type and child_id:
                        child = fetch_node(child_type, child_id, item_path)
                        if child:
                            item_doc["node"] = child
                            traverse_node(child, item_path, depth, item_doc.get("display_name"))
                elif depth > max_depth:
                    warn(f"max depth reached inside collection {item_path}")
                else:
                    add_embedded_data_rows(item, item_path, parent_type, object_id)
            else:
                collection_doc["items"].append({"path": item_path, "value": item})
                add_table_row(
                    path=item_path,
                    name=name,
                    title=collection_doc["title"],
                    value=item,
                    value_type=prop.get("type"),
                    kind=prop.get("kind"),
                    parent_type=parent_type,
                    parent_object_id=object_id,
                )

    def add_embedded_data_rows(item: dict[str, Any], path: str, parent_type: str, parent_object_id: str) -> None:
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        for key, embedded_value in data.items():
            add_table_row(
                path=f"{path}.{key}",
                name=key,
                title=key,
                value=embedded_value,
                value_type=None,
                kind=None,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
            )

    traverse_node(root, "asset", 0)
    stats["table_rows"] = len(table_rows)

    return {
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
        "stats": stats,
    }


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


def metadata_properties_by_name(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    properties = metadata.get("properties")
    if not isinstance(properties, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name"):
            result[str(prop["name"])] = prop
    return result


def should_fetch_collection(prop: dict[str, Any], value: Any) -> bool:
    if isinstance(value, dict) and "hasItems" in value:
        return True
    return bool(prop.get("isCollection"))


def collection_has_items(value: Any) -> bool:
    if isinstance(value, dict) and value.get("hasItems") is False:
        return False
    return True


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


@app.get("/{full_path:path}", include_in_schema=False)
def spa_fallback(full_path: str) -> FileResponse:
    if full_path.startswith(("api/", "static/")):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(STATIC_DIR / "index.html")
