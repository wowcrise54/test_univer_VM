from __future__ import annotations

import os
import copy
import json
import re
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
    limit: int = Field(default=50000, ge=1, le=50000)
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


class AssetCardUpdateRequest(BaseModel):
    timeline_timestamp: int | None = None
    limit_per_collection: int = Field(default=5000, ge=1, le=5000)
    max_items_per_collection: int = Field(default=5000, ge=1, le=50000)
    max_depth: int = Field(default=8, ge=0, le=8)


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


@app.put("/api/asset-cards/{asset_id}")
def update_local_asset_card(asset_id: str, payload: AssetCardUpdateRequest) -> dict[str, Any]:
    if not db.get_asset_card(asset_id):
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
    return {"asset_id": asset_id, "card": saved_card, "updated": True}


@app.delete("/api/asset-cards/{asset_id}")
def delete_local_asset_card(asset_id: str) -> dict[str, Any]:
    if not db.delete_asset_card(asset_id):
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return {"asset_id": asset_id, "deleted": True}


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
    detail_result = None
    if payload.save_to_db and payload.load_details:
        detail_result = sync_vulnerability_passport_details(
            client=client,
            token=token,
            passports=normalized,
        )
        if db_result is not None:
            db_result["details"] = detail_result
    records_response = (
        db.list_vulnerability_passports_by_ids([item.get("internal_id") for item in normalized])
        if payload.save_to_db
        else normalized
    )
    return {
        "pdql": payload.pdql,
        "pdql_token": pdql_token,
        "limit": payload.limit,
        "batch_size": payload.batch_size,
        "total": len(normalized),
        "records": records_response,
        "db": db_result,
        "details": detail_result,
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


def sync_vulnerability_passport_details(
    *,
    client: MpVmClient,
    token: str,
    passports: list[dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "requested": 0,
        "loaded": 0,
        "failed": 0,
        "skipped": 0,
        "errors": [],
    }
    for passport in passports:
        internal_id = clean_text(passport.get("internal_id")).strip()
        if not internal_id:
            result["skipped"] += 1
            continue
        result["requested"] += 1
        try:
            raw_detail = client.get_vulnerability_passport(token, internal_id)
            db.upsert_vulnerability_passport_detail(internal_id, raw_detail)
            result["loaded"] += 1
        except (MpVmApiError, requests.RequestException) as exc:
            result["failed"] += 1
            if len(result["errors"]) < 25:
                result["errors"].append({"internal_id": internal_id, "error": str(exc)})
    return result


@app.get("/api/vulnerability-passports/{passport_id}/asset-links")
def vulnerability_passport_asset_links(passport_id: str) -> dict[str, Any]:
    return {
        "passport_id": passport_id,
        "rows": db.list_asset_card_links_for_vulnerability_passport(passport_id),
    }


@app.get("/api/vulnerability-passports/{passport_id}")
def vulnerability_passport(passport_id: str) -> dict[str, Any]:
    local = db.get_vulnerability_passport(passport_id)
    if local and local.get("raw_detail"):
        return {"id": passport_id, "raw": local["raw_detail"], "source": "db", "passport": local}

    client, token = require_mpvm()
    try:
        raw_response = client.get_vulnerability_passport(token, passport_id)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
    saved = db.upsert_vulnerability_passport_detail(passport_id, raw_response)
    return {"id": passport_id, "raw": raw_response, "source": "mpvm", "passport": saved}


@app.put("/api/vulnerability-passports/{passport_id}")
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


@app.delete("/api/vulnerability-passports/{passport_id}")
def delete_vulnerability_passport(passport_id: str) -> dict[str, Any]:
    if not db.delete_vulnerability_passport(passport_id):
        raise HTTPException(status_code=404, detail="Vulnerability passport not found in local DB.")
    return {"id": passport_id, "deleted": True}


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
            prop = metadata_property_for_name(properties, name)
            title = clean_text(first_present(prop.get("title"), name))
            value_type = clean_text(first_present(prop.get("type"), value.get("type") if isinstance(value, dict) else None))
            kind = clean_text(prop.get("kind"))
            current_path = f"{path}.{name}"

            if should_fetch_collection(prop, value):
                collection_name = metadata_collection_name(prop, name)
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
                if depth >= max_depth:
                    warn(f"max depth reached before collection {current_path}")
                    continue
                collect_collection(
                    parent_type=node_type,
                    object_id=object_id or root_asset_id,
                    name=collection_name,
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

            add_value_rows(
                path=current_path,
                name=name,
                title=title,
                value=value,
                value_type=value_type,
                kind=kind,
                parent_type=node_type,
                parent_object_id=object_id,
            )

        for prop in metadata_collection_properties(metadata):
            name = metadata_collection_name(prop)
            if not name:
                continue
            if metadata_data_has_property(data, name):
                continue
            current_path = f"{path}.{name}"
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
                    child_loaded = False
                    if child_type and child_id:
                        child = fetch_node(child_type, child_id, item_path)
                        if child:
                            child_loaded = True
                            item_doc["node"] = child
                            traverse_node(child, item_path, depth, item_doc.get("display_name"))
                    if not child_loaded:
                        add_embedded_data_rows(item, item_path, parent_type, object_id)
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

    traverse_node(root, "asset", 0)
    vulnerabilities = build_asset_vulnerability_snapshot(
        client=client,
        token=token,
        timeline_token=timeline_token,
        limit_per_collection=min(limit_per_collection, 1000),
        max_items_per_collection=max_items_per_collection,
        stats=stats,
    )
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
        "vulnerabilities": vulnerabilities,
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


def build_asset_vulnerability_snapshot(
    *,
    client: MpVmClient,
    token: str,
    timeline_token: str,
    limit_per_collection: int,
    max_items_per_collection: int,
    stats: dict[str, Any],
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

    try:
        header = client.get_asset_vulnerabilities_header(token, timeline_token)
        stats["vulnerability_header_requests"] += 1
        snapshot["header"] = normalize_asset_vulnerabilities_header(header)
    except (MpVmApiError, requests.RequestException) as exc:
        warn(f"vulnerabilities header: {exc}")

    widget_sources = (
        ("os", "HostOSVulnerabilities", "Уязвимости ОС"),
        ("software", "HostSoftVulnerabilities", "Уязвимости программного обеспечения"),
    )
    page_size = max(1, min(limit_per_collection, 1000))
    max_items = max(1, max_items_per_collection)

    for source, collection_type, title in widget_sources:
        source_doc: dict[str, Any] = {
            "source": source,
            "collection_type": collection_type,
            "title": title,
            "level": None,
            "vulnerabilities_count": 0,
            "cvss_score": None,
            "groups": [],
        }
        try:
            response = client.get_asset_vulnerability_groups(token, collection_type, timeline_token)
            stats["vulnerability_group_requests"] += 1
        except (MpVmApiError, requests.RequestException) as exc:
            warn(f"{collection_type}: {exc}")
            snapshot["sources"].append(source_doc)
            continue

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
            if not collection_id:
                warn(f"{collection_type} group '{group['name'] or group_index}' does not contain collection id")
                source_doc["groups"].append(group)
                continue

            offset = 0
            while len(group["items"]) < max_items:
                current_limit = min(page_size, max_items - len(group["items"]))
                try:
                    batch = client.get_asset_vulnerability_collection(
                        token,
                        collection_type,
                        timeline_token,
                        collection_id,
                        limit=current_limit,
                        offset=offset,
                    )
                    stats["vulnerability_collection_requests"] += 1
                except (MpVmApiError, requests.RequestException) as exc:
                    warn(f"{collection_type} collection {collection_id}: {exc}")
                    break

                normalized_batch = [normalize_asset_vulnerability_item(entry) for entry in batch]
                group["items"].extend(normalized_batch)
                if not batch or len(batch) < current_limit:
                    break
                offset += len(batch)

            reported_count = group["vulnerabilities_count"]
            group["truncated"] = (
                len(group["items"]) < reported_count
                if reported_count
                else len(group["items"]) >= max_items
            )
            if group["truncated"]:
                snapshot["stats"]["truncated_groups"] += 1
                warn(
                    f"{collection_type} collection {collection_id}: loaded {len(group['items'])} of "
                    f"{reported_count or 'unknown'} vulnerability item(s)"
                )
            source_doc["groups"].append(group)

        snapshot["sources"].append(source_doc)

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
