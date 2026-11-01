from __future__ import annotations

import os
import uuid
from typing import Any, Literal

import psycopg
import requests
from fastapi import BackgroundTasks, HTTPException

from .. import db
from ..mpvm.common import http_error
from ..mpvm_client import VULNER_PASSPORT_PDQL, MpVmApiError
from ..repositories import passport_refresh
from ..services.main_host import host
from ..services.vulnerability_passport_jobs import (
    _execute_vulnerability_passport_query,
    run_vulnerability_passport_refresh_job,
)
from .routers import passports_router
from .schemas import VulnerabilityPassportQueryRequest


@passports_router.post("/api/vulnerability-passports/query")
def query_vulnerability_passports(
    payload: VulnerabilityPassportQueryRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    return _execute_vulnerability_passport_query(payload, background_tasks)


@passports_router.post("/api/vulnerability-passports/refresh-jobs", status_code=202)
def create_vulnerability_passport_refresh_job(background_tasks: BackgroundTasks) -> dict[str, Any]:
    host.require_mpvm()
    active_detail = db.get_active_vulnerability_passport_detail_job()
    if active_detail:
        raise HTTPException(status_code=409, detail={"message": "Загрузка деталей паспортов уже выполняется.", "job": active_detail})
    payload = VulnerabilityPassportQueryRequest(
        pdql=VULNER_PASSPORT_PDQL,
        utc_offset=os.getenv("MPVM_UTC_OFFSET") or os.getenv("MP10_UTC_OFFSET") or "+05:00",
        limit=None, batch_size=5000, save_to_db=True, load_details=True,
    )
    operation_id = str(uuid.uuid4())
    try:
        operation = passport_refresh.create(operation_id, payload.model_dump())
    except psycopg.errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail={"message": "Обновление паспортов уже выполняется.", "job": passport_refresh.latest()}) from exc
    cancel_event = host.CONTAINER.operation_runner.cancellations.register("passport-refresh", operation_id)
    background_tasks.add_task(
        run_vulnerability_passport_refresh_job, operation_id, payload, cancel_event,
    )
    return {"job": operation}


@passports_router.get("/api/vulnerability-passports/refresh-jobs/latest")
def latest_vulnerability_passport_refresh_job() -> dict[str, Any]:
    return {"job": passport_refresh.latest()}


@passports_router.get("/api/vulnerability-passports/refresh-jobs/{operation_id}")
def vulnerability_passport_refresh_job(operation_id: str) -> dict[str, Any]:
    job = passport_refresh.get(operation_id)
    if not job:
        raise HTTPException(status_code=404, detail="Passport refresh job not found.")
    return job


@passports_router.post("/api/vulnerability-passports/refresh-jobs/{operation_id}/cancel")
def cancel_vulnerability_passport_refresh_job(operation_id: str) -> dict[str, Any]:
    job = passport_refresh.get(operation_id)
    if not job:
        raise HTTPException(status_code=404, detail="Passport refresh job not found.")
    host.CONTAINER.operation_runner.cancellations.cancel("passport-refresh", operation_id)
    return passport_refresh.request_cancel(operation_id) or job


@passports_router.post("/api/vulnerability-passports/trending/refresh")
def refresh_trending_vulnerability_passports() -> dict[str, Any]:
    client, token = host.require_mpvm()
    try:
        return host.sync_trending_vulnerability_passports(
            client=client,
            token=token,
            utc_offset=os.getenv("MPVM_UTC_OFFSET") or "+05:00",
            batch_size=5000,
            reconcile_links=True,
        )
    except (MpVmApiError, requests.RequestException, ValueError) as exc:
        raise http_error(exc) from exc


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
        return host.CONTAINER.services.passports.list(
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
    host.CONTAINER.operation_runner.cancellations.cancel("passport-detail", job_id)
    return job


@passports_router.get("/api/vulnerability-passports/{passport_id}/asset-links")
def vulnerability_passport_asset_links(passport_id: str) -> dict[str, Any]:
    return {
        "passport_id": passport_id,
        "rows": db.list_asset_card_links_for_vulnerability_passport(passport_id),
    }


@passports_router.get("/api/vulnerability-passports/{passport_id}")
def vulnerability_passport(passport_id: str) -> dict[str, Any]:
    local = host.CONTAINER.services.passports.get(passport_id)
    if local and local.get("raw_detail"):
        return {"id": passport_id, "raw": local["raw_detail"], "source": "db", "passport": local}

    client, token = host.require_mpvm()
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

    client, token = host.require_mpvm()
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
