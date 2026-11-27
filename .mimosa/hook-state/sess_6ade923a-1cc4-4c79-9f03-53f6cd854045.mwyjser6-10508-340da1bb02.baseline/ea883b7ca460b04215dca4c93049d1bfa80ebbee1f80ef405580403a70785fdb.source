from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import TYPE_CHECKING, Any

import psycopg
import requests
from fastapi import BackgroundTasks, HTTPException

from .. import db
from ..api.schemas import VulnerabilityPassportQueryRequest
from ..core import get_settings
from ..diagnostics import log_event
from ..mpvm.common import http_error
from ..mpvm.passport_records import (
    dedupe_vulnerability_passports,
    merge_trending_vulnerability_records,
    normalize_trending_vulnerability_record,
    normalize_vulnerability_passport_record,
    vulnerability_passport_summary,
)
from ..mpvm_client import (
    TRENDING_VULNERABILITY_PDQL,
    VULNER_PASSPORT_PDQL,
    AuthConfig,
    MpVmApiError,
)
from ..services import passport_refresh as passport_refresh_service
from .main_host import host

if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient



# Defaults are bound when the function is defined, so they cannot come from the
# lazily resolved app.main; they mirror its PASSPORT_DETAIL_* settings.
_DEFAULT_PASSPORT_DETAIL_WORKERS = min(
    min(32, get_settings().background_request_limit),
    min(32, get_settings().passport_detail_workers),
)
_DEFAULT_PASSPORT_DETAIL_DB_BATCH_SIZE = 100


def sync_trending_vulnerability_passports(
    *,
    client: MpVmClient,
    token: str,
    utc_offset: str | None,
    batch_size: int,
    reconcile_links: bool,
) -> dict[str, Any]:
    pdql_token = client.create_pdql_token(
        token,
        TRENDING_VULNERABILITY_PDQL,
        utc_offset=utc_offset,
        selected_group_ids=[],
        include_nested_groups=True,
        asset_ids=[],
    )
    records, raw_response = host.fetch_asset_grid_records(
        client=client,
        token=token,
        pdql_token=pdql_token,
        limit=None,
        batch_size=batch_size,
    )
    parsed = [
        normalize_trending_vulnerability_record(record) for record in records
    ]
    if not records and raw_response.get("reportedTotal") is None:
        raise ValueError(
            "MP VM returned an unverified empty trend response; "
            "the previous snapshot was preserved."
        )
    if any(not item.get("internal_id") or not item.get("is_trend") for item in parsed):
        raise ValueError(
            "MP VM returned malformed or non-trending passport rows; "
            "the previous snapshot was preserved."
        )
    normalized = merge_trending_vulnerability_records(parsed)
    db_result = db.replace_vulnerability_passport_trends(
        normalized,
        source_pdql=TRENDING_VULNERABILITY_PDQL,
        pdql_token=pdql_token,
        reconcile_links=reconcile_links,
    )
    return {
        "status": "completed",
        "pdql": TRENDING_VULNERABILITY_PDQL,
        "pdql_token": pdql_token,
        "total": len(normalized),
        "db": db_result,
        "raw": raw_response,
    }


def run_vulnerability_passport_refresh_job(
    operation_id: str,
    payload: VulnerabilityPassportQueryRequest,
    cancel_event: threading.Event,
) -> None:
    try:
        passport_refresh_service.run(
            operation_id, payload, host._execute_vulnerability_passport_query,
            host.CONTAINER.operation_runner.submit, cancel_event,
        )
    finally:
        host.CONTAINER.operation_runner.cancellations.remove("passport-refresh", operation_id)


def _execute_vulnerability_passport_query(
    payload: VulnerabilityPassportQueryRequest,
    background_tasks: BackgroundTasks,
    progress: Callable[[int, str, str], None] | None = None,
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

    client, token = host.require_mpvm()
    query_started = time.perf_counter()
    try:
        if progress:
            progress(2, "query", "Создание запроса в MP VM.")
        pdql_token = client.create_pdql_token(
            token,
            payload.pdql,
            utc_offset=payload.utc_offset,
            selected_group_ids=payload.group_ids,
            include_nested_groups=payload.include_nested_groups,
            asset_ids=payload.asset_ids,
        )
        records, raw_response = host.fetch_asset_grid_records(
            client=client,
            token=token,
            pdql_token=pdql_token,
            limit=payload.limit,
            batch_size=payload.batch_size,
            progress_callback=(
                lambda loaded, total: progress(
                    min(75, max(3, round(loaded * 75 / total))) if total else 3,
                    "fetch", f"Получено {loaded} из {total} паспортов." if total else f"Получено {loaded} паспортов. Общий объём уточняется.",
                )
            ) if progress else None,
            retry_callback=(
                lambda loaded, total, offset, attempt: progress(
                    min(75, max(3, round(loaded * 75 / total))) if total else 3,
                    "fetch_retry",
                    f"MP VM вернул 404 для страницы offset={offset}. Повтор {attempt}/3; уже получено {loaded} паспортов.",
                )
            ) if progress else None,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
    grid_finished = time.perf_counter()

    if progress:
        progress(78, "normalize", "Проверка и объединение паспортов.")
    normalized = dedupe_vulnerability_passports(
        [normalize_vulnerability_passport_record(record) for record in records]
    )
    if progress:
        progress(82, "save", f"Сохранение {len(normalized)} паспортов в БД.")
    def save_progress(stage: str, done: int, total: int) -> None:
        # Saving spans 82-86%, rebuilding finding links 86-90%.
        if not progress or not total:
            return
        if stage == "save":
            progress(82 + round(4 * done / total), "save", f"Сохранено {done} из {total} паспортов.")
        else:
            progress(86 + round(4 * done / total), "link", f"Пересчёт связей с находками: {done} из {total} пакетов.")

    db_result = (
        db.upsert_vulnerability_passports(
            normalized, source_pdql=payload.pdql, pdql_token=pdql_token, progress=save_progress,
        )
        if payload.save_to_db
        else None
    )
    trend_sync = None
    if payload.save_to_db:
        if progress:
            progress(90, "trends", "Обновление трендов уязвимостей.")
        try:
            full_catalog_sync = (
                " ".join(payload.pdql.split())
                == " ".join(VULNER_PASSPORT_PDQL.split())
                and payload.limit is None
                and not payload.group_ids
                and not payload.asset_ids
            )
            trend_sync = host.sync_trending_vulnerability_passports(
                client=client,
                token=token,
                utc_offset=payload.utc_offset,
                batch_size=payload.batch_size,
                # A complete default passport sync already rebuilt links. A
                # scoped/custom sync may introduce a parent seen only in the
                # trend result, so reconcile once more in that case.
                reconcile_links=not full_catalog_sync,
            )
        except Exception as exc:
            # Trend metadata is an independent optional snapshot. A malformed
            # remote response or a local serialization failure must not block
            # the main passport list or its background detail job.
            trend_sync = {
                "status": "failed",
                "pdql": TRENDING_VULNERABILITY_PDQL,
                "message": str(exc),
            }
            log_event(
                "passport-sync",
                "trending-vulnerabilities.sync.failed",
                level=logging.WARNING,
                error=str(exc),
            )
    saved_finished = time.perf_counter()
    detail_job = None
    if payload.save_to_db and payload.load_details:
        if progress:
            progress(96, "details", "Подготовка фоновой загрузки деталей.")
        internal_ids = [item.get("internal_id") for item in normalized]
        candidates = db.vulnerability_passport_detail_refresh_candidates(
            internal_ids,
            ttl_hours=host.PASSPORT_DETAIL_TTL_HOURS,
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
                workers=host.PASSPORT_DETAIL_WORKERS,
                batch_size=host.PASSPORT_DETAIL_DB_BATCH_SIZE,
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
        "trend_sync": trend_sync,
        "detail_job": detail_job,
        "details": detail_job,
        "raw": raw_response,
        "timings_ms": {
            "grid_fetch": round((grid_finished - query_started) * 1000),
            "list_save": round((saved_finished - grid_finished) * 1000),
            "response_prepare": round((time.perf_counter() - saved_finished) * 1000),
        },
    }


def register_vulnerability_passport_detail_job(job_id: str) -> threading.Event:
    return host.CONTAINER.operation_runner.cancellations.register("passport-detail", job_id)


def unregister_vulnerability_passport_detail_job(job_id: str) -> None:
    host.CONTAINER.operation_runner.cancellations.remove("passport-detail", job_id)


def run_vulnerability_passport_detail_job(
    *,
    job_id: str,
    auth: AuthConfig,
    token: str,
    internal_ids: list[str],
    cancel_event: threading.Event,
    workers: int = _DEFAULT_PASSPORT_DETAIL_WORKERS,
    batch_size: int = _DEFAULT_PASSPORT_DETAIL_DB_BATCH_SIZE,
) -> None:
    worker_state = threading.local()
    worker_clients: list[MpVmClient] = []
    worker_clients_lock = threading.Lock()

    def fetch_detail(internal_id: str) -> tuple[str, dict[str, Any]]:
        client = getattr(worker_state, "client", None)
        if client is None:
            client = host.MpVmClient(auth)
            worker_state.client = client
            with worker_clients_lock:
                worker_clients.append(client)
        with host.BACKGROUND_REQUEST_SEMAPHORE:
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
        if job.get("loaded_count"):
            db.reconcile_vulnerability_passport_detail_job_links()
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
