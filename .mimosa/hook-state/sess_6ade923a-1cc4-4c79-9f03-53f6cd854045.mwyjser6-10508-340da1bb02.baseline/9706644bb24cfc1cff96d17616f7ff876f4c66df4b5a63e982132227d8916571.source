from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import db
from ..api.schemas import ASSET_CARD_MAX_DEPTH
from ..diagnostics import (
    diagnostic_context,
    log_event,
    new_trace_id,
    redact,
    set_diagnostic_context,
)
from ..mpvm.asset_metadata import ASSET_CARD_STAGE_PROGRESS
from ..mpvm.docker_vulnerabilities import validate_docker_vulnerability_pdql
from ..mpvm_client import DOCKER_VULNERABILITY_PDQL, AuthConfig
from ..services.asset_card_builder import AssetCardBuildCancelled, AssetCardRequestExecutor
from .main_host import host


def register_asset_card_build_job(job_id: str) -> threading.Event:
    return host.CONTAINER.operation_runner.cancellations.register("asset-card", job_id)


def unregister_asset_card_build_job(job_id: str) -> None:
    host.CONTAINER.operation_runner.cancellations.remove("asset-card", job_id)


def run_asset_card_build_job(
    *,
    job_id: str,
    auth: AuthConfig,
    token: str,
    request: dict[str, Any],
    cancel_event: threading.Event,
    trace_id: str | None = None,
) -> None:
    acquired = False
    try:
        while not cancel_event.is_set():
            acquired = host.ASSET_CARD_BUILD_SEMAPHORE.acquire(timeout=0.25)
            if acquired:
                break
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
    finally:
        if acquired:
            host.ASSET_CARD_BUILD_SEMAPHORE.release()


def run_asset_card_build_jobs(
    *,
    jobs: list[dict[str, Any]],
    auth: AuthConfig,
    token: str,
    requests: list[dict[str, Any]],
    cancel_events: dict[str, threading.Event] | None = None,
    trace_id: str | None = None,
) -> None:
    if len(jobs) != len(requests):
        raise ValueError("jobs and requests must contain the same number of items")
    events = cancel_events or {
        str(job["job_id"]): host.register_asset_card_build_job(str(job["job_id"]))
        for job in jobs
    }
    worker_count = min(host.ASSET_CARD_BUILD_WORKERS, len(jobs))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="asset-card-batch") as executor:
        futures = {
            executor.submit(
                host.run_asset_card_build_job,
                job_id=str(job["job_id"]),
                auth=auth,
                token=token,
                request=request,
                cancel_event=events[str(job["job_id"])],
                trace_id=trace_id,
            ): str(job["job_id"])
            for job, request in zip(jobs, requests, strict=True)
        }
        for future, job_id in futures.items():
            try:
                future.result()
            except Exception:
                host.log_exception("asset-card-build", "batch.worker.failed", job_id=job_id)


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
            if not force and completed < discovered and now - last_progress_write < 5.0:
                return
            last_progress_write = now
            card_stats: Any = card.get("stats") if isinstance(card, dict) else {}
            vulnerability_stats: Any = (
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
            worker_limit=host.ASSET_CARD_REQUEST_WORKERS,
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
            workers=host.ASSET_CARD_REQUEST_WORKERS,
            cancel_event=cancel_event,
            on_progress=lambda discovered, completed: write_progress(discovered, completed),
        )
        set_stage("collecting")
        card = host.build_asset_card(
            client=None,
            token=token,
            asset_id=str(request["asset_id"]),
            timeline_timestamp=request.get("timeline_timestamp"),
            limit_per_collection=int(request.get("limit_per_collection") or 5000),
            max_items_per_collection=int(request.get("max_items_per_collection") or 5000),
            max_depth=int(ASSET_CARD_MAX_DEPTH if request.get("max_depth") is None else request["max_depth"]),
            docker_vulnerability_pdql=validate_docker_vulnerability_pdql(
                str(request.get("docker_vulnerability_pdql") or DOCKER_VULNERABILITY_PDQL)
            ),
            request_executor=executor,
            stage_callback=set_stage,
        )
        if cancel_event.is_set():
            raise AssetCardBuildCancelled("Cancelled before saving.")
        set_stage("saving", card=card)
        saved = db.upsert_asset_card(card)
        if not saved:
            raise RuntimeError("Asset card could not be saved.")
        canonical_asset_id = str(saved["asset_id"])
        if canonical_asset_id != str(request["asset_id"]) and request.get("parent_operation_id"):
            db.rebind_scan_postprocess_asset(job_id, canonical_asset_id)
        host.CONTAINER.services.remediation.reconcile_asset(canonical_asset_id)
        set_stage("completed", card=card)
        db.finish_asset_card_build_job(
            job_id,
            status="completed",
            stage="completed",
            message="Asset card build completed.",
            stats=card.get("stats") if isinstance(card.get("stats"), dict) else {},
        )
        if not request.get("parent_operation_id"):
            host.capture_vulnerability_snapshot("asset_card_build", job_id)
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
        host.log_exception(
            "asset-card-build",
            "build.failed",
            duration_ms=round((time.perf_counter() - build_started_at) * 1000, 2),
        )
    finally:
        if executor:
            executor.close()
        unregister_asset_card_build_job(job_id)
