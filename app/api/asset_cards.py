from __future__ import annotations

import ipaddress
import logging
import uuid
from typing import Any, Literal

import psycopg
import requests
from fastapi import BackgroundTasks, Header, HTTPException

from .. import db
from ..diagnostics import log_event, new_trace_id
from ..mpvm.asset_metadata import (
    dedupe_asset_candidates,
    normalize_asset_candidate_record,
    sanitize_asset_card_for_response,
)
from ..mpvm.common import http_error
from ..mpvm.docker_vulnerabilities import docker_scan_group_name, validate_docker_vulnerability_pdql
from ..mpvm.scanner_task_rows import remote_scanner_task_templates
from ..mpvm_client import MpVmApiError
from ..services.asset_card_build_jobs import register_asset_card_build_job
from ..services.asset_card_refresh import (
    build_asset_refresh_task_payload,
    run_asset_card_bulk_refresh_operation,
)
from ..services.main_host import host
from ..services.scan_postprocess import SCAN_LOG, scan_log
from .routers import asset_cards_router
from .schemas import (
    AssetCardAssetQueryRequest,
    AssetCardBuildBatchJobRequest,
    AssetCardBuildJobRequest,
    AssetCardBuildRequest,
    AssetCardBulkRefreshRequest,
    AssetCardRefreshScanRequest,
    AssetCardUpdateRequest,
)


@asset_cards_router.post("/api/asset-cards/query-assets")
def query_asset_card_assets(payload: AssetCardAssetQueryRequest) -> dict[str, Any]:
    client, token = host.require_mpvm()
    try:
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
    client, token = host.require_mpvm()
    asset_id = payload.asset_id.strip()
    if not asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    docker_pdql = validate_docker_vulnerability_pdql(payload.docker_vulnerability_pdql)

    try:
        card = host.build_asset_card(
            client=client,
            token=token,
            asset_id=asset_id,
            timeline_timestamp=payload.timeline_timestamp,
            limit_per_collection=payload.limit_per_collection,
            max_items_per_collection=payload.max_items_per_collection,
            max_depth=payload.max_depth,
            docker_vulnerability_pdql=docker_pdql,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    saved_card = db.upsert_asset_card(card) if payload.save_to_db else None
    if saved_card is not None:
        host.CONTAINER.services.remediation.reconcile_asset(str(saved_card["asset_id"]))
        host.capture_vulnerability_snapshot(
            "asset_card_build",
            host.current_trace_id() or str(uuid.uuid4()),
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
    docker_pdql = validate_docker_vulnerability_pdql(payload.docker_vulnerability_pdql)
    active_job = db.get_active_asset_card_build_job()
    if active_job:
        raise HTTPException(
            status_code=409,
            detail={"message": "An asset card build is already running.", "job": active_job},
        )
    client, token = host.require_mpvm()
    request = payload.model_dump()
    request["asset_id"] = asset_id
    request["docker_vulnerability_pdql"] = docker_pdql
    job_id = str(uuid.uuid4())
    trace_id = host.current_trace_id() or new_trace_id()
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
        host.run_asset_card_build_job,
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


@asset_cards_router.post("/api/asset-cards/build-jobs/batch", status_code=202)
def create_asset_card_build_jobs_batch(
    payload: AssetCardBuildBatchJobRequest,
    background_tasks: BackgroundTasks,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    clean_idempotency_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_idempotency_key)
    if replay and replay.get("kind") == "asset_card_build_batch":
        job_ids = (replay.get("result") or {}).get("job_ids") or []
        jobs: Any = [db.get_asset_card_build_job(str(job_id)) for job_id in job_ids]
        if all(jobs):
            return {"jobs": jobs, "idempotent_replay": True}

    client, token = host.require_mpvm()
    docker_pdql = validate_docker_vulnerability_pdql(payload.docker_vulnerability_pdql)
    batch_id = str(uuid.uuid4())
    trace_id = host.current_trace_id() or new_trace_id()
    base_request = payload.model_dump(exclude={"asset_ids"})
    base_request["docker_vulnerability_pdql"] = docker_pdql
    specs: list[dict[str, Any]] = []
    requests_by_job_id: dict[str, dict[str, Any]] = {}
    for asset_id in payload.asset_ids:
        job_id = str(uuid.uuid4())
        request = {**base_request, "asset_id": asset_id, "batch_id": batch_id}
        requests_by_job_id[job_id] = request
        specs.append(
            {
                "job_id": job_id,
                "trace_id": trace_id,
                "asset_id": asset_id,
                "operation": "refresh" if db.asset_card_exists(asset_id) else "create",
                "request": request,
            }
        )

    try:
        jobs = db.create_asset_card_build_jobs(
            specs,
            batch_operation={
                "operation_id": batch_id,
                "source_id": batch_id,
                "trace_id": trace_id,
                "idempotency_key": clean_idempotency_key,
                "request": {**base_request, "asset_ids": payload.asset_ids},
            },
        )
    except psycopg.errors.UniqueViolation as exc:
        replay = db.get_operation_by_idempotency_key(clean_idempotency_key)
        if replay and replay.get("kind") == "asset_card_build_batch":
            job_ids = (replay.get("result") or {}).get("job_ids") or []
            replay_jobs = [db.get_asset_card_build_job(str(job_id)) for job_id in job_ids]
            if all(replay_jobs):
                return {"jobs": replay_jobs, "idempotent_replay": True}
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ASSET_CARD_BUILD_CAPACITY_EXCEEDED",
                "message": "Asset card build capacity is unavailable.",
            },
        ) from exc
    if not jobs or len(jobs) != len(specs):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ASSET_CARD_BUILD_CAPACITY_EXCEEDED",
                "message": "Asset card build capacity is unavailable.",
            },
        )

    cancel_events = {
        spec["job_id"]: register_asset_card_build_job(spec["job_id"])
        for spec in specs
    }
    background_tasks.add_task(
        host.run_asset_card_build_jobs,
        jobs=specs,
        auth=client.auth,
        token=token,
        requests=[requests_by_job_id[spec["job_id"]] for spec in specs],
        cancel_events=cancel_events,
        trace_id=trace_id,
    )
    log_event(
        "asset-card-build",
        "batch.scheduled",
        trace_id=trace_id,
        batch_id=batch_id,
        job_ids=[spec["job_id"] for spec in specs],
        asset_ids=payload.asset_ids,
    )
    return {"jobs": jobs}


@asset_cards_router.get("/api/asset-cards/build-jobs/active")
def active_asset_card_build_job() -> dict[str, Any]:
    return {"job": db.get_active_asset_card_build_job()}


@asset_cards_router.get("/api/asset-cards/refresh-scan/templates")
def asset_card_refresh_templates() -> dict[str, Any]:
    templates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for task in db.list_scan_tasks():
        task_id = str(task.get("mp_task_id") or "")
        payload = task.get("payload")
        if task_id and not task.get("deleted_at") and isinstance(payload, dict) and payload.get("scope") and payload.get("profile"):
            templates.append({"mp_task_id": task_id, "name": payload.get("name") or task.get("name") or task_id, "source": "local"})
            seen.add(task_id)
    client, token = host.require_mpvm()
    try:
        remote = remote_scanner_task_templates(client, token)
    except (MpVmApiError, requests.RequestException) as exc:
        if not templates:
            raise http_error(exc) from exc
        remote = []
    for task in remote:
        if task["mp_task_id"] not in seen:
            templates.append({key: task[key] for key in ("mp_task_id", "name", "source")})
            seen.add(task["mp_task_id"])
    return {"rows": templates, "recommended_task_id": templates[0]["mp_task_id"] if templates else None}


@asset_cards_router.post("/api/asset-cards/refresh-scan/bulk", status_code=202)
def refresh_asset_cards_bulk(
    payload: AssetCardBulkRefreshRequest,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict[str, Any]:
    """Queue bounded parallel refresh scans for all saved cards or only stale cards."""
    clean_key = idempotency_key if isinstance(idempotency_key, str) else None
    replay = db.get_operation_by_idempotency_key(clean_key)
    if replay:
        if replay.get("kind") != "asset_card_bulk_refresh":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "IDEMPOTENCY_KEY_CONFLICT",
                    "message": "Idempotency key belongs to another operation.",
                    "component": "operations",
                },
            )
        return {"operation_id": replay["operation_id"], "operation": replay, "idempotent_replay": True}

    request = payload.model_dump()
    template = host.resolve_asset_card_refresh_template("", payload.template_task_id)
    request["template_task_id"] = template["mp_task_id"]
    operation_id = str(uuid.uuid4())
    label = "Все карточки активов" if payload.selection == "all" else "Карточки старше порога свежести"
    operation = db.register_operation(
        operation_id,
        kind="asset_card_bulk_refresh",
        source_id=operation_id,
        status="queued",
        stage="queued",
        progress_percent=0,
        subject_type="asset_cards",
        subject_label=label,
        message="Массовое обновление карточек поставлено в очередь.",
        request=request,
        idempotency_key=clean_key,
    )
    cancel_event = host.CONTAINER.operation_runner.cancellations.register("asset-card-bulk-refresh", operation_id)
    future = host.CONTAINER.operation_runner.submit(
        "asset-card-bulk-refresh",
        run_asset_card_bulk_refresh_operation,
        operation_id=operation_id,
        config=request,
        cancel_event=cancel_event,
    )
    future.add_done_callback(
        lambda _future: host.CONTAINER.operation_runner.cancellations.remove("asset-card-bulk-refresh", operation_id)
    )
    return {"operation_id": operation_id, "operation": operation}


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

    template = host.resolve_asset_card_refresh_template(asset_id, payload.template_task_id)

    client, token = host.require_mpvm()
    task_payload = build_asset_refresh_task_payload(
        template["payload"],
        asset_id=asset_id,
        target_ip=target_ip,
        display_name=str(card.get("display_name") or card.get("hostname") or target_ip),
    )
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
    if host.DOCKER_DYNAMIC_GROUP_ITERATIONS > 0:
        options["docker_dynamic_group"] = {
            "name": docker_scan_group_name(postprocess_run_id),
            "state": "planned",
        }
    postprocess_holder: dict[str, dict[str, Any]] = {}
    refresh_task_id: str | None = None

    def ensure_refresh_postprocess_run(started_from: str) -> dict[str, Any]:
        if not refresh_task_id:
            raise RuntimeError("Refresh scanner task id is unavailable.")
        if "run" not in postprocess_holder:
            postprocess_holder["run"] = db.create_scan_postprocess_run(
                postprocess_run_id,
                mp_task_id=refresh_task_id,
                started_from=started_from,
                options=options,
                idempotency_key=clean_key,
            )
        return postprocess_holder["run"]

    try:
        refresh_task_id = client.create_scanner_task(token, task_payload)
        db.record_scan_task(
            mp_task_id=refresh_task_id,
            payload=task_payload,
            status="asset_refresh_created",
            remote_response={"id": refresh_task_id, "template_task_id": template.get("mp_task_id"), "refresh_asset_id": asset_id},
        )
        start_result = host.start_scanner_task_impl(
            client=client,
            token=token,
            task_id=refresh_task_id,
            options=payload.start_options,
            docker_group_run_id=postprocess_run_id,
            before_remote_start=ensure_refresh_postprocess_run,
        )
    except Exception as exc:
        if "run" in postprocess_holder:
            try:
                host.finish_provisional_scan_start_failure(
                    run_id=postprocess_run_id,
                    auth=client.auth,
                    token=token,
                    error=exc,
                )
            except Exception:
                SCAN_LOG.exception(
                    "[scan-postprocess] failed to finalize provisional refresh scanner start "
                    "postprocess_run_id=%s task_id=%s",
                    postprocess_run_id,
                    refresh_task_id,
                )
        if isinstance(exc, MpVmApiError | requests.RequestException):
            raise http_error(exc) from exc
        raise

    if start_result.get("status") != "started":
        return {
            **start_result,
            "task_id": refresh_task_id,
            "template_task_id": template.get("mp_task_id"),
            "refresh_asset_id": asset_id,
            "target_ip": target_ip,
        }

    created_before_start = "run" in postprocess_holder
    docker_group = start_result.get("docker_dynamic_group")
    if not created_before_start and isinstance(docker_group, dict):
        options["docker_dynamic_group"] = docker_group
    postprocess = ensure_refresh_postprocess_run(str(start_result["started_from"]))
    if created_before_start:
        postprocess = db.get_scan_postprocess_run(postprocess_run_id) or postprocess
    background_tasks.add_task(host.schedule_scan_postprocess, postprocess_run_id, client.auth, token)
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
    host.CONTAINER.operation_runner.cancellations.cancel("asset-card", job_id)
    log_event(
        "asset-card-build",
        "build.cancel.requested",
        trace_id=job.get("trace_id"),
        job_id=job_id,
        asset_id=job.get("asset_id"),
        status=job.get("status"),
    )
    return job


@asset_cards_router.get("/api/asset-cards/local")
def local_asset_cards(
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return host.CONTAINER.services.asset_cards.list(q=q, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@asset_cards_router.get("/api/asset-cards/{asset_id}/summary")
def local_asset_card_summary(asset_id: str) -> dict[str, Any]:
    card = db.get_asset_card_summary(asset_id)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return card


@asset_cards_router.get("/api/asset-cards/{asset_id}/history")
def local_asset_card_history(asset_id: str, limit: int = 20) -> dict[str, Any]:
    return {"asset_id": asset_id, "items": db.get_asset_card_history(asset_id, limit=limit)}


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
    card = host.CONTAINER.services.asset_cards.get(asset_id, section=section)
    if not card:
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")
    return card


@asset_cards_router.put("/api/asset-cards/{asset_id}")
def update_local_asset_card(asset_id: str, payload: AssetCardUpdateRequest) -> dict[str, Any]:
    if not db.asset_card_exists(asset_id):
        raise HTTPException(status_code=404, detail="Asset card not found in local DB.")

    client, token = host.require_mpvm()
    docker_pdql = validate_docker_vulnerability_pdql(payload.docker_vulnerability_pdql)
    try:
        card = host.build_asset_card(
            client=client,
            token=token,
            asset_id=asset_id,
            timeline_timestamp=payload.timeline_timestamp,
            limit_per_collection=payload.limit_per_collection,
            max_items_per_collection=payload.max_items_per_collection,
            max_depth=payload.max_depth,
            docker_vulnerability_pdql=docker_pdql,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    saved_card = db.upsert_asset_card(card)
    if not saved_card:
        raise HTTPException(status_code=500, detail="Updated asset card could not be saved.")
    host.CONTAINER.services.remediation.reconcile_asset(str(saved_card["asset_id"]))
    host.capture_vulnerability_snapshot(
        "asset_card_update",
        host.current_trace_id() or str(uuid.uuid4()),
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
    host.capture_vulnerability_snapshot(
        "asset_card_delete",
        host.current_trace_id() or str(uuid.uuid4()),
    )
    return {"asset_id": asset_id, "deleted": True}
