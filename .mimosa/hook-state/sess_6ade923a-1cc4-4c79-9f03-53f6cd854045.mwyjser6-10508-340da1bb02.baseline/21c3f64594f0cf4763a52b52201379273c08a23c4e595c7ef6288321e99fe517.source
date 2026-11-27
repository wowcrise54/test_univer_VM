from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import BackgroundTasks, Header, HTTPException, Request
from fastapi.responses import FileResponse

from .. import db
from ..diagnostics import diagnostic_context, log_event, normalize_correlation_id, redact
from ..mpvm.common import as_dict
from ..services.main_host import host
from ..services.operation_diagnostics import build_operation_diagnostic_archive
from .automations import cancel_automation_run
from .routers import diagnostics_router, operations_router
from .schemas import (
    AssetCardBuildJobRequest,
    FrontendDiagnosticBatch,
    SavedViewRequest,
    VulnerabilityPassportQueryRequest,
)


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
        return host.CONTAINER.services.operations.list(status=status, kind=kind, q=q, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@operations_router.get("/api/operations/summary")
def operations_summary() -> dict[str, Any]:
    return host.CONTAINER.services.operations.summary()


@operations_router.post("/api/operations/clear-history")
def clear_operations_history(request: Request) -> dict[str, int]:
    actor = str(request.state.user.get("username") or "unknown")
    return host.CONTAINER.services.operations.clear_history(actor=actor)


@operations_router.get("/api/operations/{operation_id}")
def operation_detail(operation_id: str) -> dict[str, Any]:
    operation = host.CONTAINER.repositories.operations.get(operation_id)
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
        host.cancel_asset_card_build_job(operation["source_id"])
    elif operation["kind"] == "asset_card_bulk_refresh":
        host.CONTAINER.operation_runner.cancellations.cancel("asset-card-bulk-refresh", operation["source_id"])
        result = as_dict(operation.get("result"))
        child_ids = {
            str(child_id).strip()
            for child_id in result.get("child_operation_ids") or []
            if str(child_id).strip()
        }
        current_child_id = str(result.get("current_child_operation_id") or "").strip()
        if current_child_id:
            child_ids.add(current_child_id)
        for child_id in child_ids:
            child = db.get_operation(child_id)
            if child and child.get("can_cancel"):
                host.cancel_operation(child_id)
        db.register_operation(
            operation_id,
            kind="asset_card_bulk_refresh",
            source_id=operation["source_id"],
            status="cancelling",
            stage="cancelling",
            progress_percent=operation.get("progress_percent") or 0,
            message="Остановка массового обновления карточек запрошена.",
        )
    elif operation["kind"] == "passport_detail_sync":
        host.cancel_vulnerability_passport_detail_job(operation["source_id"])
    elif operation["kind"] == "passport_catalog_refresh":
        host.cancel_vulnerability_passport_refresh_job(operation["source_id"])
    elif operation["kind"] == "scan_postprocess":
        host.cancel_scan_postprocess_run(operation["source_id"])
    elif operation["kind"] == "automation_run":
        cancel_automation_run(operation["source_id"])
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
    request_data = as_dict(operation.get("request"))
    if operation["kind"] == "asset_card_build":
        result = host.create_asset_card_build_job(AssetCardBuildJobRequest(**request_data), background_tasks)
        new_id = result["job"]["job_id"]
    elif operation["kind"] == "passport_detail_sync":
        if not request_data.get("pdql"):
            raise HTTPException(
                status_code=409,
                detail={"code": "RETRY_CONTEXT_MISSING", "message": "Original passport query is unavailable.", "component": "operations"},
            )
        result = host.query_vulnerability_passports(VulnerabilityPassportQueryRequest(**request_data), background_tasks)
        detail_job = result.get("detail_job") or {}
        new_id = detail_job.get("job_id")
        if not new_id:
            raise HTTPException(status_code=409, detail={"code": "RETRY_NOT_REQUIRED", "message": "No passport details require refresh.", "component": "operations"})
    elif operation["kind"] == "automation_run":
        source = host.AUTOMATION_REPOSITORY.get_run(operation["source_id"], include_steps=False)
        if not source:
            raise HTTPException(status_code=409, detail={"code": "RETRY_CONTEXT_MISSING", "message": "Original automation run is unavailable.", "component": "operations"})
        retried_run = host.get_automation_service().start_run(source["runbook_id"], trigger_type="retry", idempotency_key=clean_key)
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
    path = build_operation_diagnostic_archive(operation)
    return FileResponse(path, media_type="application/zip", filename=path.name)


@operations_router.get("/api/saved-views")
def saved_views(route: str) -> dict[str, Any]:
    return {"rows": host.CONTAINER.repositories.operations.saved_views(route)}


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
        item_trace_id = normalize_correlation_id(item.trace_id, fallback=False) or host.current_trace_id()
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
    return {"accepted": len(payload.events), "trace_id": host.current_trace_id()}
