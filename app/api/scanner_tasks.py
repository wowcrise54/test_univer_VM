from __future__ import annotations

from typing import Any

import psycopg
import requests
from fastapi import BackgroundTasks, Header, HTTPException

from .. import db
from ..mpvm.common import http_error
from ..mpvm_client import MpVmApiError
from ..services.main_host import host
from ..services.scanner_task_launch import (
    _start_scanner_task_request,
    delete_scanner_task_idempotent,
    run_false_targets_precheck,
    scanner_task_payload,
)
from .routers import tasks_router
from .schemas import DeleteScannerTaskRequest, ScannerTaskRequest, StartScannerTaskRequest


@tasks_router.get("/api/mpvm/scanner-tasks/remote")
def remote_scanner_tasks(offset: int = 0, limit: int = 50, main_filter: str | None = None) -> Any:
    client, token = host.require_mpvm()
    try:
        return client.list_remote_scanner_tasks(token, offset=offset, limit=limit, main_filter=main_filter)
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.get("/api/scanner-tasks")
def local_scanner_tasks() -> list[dict[str, Any]]:
    return host.CONTAINER.services.tasks.list()


@tasks_router.get("/api/scanner-tasks/{task_id}/results")
def scanner_task_results(task_id: str) -> dict[str, Any]:
    local_task = db.get_scan_task(task_id)
    if not local_task:
        raise HTTPException(status_code=404, detail="Local scanner task not found.")

    client, token = host.require_mpvm()
    try:
        runs = client.get_task_runs(token, task_id)
        if not runs:
            return {
                "task_id": task_id,
                "task_name": local_task.get("name") or task_id,
                "task_status": local_task.get("status"),
                "is_precheck": str(local_task.get("status") or "").startswith("precheck_"),
                "run": None,
                "items": [],
                "total": 0,
            }

        run = runs[0]
        run_id = str(run.get("id") or "").strip()
        if not run_id:
            raise HTTPException(status_code=502, detail="MP VM returned a scanner run without an id.")
        jobs = client.get_all_run_jobs(
            token,
            run_id,
            target_pattern="",
            orderby="startedAt desc",
            batch_size=1000,
        )
        is_precheck = str(local_task.get("status") or "").startswith("precheck_") or any(
            str(job.get("runMode") or "") == "connectionCheck" for job in jobs
        )
        return {
            "task_id": task_id,
            "task_name": local_task.get("name") or task_id,
            "task_status": local_task.get("status"),
            "is_precheck": is_precheck,
            "run": run,
            "items": jobs,
            "total": len(jobs),
        }
    except HTTPException:
        raise
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


@tasks_router.post("/api/scanner-tasks")
def create_scanner_task(payload: ScannerTaskRequest) -> dict[str, Any]:
    client, token = host.require_mpvm()
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
    client, token = host.require_mpvm()
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
    client, token = host.require_mpvm()
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
    result = _start_scanner_task_request(
        task_id, payload or StartScannerTaskRequest(), clean_idempotency_key, background_tasks=background_tasks,
    )
    operation_id = result.get("operation_id") or result.get("postprocess_run_id")
    if operation_id:
        try:
            workflow = host.CONTAINER.services.vm_workflows.track_scan(
                task_id=task_id, operation_id=str(operation_id), options=(payload or StartScannerTaskRequest()).model_dump(),
                actor=None, idempotency_key=clean_idempotency_key,
            )
            result["workflow_id"] = workflow["workflow_id"]
            result["workflow"] = workflow
        except psycopg.Error:
            host.log_exception("vm-workflow", "legacy_scan.workflow_tracking_failed", operation_id=operation_id)
    return result


@tasks_router.post("/api/scanner-tasks/{task_id}/retry-false", status_code=202)
def retry_false_precheck(
    task_id: str,
    payload: StartScannerTaskRequest | None = None,
) -> dict[str, Any]:
    client, token = host.require_mpvm()
    try:
        return run_false_targets_precheck(
            client=client,
            token=token,
            source_precheck_task_id=task_id,
            options=payload or StartScannerTaskRequest(),
        )
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
    client, token = host.require_mpvm()
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
