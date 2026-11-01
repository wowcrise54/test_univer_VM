from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import psycopg
from fastapi import BackgroundTasks

from .. import db
from ..api.schemas import (
    AssetCardRefreshScanRequest,
    StartScannerTaskRequest,
)
from ..services.scanner_task_launch import (
    _start_scanner_task_request,
)
from .main_host import host

if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient


def start_vm_scan_child(task_id: str, options: dict[str, Any], workflow_id: str) -> dict[str, Any]:
    payload = StartScannerTaskRequest(**options)
    return _start_scanner_task_request(task_id, payload, f"vm-workflow:{workflow_id}:scan")


def start_vm_verification_children(
    workflow_id: str, asset_ids: list[str], options: dict[str, Any],
) -> dict[str, Any]:
    operation_ids: list[str] = []
    errors: list[dict[str, str]] = []
    payload = AssetCardRefreshScanRequest(**options)
    for asset_id in asset_ids:
        tasks = BackgroundTasks()
        try:
            result = host.refresh_asset_card_by_scan(
                asset_id, payload, tasks, idempotency_key=f"vm-workflow:{workflow_id}:asset:{asset_id}",
            )
            operation_id = result.get("operation_id") or result.get("postprocess_run_id")
            if operation_id:
                operation_ids.append(str(operation_id))
            for task in tasks.tasks:
                task.func(*task.args, **task.kwargs)
        except Exception as exc:
            errors.append({"asset_id": asset_id, "message": str(exc)})
    return {"operation_ids": operation_ids, "errors": errors}


def start_team_scanner_task(
    task_id: str, options: dict[str, Any], idempotency_key: str | None, actor: str | None,
) -> dict[str, Any]:
    start_options = StartScannerTaskRequest(**options)
    result = _start_scanner_task_request(task_id, start_options, idempotency_key)
    operation_id = result.get("operation_id") or result.get("postprocess_run_id")
    if operation_id:
        try:
            workflow = host.CONTAINER.services.vm_workflows.track_scan(
                task_id=task_id, operation_id=str(operation_id), options=start_options.model_dump(),
                actor=actor, idempotency_key=idempotency_key,
            )
            result["workflow_id"] = workflow["workflow_id"]
            result["workflow"] = workflow
        except psycopg.Error:
            host.log_exception("vm-workflow", "team_scan.workflow_tracking_failed", operation_id=operation_id)
    return result


def stop_team_scanner_task(task_id: str) -> dict[str, Any]:
    client, token = host.require_mpvm()
    response = client.stop_scanner_task(token, task_id)
    db.update_scan_task_status(task_id, "stop_requested", response)
    return response


def _mpvm_call(action: Callable[[MpVmClient, str], Any]) -> Any:
    client, token = host.require_mpvm()
    return action(client, token)
