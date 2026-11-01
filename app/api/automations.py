from __future__ import annotations

from typing import Any

import psycopg
from fastapi import Header, HTTPException

from .. import db
from ..services.main_host import host
from .routers import automations_router, notifications_router
from .schemas import (
    AutomationPublishRequest,
    AutomationRunbookRequest,
    AutomationRunRequest,
    AutomationScheduleRequest,
)

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
        "description": "Сканирование актива временной задачей MP VM, перенос карточки и удаление задачи.",
        "steps": [{"step_id": "asset-card", "type": "asset_card_build", "config": {"asset_id": "", "wait": True, "timeout_seconds": 14400, "start_options": {"task_timeout_minutes": 120}}, "on_error": "stop", "max_retries": 1}],
    },
    {
        "template_id": "stale-asset-card-refresh",
        "name": "Обновление устаревших карточек",
        "description": "Параллельно обновляет карточки, у которых дата «Обновлено» старше настроенного порога свежести (по умолчанию 14 дней).",
        "steps": [{"step_id": "stale-asset-cards", "type": "asset_card_build", "config": {"selection": "stale", "parallelism": 10, "wait": True, "timeout_seconds": 14400, "start_options": {"task_timeout_minutes": 120}}, "on_error": "stop", "max_retries": 1}],
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
    return {"rows": host.AUTOMATION_REPOSITORY.list_runbooks()}


@automations_router.post("/runbooks", status_code=201)
def create_automation_runbook(payload: AutomationRunbookRequest) -> dict[str, Any]:
    try:
        return host.get_automation_service().create_runbook(
            payload.name, payload.description, {"steps": [step.model_dump() for step in payload.steps]}
        )
    except (ValueError, psycopg.errors.UniqueViolation) as exc:
        raise HTTPException(status_code=409 if isinstance(exc, psycopg.errors.UniqueViolation) else 422, detail=str(exc)) from exc


@automations_router.get("/runbooks/{runbook_id}")
def automation_runbook(runbook_id: str) -> dict[str, Any]:
    result = host.AUTOMATION_REPOSITORY.get_runbook(runbook_id)
    if not result:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return result


@automations_router.put("/runbooks/{runbook_id}")
def update_automation_runbook(runbook_id: str, payload: AutomationRunbookRequest) -> dict[str, Any]:
    try:
        result = host.get_automation_service().update_runbook(
            runbook_id, payload.name, payload.description, {"steps": [step.model_dump() for step in payload.steps]}
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return result


@automations_router.delete("/runbooks/{runbook_id}")
def delete_automation_runbook(runbook_id: str) -> dict[str, Any]:
    if not host.AUTOMATION_REPOSITORY.delete_runbook(runbook_id):
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return {"runbook_id": runbook_id, "deleted": True}


@automations_router.post("/runbooks/{runbook_id}/clone", status_code=201)
def clone_automation_runbook(runbook_id: str) -> dict[str, Any]:
    source = host.AUTOMATION_REPOSITORY.get_runbook(runbook_id)
    if not source:
        raise HTTPException(status_code=404, detail="Runbook not found.")
    return host.get_automation_service().create_runbook(
        f"{source['name']} — копия", source.get("description") or "", source["draft"]
    )


@automations_router.post("/runbooks/{runbook_id}/publish")
def publish_automation_runbook(runbook_id: str, payload: AutomationPublishRequest) -> dict[str, Any]:
    try:
        result = host.get_automation_service().publish(runbook_id, payload.confirm_name)
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
        return host.get_automation_service().start_run(
            runbook_id, dry_run=payload.dry_run,
            idempotency_key=idempotency_key if isinstance(idempotency_key, str) else None,
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@automations_router.get("/schedules")
def automation_schedules() -> dict[str, Any]:
    return {"rows": host.AUTOMATION_REPOSITORY.list_schedules()}


@automations_router.post("/schedules", status_code=201)
def create_automation_schedule(payload: AutomationScheduleRequest) -> dict[str, Any]:
    if not host.AUTOMATION_REPOSITORY.get_version(payload.runbook_id):
        raise HTTPException(status_code=409, detail="Runbook must be published before scheduling.")
    try:
        next_run_at = host.get_automation_service().next_run(payload.cron_expression, payload.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return host.AUTOMATION_REPOSITORY.create_schedule(
        runbook_id=payload.runbook_id, name=payload.name, cron_expression=payload.cron_expression,
        timezone=payload.timezone, enabled=payload.enabled, next_run_at=next_run_at,
    )


@automations_router.put("/schedules/{schedule_id}")
def update_automation_schedule(schedule_id: str, payload: AutomationScheduleRequest) -> dict[str, Any]:
    try:
        next_run_at = host.get_automation_service().next_run(payload.cron_expression, payload.timezone)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = host.AUTOMATION_REPOSITORY.update_schedule(
        schedule_id, name=payload.name, cron_expression=payload.cron_expression,
        timezone=payload.timezone, enabled=payload.enabled, next_run_at=next_run_at,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return result


@automations_router.delete("/schedules/{schedule_id}")
def delete_automation_schedule(schedule_id: str) -> dict[str, Any]:
    if not host.AUTOMATION_REPOSITORY.delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"schedule_id": schedule_id, "deleted": True}


@automations_router.get("/runs")
def automation_runs(limit: int = 100) -> dict[str, Any]:
    return {"rows": host.AUTOMATION_REPOSITORY.list_runs(limit=max(1, min(limit, 500)))}


@automations_router.get("/runs/{run_id}")
def automation_run(run_id: str) -> dict[str, Any]:
    result = host.AUTOMATION_REPOSITORY.get_run(run_id)
    if not result:
        raise HTTPException(status_code=404, detail="Automation run not found.")
    return result


@automations_router.post("/runs/{run_id}/cancel")
def cancel_automation_run(run_id: str) -> dict[str, Any]:
    if not host.AUTOMATION_REPOSITORY.request_cancel(run_id):
        raise HTTPException(status_code=409, detail="Automation run is not active.")
    current = host.AUTOMATION_REPOSITORY.get_run(run_id)
    for step in (current or {}).get("steps") or []:
        child_id = step.get("child_operation_id")
        child = db.get_operation(child_id) if child_id else None
        if child and child.get("can_cancel"):
            host.cancel_operation(child_id)
            break
    return current or {"run_id": run_id, "status": "cancelling"}


@automations_router.post("/runs/{run_id}/retry", status_code=202)
def retry_automation_run(run_id: str) -> dict[str, Any]:
    source = host.AUTOMATION_REPOSITORY.get_run(run_id, include_steps=False)
    if not source:
        raise HTTPException(status_code=404, detail="Automation run not found.")
    return host.get_automation_service().start_run(source["runbook_id"], trigger_type="retry")


@notifications_router.get("")
def notifications(unread_only: bool = False, limit: int = 100) -> dict[str, Any]:
    return host.AUTOMATION_REPOSITORY.list_notifications(unread_only=unread_only, limit=max(1, min(limit, 500)))


@notifications_router.post("/{notification_id}/read")
def mark_notification_read(notification_id: str) -> dict[str, Any]:
    if not host.AUTOMATION_REPOSITORY.mark_notification_read(notification_id):
        raise HTTPException(status_code=404, detail="Notification not found.")
    return {"notification_id": notification_id, "is_read": True}
