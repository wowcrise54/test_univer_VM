from __future__ import annotations

from typing import Annotated, NoReturn
from uuid import UUID

import psycopg
import requests
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app import auth as app_auth
from app.mpvm_client import MpVmApiError

from ..domain.errors import DomainError
from ..services.team_tasks import TeamTaskPersistError
from . import scanner_task_runs

router = APIRouter(prefix="/api/team-tasks", tags=["team-tasks"])


class TeamTaskCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    preset_id: UUID
    asset_group_ids: list[str] = Field(default_factory=list, max_length=100)
    targets: list[str] = Field(default_factory=list, max_length=1000)
    name: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    start_now: bool = False


class TeamTaskUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    asset_group_ids: list[str] = Field(default_factory=list, max_length=100)
    targets: list[str] = Field(default_factory=list, max_length=1000)
    name: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=2000)


def _service(request: Request):
    return request.app.state.container.services.team_tasks


def _user(request: Request) -> dict:
    return getattr(request.state, "user", None) or {}


def _unrestricted(request: Request) -> bool:
    """Preset managers supervise every team; engineers see only their own team."""
    return "task_presets.manage" in app_auth.effective_permissions(_user(request))


def _audit(request: Request, event_type: str, target_id: str | None, details: dict | None = None) -> None:
    app_auth.audit_event(
        request=request,
        user=getattr(request.state, "user", None),
        event_type=event_type,
        decision="allow",
        permission_key="tasks.team",
        target_type="scanner_task",
        target_id=target_id,
        details=details,
    )


def _raise_domain_error(exc: Exception) -> NoReturn:
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, TeamTaskPersistError):
        raise HTTPException(500, detail={
            "code": "TEAM_TASK_NOT_PERSISTED", "message": str(exc), "context": {"mp_task_id": exc.mp_task_id},
        }) from exc
    if isinstance(exc, LookupError):
        raise HTTPException(404, detail={"code": "TEAM_TASK_NOT_FOUND", "message": str(exc)}) from exc
    if isinstance(exc, DomainError):
        raise HTTPException(exc.status_code, detail={"code": exc.code, "message": exc.message, "context": exc.context}) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(422, detail={"code": "INVALID_TEAM_TASK", "message": str(exc)}) from exc
    if isinstance(exc, psycopg.errors.UniqueViolation):
        raise HTTPException(409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT",
                                         "message": "Запрос с этим ключом уже выполняется."}) from exc
    if isinstance(exc, MpVmApiError | requests.RequestException):
        raise HTTPException(502, detail={"code": "MPVM_REQUEST_FAILED", "message": str(exc)[:500]}) from exc
    raise exc


def _groups(task: dict) -> list:
    return [group.get("id") for group in task.get("preset_asset_groups") or []]


@router.get("")
def list_team_tasks(request: Request) -> dict:
    return _service(request).list(_user(request), unrestricted=_unrestricted(request))


@router.post("", status_code=201)
def create_team_task(
    request: Request,
    payload: TeamTaskCreateRequest,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    service = _service(request)
    try:
        created = service.create(
            _user(request), preset_id=str(payload.preset_id), asset_group_ids=payload.asset_group_ids,
            name=payload.name, description=payload.description, unrestricted=_unrestricted(request),
            idempotency_key=idempotency_key, targets=payload.targets,
        )
        task = created["task"]
        if not created["idempotent_replay"]:
            _audit(request, "team_task_created", task["mp_task_id"],
                   {"preset_id": task.get("preset_id"), "asset_group_ids": _groups(task),
                    "targets": task.get("preset_targets") or []})
        if payload.start_now:
            created["start"] = service.start(
                task["mp_task_id"], _user(request), unrestricted=True,
                idempotency_key=f"{idempotency_key}:start" if idempotency_key else None,
            )
            _audit(request, "team_task_started", task["mp_task_id"], {"preset_id": task.get("preset_id")})
        return created
    except Exception as exc:
        _raise_domain_error(exc)


@router.put("/{task_id}")
def update_team_task(request: Request, task_id: str, payload: TeamTaskUpdateRequest) -> dict:
    try:
        task = _service(request).update(
            task_id, _user(request), asset_group_ids=payload.asset_group_ids, name=payload.name,
            description=payload.description, unrestricted=_unrestricted(request), targets=payload.targets,
        )
        _audit(request, "team_task_updated", task_id, {"preset_id": task.get("preset_id"),
                                                       "asset_group_ids": _groups(task),
                                                       "targets": task.get("preset_targets") or []})
        return task
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/{task_id}/start", status_code=202)
def start_team_task(
    request: Request,
    task_id: str,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    try:
        result = _service(request).start(
            task_id, _user(request), idempotency_key=idempotency_key, unrestricted=_unrestricted(request),
        )
        _audit(request, "team_task_started", task_id, {"status": result.get("status")})
        return result
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/{task_id}/stop")
def stop_team_task(request: Request, task_id: str) -> dict:
    try:
        result = _service(request).stop(task_id, _user(request), unrestricted=_unrestricted(request))
        _audit(request, "team_task_stopped", task_id)
        return result
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/{task_id}/delete")
def delete_team_task(
    request: Request,
    task_id: str,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    try:
        result = _service(request).delete(
            task_id, _user(request), idempotency_key=idempotency_key, unrestricted=_unrestricted(request),
        )
        _audit(request, "team_task_deleted", task_id)
        return result
    except Exception as exc:
        _raise_domain_error(exc)


def _require_team_task(request: Request, task_id: str) -> None:
    try:
        _service(request).get(task_id, _user(request), unrestricted=_unrestricted(request))
    except Exception as exc:
        _raise_domain_error(exc)


@router.get("/{task_id}/runs")
def team_task_runs(
    request: Request,
    task_id: str,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> dict:
    _require_team_task(request, task_id)
    return scanner_task_runs.scanner_task_runs(request, task_id, offset, limit)


@router.get("/{task_id}/runs/{run_id}/jobs")
def team_task_run_jobs(request: Request, task_id: str, run_id: str) -> dict:
    _require_team_task(request, task_id)
    return scanner_task_runs.scanner_task_run_jobs(request, task_id, run_id)
