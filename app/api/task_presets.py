from __future__ import annotations

from typing import Any, Literal, NoReturn
from uuid import UUID

import psycopg
import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app import auth as app_auth
from app.mpvm_client import MpVmApiError

from ..domain.errors import DomainError
from .schemas import DeniedScanSettings, StartScannerTaskRequest, TaskTriggerParameters

router = APIRouter(prefix="/api/task-presets", tags=["task-presets"])


class AssetGroupRef(BaseModel):
    model_config = {"extra": "forbid"}

    id: str = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=500)
    path: str | None = Field(default=None, max_length=2000)


class TaskPresetRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    os_family: Literal["windows", "linux"]
    scope_id: str = Field(min_length=1, max_length=200)
    profile_id: str = Field(min_length=1, max_length=200)
    credential_id: str | None = Field(default=None, max_length=200)
    credential_transport: Literal["windows", "ssh"] = "windows"
    agent_ids: list[str] = Field(default_factory=list, max_length=200)
    host_discovery_enabled: bool = False
    host_discovery_profile_id: str | None = Field(default=None, max_length=200)
    is_fqdn_priority: bool = True
    time_zone: str = Field(default="+05:00", pattern=r"^[+-]\d{2}:\d{2}$")
    trigger_parameters: TaskTriggerParameters | None = None
    denied_scan_settings: DeniedScanSettings | None = None
    start_options: StartScannerTaskRequest = Field(default_factory=StartScannerTaskRequest)
    allowed_asset_groups: list[AssetGroupRef] = Field(min_length=1, max_length=500)
    max_groups_per_task: int = Field(default=5, ge=1, le=100)
    max_active_tasks: int | None = Field(default=None, ge=1, le=100)
    name_prefix: str = Field(default="", max_length=60)
    role_ids: list[int] = Field(min_length=1, max_length=100)

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Preset name cannot be empty.")
        return cleaned

    def preset_values(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"role_ids", "expected_version"})


class TaskPresetUpdateRequest(TaskPresetRequest):
    expected_version: int = Field(ge=1)


class TaskPresetArchiveRequest(BaseModel):
    model_config = {"extra": "forbid"}

    expected_version: int = Field(ge=1)


def _service(request: Request):
    return request.app.state.container.services.task_presets


def _user(request: Request) -> dict:
    return getattr(request.state, "user", None) or {}


def _can_manage(request: Request) -> bool:
    return "task_presets.manage" in app_auth.effective_permissions(_user(request))


def _audit(request: Request, event_type: str, target_id: str | None, details: dict | None = None) -> None:
    app_auth.audit_event(
        request=request,
        user=getattr(request.state, "user", None),
        event_type=event_type,
        decision="allow",
        permission_key="task_presets.manage",
        target_type="scan_task_preset",
        target_id=target_id,
        details=details,
    )


def _raise_domain_error(exc: Exception) -> NoReturn:
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, LookupError):
        raise HTTPException(404, detail={"code": "TASK_PRESET_NOT_FOUND", "message": str(exc)}) from exc
    if isinstance(exc, DomainError):
        raise HTTPException(exc.status_code, detail={"code": exc.code, "message": exc.message, "context": exc.context}) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(422, detail={"code": "INVALID_TASK_PRESET", "message": str(exc)}) from exc
    if isinstance(exc, psycopg.errors.UniqueViolation):
        raise HTTPException(409, detail={"code": "TASK_PRESET_NAME_EXISTS",
                                         "message": "Активный пресет с таким названием уже существует."}) from exc
    if isinstance(exc, MpVmApiError | requests.RequestException):
        raise HTTPException(502, detail={"code": "MPVM_REQUEST_FAILED", "message": str(exc)[:500]}) from exc
    raise exc


def _summary(preset: dict) -> dict:
    return {
        "name": preset.get("name"), "os_family": preset.get("os_family"), "version": preset.get("version"),
        "role_ids": preset.get("role_ids"), "profile_id": preset.get("profile_id"),
        "credential_id": preset.get("credential_id"),
        "asset_group_ids": [group.get("id") for group in preset.get("allowed_asset_groups") or []],
    }


@router.get("")
def list_task_presets(request: Request, include_archived: bool = False) -> dict:
    return _service(request).list_for_user(_user(request), can_manage=_can_manage(request),
                                           include_archived=include_archived)


@router.get("/asset-groups")
def task_preset_asset_groups(request: Request) -> dict:
    try:
        return _service(request).asset_groups()
    except Exception as exc:
        _raise_domain_error(exc)


@router.get("/lookups")
def task_preset_lookups(request: Request) -> dict:
    try:
        return _service(request).lookups()
    except Exception as exc:
        _raise_domain_error(exc)


@router.get("/templates")
def task_preset_templates(request: Request) -> dict:
    return _service(request).templates()


@router.get("/{preset_id}")
def get_task_preset(request: Request, preset_id: UUID) -> dict:
    try:
        return _service(request).get_for_user(str(preset_id), _user(request), can_manage=_can_manage(request))
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("", status_code=201)
def create_task_preset(request: Request, payload: TaskPresetRequest) -> dict:
    try:
        preset = _service(request).create(payload.preset_values(), payload.role_ids, actor=_user(request).get("username"))
        _audit(request, "task_preset_created", preset["preset_id"], _summary(preset))
        return preset
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/from-task/{task_id}")
def task_preset_draft_from_task(request: Request, task_id: str) -> dict:
    task = request.app.state.container.services.tasks.get(task_id)
    if not task:
        raise HTTPException(404, detail={"code": "SCANNER_TASK_NOT_FOUND", "message": "Local scanner task not found."})
    return {"draft": _service(request).draft_from_task(task)}


@router.post("/from-template/{template_id}")
def task_preset_draft_from_template(request: Request, template_id: str) -> dict:
    try:
        return _service(request).draft_from_template(template_id)
    except Exception as exc:
        _raise_domain_error(exc)


@router.put("/{preset_id}")
def update_task_preset(request: Request, preset_id: UUID, payload: TaskPresetUpdateRequest) -> dict:
    try:
        preset = _service(request).update(
            str(preset_id), payload.preset_values(), payload.role_ids,
            expected_version=payload.expected_version, actor=_user(request).get("username"),
        )
        _audit(request, "task_preset_updated", preset["preset_id"], _summary(preset))
        return preset
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/{preset_id}/archive")
def archive_task_preset(request: Request, preset_id: UUID, payload: TaskPresetArchiveRequest) -> dict:
    try:
        preset = _service(request).archive(
            str(preset_id), expected_version=payload.expected_version, actor=_user(request).get("username"),
        )
        _audit(request, "task_preset_archived", preset["preset_id"], {"name": preset.get("name")})
        return preset
    except Exception as exc:
        _raise_domain_error(exc)
