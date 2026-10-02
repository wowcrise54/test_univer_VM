from __future__ import annotations

from typing import NoReturn
from uuid import UUID

import psycopg
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app import auth as app_auth

router = APIRouter(prefix="/api/scanner-task-folders", tags=["scanner-task-folders"])


class TaskFolderCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Task folder name cannot be empty.")
        return cleaned


class TaskFolderAssignmentsRequest(BaseModel):
    task_ids: list[str] = Field(min_length=1, max_length=2000)
    folder_id: UUID | None

    @field_validator("task_ids")
    @classmethod
    def clean_task_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not cleaned:
            raise ValueError("At least one task id is required.")
        return cleaned


def _service(request: Request):
    return request.app.state.container.services.scanner_task_folders


def _actor(request: Request) -> str | None:
    return getattr(request.state, "user", {}).get("username")


def _audit(request: Request, event_type: str, target_id: str | None, details: dict | None = None) -> None:
    app_auth.audit_event(
        request=request,
        user=getattr(request.state, "user", None),
        event_type=event_type,
        decision="allow",
        permission_key="tasks.manage",
        target_type="scanner_task_folder",
        target_id=target_id,
        details=details,
    )


def _raise_domain_error(exc: Exception) -> NoReturn:
    if isinstance(exc, LookupError):
        raise HTTPException(404, detail={"code": "TASK_FOLDER_NOT_FOUND", "message": str(exc)}) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(422, detail={"code": "INVALID_TASK_FOLDER", "message": str(exc)}) from exc
    if isinstance(exc, psycopg.errors.UniqueViolation):
        raise HTTPException(409, detail={"code": "TASK_FOLDER_NAME_EXISTS", "message": "A task folder with this name already exists."}) from exc
    raise exc


@router.get("")
def list_task_folders(request: Request) -> dict:
    return _service(request).list()


@router.post("", status_code=201)
def create_task_folder(request: Request, payload: TaskFolderCreateRequest) -> dict:
    try:
        folder = _service(request).create(payload.name, actor=_actor(request))
        _audit(request, "task_folder_created", folder["folder_id"], {"name": folder["name"]})
        return folder
    except Exception as exc:
        _raise_domain_error(exc)


@router.patch("/{folder_id}")
def rename_task_folder(request: Request, folder_id: UUID, payload: TaskFolderCreateRequest) -> dict:
    try:
        folder = _service(request).rename(str(folder_id), payload.name, actor=_actor(request))
        _audit(request, "task_folder_renamed", folder["folder_id"], {"name": folder["name"]})
        return folder
    except Exception as exc:
        _raise_domain_error(exc)


@router.delete("/{folder_id}")
def delete_task_folder(request: Request, folder_id: UUID) -> dict:
    try:
        _service(request).delete(str(folder_id), actor=_actor(request))
        _audit(request, "task_folder_deleted", str(folder_id))
        return {"deleted": True}
    except Exception as exc:
        _raise_domain_error(exc)


@router.put("/assignments")
def assign_tasks_to_folder(request: Request, payload: TaskFolderAssignmentsRequest) -> dict:
    try:
        _service(request).assign(
            payload.task_ids,
            str(payload.folder_id) if payload.folder_id else None,
            actor=_actor(request),
        )
        _audit(request, "task_folder_assignments_changed", str(payload.folder_id) if payload.folder_id else None,
               {"task_ids": payload.task_ids})
        return {"assigned": len(payload.task_ids), "folder_id": str(payload.folder_id) if payload.folder_id else None}
    except Exception as exc:
        _raise_domain_error(exc)
