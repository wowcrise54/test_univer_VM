from __future__ import annotations

from typing import Annotated

import psycopg
from fastapi import APIRouter, HTTPException, Query, Request

from .schemas import (
    AssetGroupCreateRequest,
    AssetGroupOverrideRequest,
    AssetGroupPreviewRequest,
    AssetGroupUpdateRequest,
)


router = APIRouter(prefix="/api/asset-groups", tags=["asset-groups"])


def _service(request: Request):
    return request.app.state.container.services.asset_groups


def _actor(request: Request) -> str | None:
    return getattr(request.state, "user", {}).get("username")


def _raise_domain_error(exc: Exception) -> None:
    if isinstance(exc, LookupError):
        raise HTTPException(404, detail={"code": "ASSET_GROUP_NOT_FOUND", "message": str(exc)}) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(422, detail={"code": "INVALID_ASSET_GROUP", "message": str(exc)}) from exc
    if isinstance(exc, psycopg.errors.UniqueViolation):
        raise HTTPException(409, detail={"code": "ASSET_GROUP_NAME_EXISTS", "message": "A group with this name already exists at this level."}) from exc
    raise exc


@router.get("/tree")
def tree(request: Request) -> dict:
    return _service(request).tree()


@router.get("")
def list_groups(request: Request) -> dict:
    return _service(request).tree()


@router.post("/preview")
def preview(request: Request, payload: AssetGroupPreviewRequest) -> dict:
    try:
        return _service(request).preview(payload.query, limit=payload.limit)
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("", status_code=201)
def create_group(request: Request, payload: AssetGroupCreateRequest) -> dict:
    try:
        return _service(request).create(actor=_actor(request), **payload.model_dump())
    except Exception as exc:
        _raise_domain_error(exc)


@router.get("/{group_id}")
def get_group(request: Request, group_id: str) -> dict:
    group = _service(request).get(group_id)
    if not group:
        raise HTTPException(404, detail={"code": "ASSET_GROUP_NOT_FOUND", "message": "Asset group not found."})
    return group


@router.patch("/{group_id}")
def update_group(request: Request, group_id: str, payload: AssetGroupUpdateRequest) -> dict:
    try:
        group = _service(request).update(group_id, payload.model_dump(exclude_unset=True))
        if not group:
            raise LookupError("Asset group not found.")
        return group
    except Exception as exc:
        _raise_domain_error(exc)


@router.post("/{group_id}/evaluate")
def evaluate_group(request: Request, group_id: str) -> dict:
    try:
        return _service(request).evaluate(group_id)
    except Exception as exc:
        _raise_domain_error(exc)


@router.get("/{group_id}/members")
def members(
    request: Request,
    group_id: str,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    try:
        return _service(request).members(group_id, limit=limit, offset=offset)
    except Exception as exc:
        _raise_domain_error(exc)


@router.put("/{group_id}/overrides/{asset_id}")
def set_override(request: Request, group_id: str, asset_id: str, payload: AssetGroupOverrideRequest) -> dict:
    try:
        return _service(request).set_override(group_id, asset_id, payload.action, actor=_actor(request))
    except Exception as exc:
        _raise_domain_error(exc)


@router.delete("/{group_id}/overrides/{asset_id}")
def delete_override(request: Request, group_id: str, asset_id: str) -> dict:
    return {"deleted": _service(request).delete_override(group_id, asset_id)}


@router.post("/{group_id}/archive")
def archive_group(request: Request, group_id: str) -> dict:
    if not _service(request).archive(group_id):
        raise HTTPException(404, detail={"code": "ASSET_GROUP_NOT_FOUND", "message": "Asset group not found."})
    return {"group_id": group_id, "archived": True}
