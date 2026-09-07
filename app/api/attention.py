from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request

router = APIRouter(tags=["operator"])


def _permissions(request: Request) -> set[str]:
    from .. import auth
    user = getattr(request.state, "user", {}) or {}
    return set(user.get("permissions") or auth.BUILTIN_ROLE_PERMISSIONS.get(user.get("role"), ()))


@router.get("/api/attention")
def attention(
    request: Request,
    type: Annotated[Literal["case", "operation", "coverage", "automation"] | None, Query()] = None,
    priority: Annotated[Literal["critical", "high", "medium", "low", "info"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: Annotated[str | None, Query(max_length=500)] = None,
    mine: bool = False,
) -> dict:
    if not getattr(request.app.state.container.settings, "attention_search_enabled", True):
        raise HTTPException(404, detail={"code": "FEATURE_DISABLED", "message": "Attention queue is disabled."})
    try:
        result = request.app.state.container.services.attention.attention(
            permissions=_permissions(request), limit=limit, cursor=cursor,
            owner=(getattr(request.state, "user", {}) or {}).get("username") if mine else None,
            kind=type, priority=priority,
        )
        return result
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "INVALID_CURSOR", "message": str(exc)}) from exc


@router.get("/api/search")
def search(
    request: Request,
    q: Annotated[str, Query(min_length=2, max_length=200)],
    type: Annotated[Literal["asset", "vulnerability", "task", "case", "operation"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=20)] = 20,
    cursor: Annotated[str | None, Query(max_length=500)] = None,
) -> dict:
    if not getattr(request.app.state.container.settings, "attention_search_enabled", True):
        raise HTTPException(404, detail={"code": "FEATURE_DISABLED", "message": "Search is disabled."})
    if len(q.strip()) < 2:
        raise HTTPException(422, detail={"code": "INVALID_QUERY", "message": "Search query must contain at least two characters."})
    try:
        return request.app.state.container.services.attention.search(
            query=q, kind=type, permissions=_permissions(request), limit=limit, cursor=cursor,
        )
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "INVALID_CURSOR", "message": str(exc)}) from exc
