from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException

from ..services.main_host import host
from .routers import assets_router


@assets_router.get("/api/assets")
def assets(
    q: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: Literal["asc", "desc"] | None = None,
) -> dict[str, Any]:
    try:
        return host.CONTAINER.services.assets.list_findings(q=q, severity=severity, limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@assets_router.get("/api/assets/summary")
def assets_summary() -> dict[str, Any]:
    return host.CONTAINER.services.assets.summary()
