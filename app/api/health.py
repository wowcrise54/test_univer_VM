from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["system"])


@router.get("/api/live")
def live() -> dict[str, bool]:
    return {"ok": True}


@router.get("/api/ready")
def ready(request: Request) -> JSONResponse:
    container = request.app.state.container
    state = container.database_recovery.check()
    connected = bool(container.session.client and container.session.access_token)
    return JSONResponse(
        status_code=200 if state["ready"] else 503,
        content={**state, "mpvm": "ok" if connected else "degraded"},
    )
