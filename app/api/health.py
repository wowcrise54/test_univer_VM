from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

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


def _label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(*, database_ready: bool, mpvm_connected: bool, operations: dict | None) -> str:
    """Prometheus text exposition; contains counters only, never identifiers or secrets."""
    lines = [
        "# HELP mpvm_database_ready 1 when PostgreSQL is reachable and recovery has completed.",
        "# TYPE mpvm_database_ready gauge",
        f"mpvm_database_ready {int(database_ready)}",
        "# HELP mpvm_session_connected 1 when an MP VM session is established.",
        "# TYPE mpvm_session_connected gauge",
        f"mpvm_session_connected {int(mpvm_connected)}",
    ]
    if operations is not None:
        lines += [
            "# HELP mpvm_operations_active Operations that are queued or running.",
            "# TYPE mpvm_operations_active gauge",
            f"mpvm_operations_active {int(operations.get('active', 0))}",
            "# HELP mpvm_operations_attention Operations that failed or need operator attention.",
            "# TYPE mpvm_operations_attention gauge",
            f"mpvm_operations_attention {int(operations.get('attention', 0))}",
            "# HELP mpvm_operations Operations in the visible history by status.",
            "# TYPE mpvm_operations gauge",
        ]
        lines += [
            f'mpvm_operations{{status="{_label(status)}"}} {int(count)}'
            for status, count in sorted((operations.get("by_status") or {}).items())
        ]
        lines += [
            "# HELP mpvm_operations_by_kind Operations in the visible history by kind.",
            "# TYPE mpvm_operations_by_kind gauge",
        ]
        lines += [
            f'mpvm_operations_by_kind{{kind="{_label(kind)}"}} {int(count)}'
            for kind, count in sorted((operations.get("by_kind") or {}).items())
        ]
    return "\n".join(lines) + "\n"


@router.get("/api/metrics", include_in_schema=False)
def metrics(request: Request) -> PlainTextResponse:
    container = request.app.state.container
    expected = container.settings.metrics_token
    if not expected:
        raise HTTPException(404, detail="Not Found")
    scheme, _, supplied = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), expected.encode()):
        raise HTTPException(401, detail={"code": "METRICS_TOKEN_INVALID", "message": "Неверный токен метрик."})
    state = container.database_recovery.check()
    operations = None
    if state["ready"]:
        try:
            operations = container.repositories.operations.counters()
        except Exception:
            operations = None
    connected = bool(container.session.client and container.session.access_token)
    return PlainTextResponse(
        render_metrics(database_ready=bool(state["ready"]), mpvm_connected=connected, operations=operations),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
