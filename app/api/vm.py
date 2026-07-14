from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/vm", tags=["vm-workflows"])


class VmScanRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=200)
    options: dict[str, Any] = Field(default_factory=dict)


def _service(request: Request):
    return request.app.state.container.services.vm_workflows


def _actor(request: Request) -> str | None:
    return getattr(request.state, "user", {}).get("username")


def _require(request: Request, required: set[str]) -> None:
    permissions = set(getattr(request.state, "user", {}).get("permissions") or [])
    missing = sorted(required - permissions)
    if missing:
        raise HTTPException(403, detail={"code": "PERMISSION_DENIED", "message": f"Missing permissions: {', '.join(missing)}"})


@router.get("/overview")
def overview(request: Request) -> dict:
    _require(request, {"operations.read", "assets.read", "remediation.read", "risk.read"})
    return _service(request).overview()


@router.get("/workflows")
def list_workflows(
    request: Request, status: str | None = None, kind: Literal["scan", "verification"] | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50, offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    return _service(request).list(status=status, kind=kind, limit=limit, offset=offset)


@router.get("/workflows/{workflow_id}")
def get_workflow(request: Request, workflow_id: str) -> dict:
    result = _service(request).get(workflow_id)
    if not result:
        raise HTTPException(404, detail={"code": "VM_WORKFLOW_NOT_FOUND", "message": "VM workflow not found."})
    return result


@router.post("/workflows/scan", status_code=202)
def start_scan(
    request: Request, payload: VmScanRequest,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    try:
        workflow, replay = _service(request).start_scan(
            task_id=payload.task_id, options=payload.options, actor=_actor(request), idempotency_key=idempotency_key,
        )
    except ValueError as exc:
        raise HTTPException(409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT", "message": str(exc)}) from exc
    return {"workflow": workflow, "workflow_id": workflow["workflow_id"], "status": workflow["status"], "idempotent_replay": replay}


@router.post("/workflows/{workflow_id}/cancel")
def cancel_workflow(request: Request, workflow_id: str) -> dict:
    result = _service(request).cancel(workflow_id)
    if not result:
        raise HTTPException(404, detail={"code": "VM_WORKFLOW_NOT_FOUND", "message": "VM workflow not found."})
    return result


@router.post("/workflows/{workflow_id}/retry", status_code=202)
def retry_workflow(
    request: Request, workflow_id: str,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    result, replay = _service(request).retry(workflow_id, _actor(request), idempotency_key)
    if not result:
        raise HTTPException(409, detail={"code": "VM_WORKFLOW_NOT_RETRYABLE", "message": "VM workflow cannot be retried."})
    return {"workflow": result, "workflow_id": result["workflow_id"], "idempotent_replay": replay}
