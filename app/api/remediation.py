from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

Status = Literal["open", "in_progress", "risk_accepted", "false_positive", "resolved"]
Severity = Literal["critical", "high", "medium", "low", "unknown"]

router = APIRouter(prefix="/api/remediation", tags=["remediation"])
coverage_router = APIRouter(prefix="/api/coverage", tags=["coverage"])


class CaseUpdate(BaseModel):
    expected_version: int = Field(ge=1)
    status: Status | None = None
    assignee: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    risk_reason: str | None = Field(default=None, max_length=4000)
    risk_expires_at: datetime | None = None
    exception_reason: str | None = Field(default=None, max_length=4000)
    exception_expires_at: datetime | None = None
    comment: str | None = Field(default=None, max_length=4000)


class BulkCaseUpdate(BaseModel):
    case_ids: list[str] = Field(min_length=1, max_length=500)
    status: Status | None = None
    assignee: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    risk_reason: str | None = Field(default=None, max_length=4000)
    risk_expires_at: datetime | None = None
    exception_reason: str | None = Field(default=None, max_length=4000)
    exception_expires_at: datetime | None = None
    comment: str | None = Field(default=None, max_length=4000)


class PolicyUpdate(BaseModel):
    critical_days: int = Field(ge=1, le=3650)
    high_days: int = Field(ge=1, le=3650)
    medium_days: int = Field(ge=1, le=3650)
    low_days: int = Field(ge=1, le=3650)
    near_due_days: int = Field(ge=0, le=365)
    apply_to_open: bool = False


def _service(request: Request):
    return request.app.state.container.services.remediation


@router.get("/cases")
def list_cases(
    request: Request, q: Annotated[str | None, Query(max_length=500)] = None,
    status: Status | None = None, severity: Severity | None = None,
    assignee: Annotated[str | None, Query(max_length=200)] = None, overdue: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50, offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    return _service(request).list(q=q, status=status, severity=severity, assignee=assignee, overdue=overdue, limit=limit, offset=offset)


@router.get("/cases/{case_id}")
def get_case(request: Request, case_id: str) -> dict:
    item = _service(request).get(case_id)
    if not item:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": "Remediation case not found."})
    return item


@router.patch("/cases/{case_id}")
def update_case(request: Request, case_id: str, payload: CaseUpdate) -> dict:
    try:
        item = _service(request).update(case_id, payload.model_dump(exclude_unset=True, mode="json"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_CASE_UPDATE", "message": str(exc)}) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail={"code": "VERSION_CONFLICT", "message": "Case was changed by another operator."}) from exc
    if not item:
        raise HTTPException(status_code=404, detail={"code": "CASE_NOT_FOUND", "message": "Remediation case not found."})
    return item


@router.post("/cases/bulk-update")
def bulk_update(request: Request, payload: BulkCaseUpdate) -> dict:
    values = payload.model_dump(exclude={"case_ids"}, exclude_unset=True, mode="json")
    try:
        return _service(request).bulk_update(payload.case_ids, values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_CASE_UPDATE", "message": str(exc)}) from exc


@router.get("/summary")
def summary(request: Request) -> dict:
    return _service(request).summary()


@router.get("/policy")
def policy(request: Request) -> dict:
    return _service(request).policy()


@router.put("/policy")
def update_policy(request: Request, payload: PolicyUpdate) -> dict:
    values = payload.model_dump(exclude={"apply_to_open"})
    return _service(request).update_policy(values, apply_to_open=payload.apply_to_open)


@coverage_router.get("/summary")
def coverage_summary(request: Request) -> dict:
    return request.app.state.container.services.coverage.summary()


@coverage_router.get("/assets")
def coverage_assets(
    request: Request, q: Annotated[str | None, Query(max_length=500)] = None,
    issue: Literal["missing", "stale", "truncated", "failed"] | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50, offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    return request.app.state.container.services.coverage.list_assets(q=q, issue=issue, limit=limit, offset=offset)
