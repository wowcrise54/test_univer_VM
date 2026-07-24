from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request

from .. import auth as app_auth
from ..services.vulnerabilities import VulnerabilityAnalyticsService

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

SeverityFilter = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
    "none",
    "empty",
    "unrated",
]
SourceFilter = Literal["os", "software", "docker"]
SortDirection = Literal["asc", "desc"]
TrendBucket = Literal["day", "week"]


def _service(request: Request) -> VulnerabilityAnalyticsService:
    return request.app.state.container.services.vulnerabilities


@router.get("/summary")
def vulnerability_summary(
    request: Request,
    q: Annotated[str | None, Query(max_length=500)] = None,
    host_q: Annotated[str | None, Query(max_length=500)] = None,
    severity: SeverityFilter | None = None,
    source: SourceFilter | None = None,
) -> dict:
    return _service(request).summary(q=q, host_q=host_q, severity=severity, source=source)


@router.get("/trending")
def trending_vulnerabilities(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> dict:
    return _service(request).trending(limit=limit)


@router.get("/trends")
def vulnerability_trends(
    request: Request,
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    bucket: TrendBucket = "day",
) -> dict:
    try:
        return _service(request).trends(from_at=from_at, to_at=to_at, bucket=bucket)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_RANGE", "message": str(exc)},
        ) from exc


@router.get("/hosts")
def vulnerability_hosts(
    request: Request,
    selector: Annotated[str, Query(min_length=1, max_length=2000)],
    host_q: Annotated[str | None, Query(max_length=500)] = None,
    severity: SeverityFilter | None = None,
    source: SourceFilter | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    sort_by: str | None = None,
    sort_dir: SortDirection | None = None,
) -> dict:
    try:
        result = _service(request).hosts(
            selector=selector,
            host_q=host_q,
            severity=severity,
            source=source,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
        user = getattr(request.state, "user", None) or {}
        permissions = set(
            user.get("permissions")
            or app_auth.BUILTIN_ROLE_PERMISSIONS.get(user.get("role"), ())
        )
        if "remediation.read" not in permissions:
            for row in result.get("rows", []):
                row.pop("remediation", None)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc


@router.get("")
def vulnerabilities(
    request: Request,
    q: Annotated[str | None, Query(max_length=500)] = None,
    host_q: Annotated[str | None, Query(max_length=500)] = None,
    severity: SeverityFilter | None = None,
    source: SourceFilter | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    sort_by: str | None = None,
    sort_dir: SortDirection | None = None,
) -> dict:
    try:
        return _service(request).list(
            q=q,
            host_q=host_q,
            severity=severity,
            source=source,
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"code": "INVALID_SORT", "message": str(exc)}) from exc
