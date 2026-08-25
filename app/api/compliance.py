from __future__ import annotations

from datetime import date
from io import BytesIO
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from .. import auth as app_auth
from ..domain.compliance import ComplianceScope
from ..reports.compliance import render_compliance_pdf, render_compliance_xlsx
from ..services.compliance import ComplianceService

dashboard_router = APIRouter(
    prefix="/api/vulnerabilities/compliance",
    tags=["vulnerability-compliance"],
)
report_router = APIRouter(
    prefix="/api/reports/vulnerabilities/compliance",
    tags=["vulnerability-compliance-reports"],
)


class ComplianceReportRequest(BaseModel):
    assessment_date: date | None = None
    asset_ids: list[str] | None = Field(default=None, max_length=5000)

    @field_validator("asset_ids")
    @classmethod
    def normalize_asset_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = list(dict.fromkeys(item.strip() for item in value if item.strip()))
        return normalized or None


def _service(request: Request) -> ComplianceService:
    return request.app.state.container.services.compliance


def _assessment_date(value: date | None) -> date:
    return value or date.today()


@dashboard_router.get("/{scope}/summary")
def compliance_summary(
    scope: ComplianceScope,
    request: Request,
    assessment_date: date | None = None,
) -> dict:
    return _service(request).summary(
        scope=scope,
        assessment_date=_assessment_date(assessment_date),
    )


def _page(
    method,
    *,
    scope,
    assessment_date,
    limit,
    offset,
    sort_by,
    sort_dir,
):
    try:
        return method(
            scope=scope,
            assessment_date=_assessment_date(assessment_date),
            limit=limit,
            offset=offset,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_COMPLIANCE_QUERY", "message": str(exc)},
        ) from exc


@dashboard_router.get("/{scope}/findings")
def compliance_findings(
    scope: ComplianceScope,
    request: Request,
    assessment_date: date | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    sort_by: str = "cvss_score",
    sort_dir: str = "desc",
) -> dict:
    return _page(
        _service(request).findings,
        scope=scope,
        assessment_date=assessment_date,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )


@dashboard_router.get("/{scope}/stale-assets")
def compliance_stale_assets(
    scope: ComplianceScope,
    request: Request,
    assessment_date: date | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    sort_by: str = "age_days",
    sort_dir: str = "desc",
) -> dict:
    return _page(
        _service(request).stale_assets,
        scope=scope,
        assessment_date=assessment_date,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )


@report_router.post("/{scope}/{report_format}")
def compliance_report(
    scope: ComplianceScope,
    report_format: Literal["pdf", "xlsx"],
    payload: ComplianceReportRequest,
    request: Request,
) -> StreamingResponse:
    assessment_date = _assessment_date(payload.assessment_date)
    dataset = _service(request).report_dataset(
        scope=scope,
        assessment_date=assessment_date,
        asset_ids=payload.asset_ids,
    )
    if report_format == "pdf":
        content = render_compliance_pdf(dataset)
        media_type = "application/pdf"
    else:
        content = render_compliance_xlsx(dataset)
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    filename = f"critical-vulnerabilities-{scope}-{assessment_date.isoformat()}.{report_format}"
    app_auth.audit_event(
        request=request,
        user=getattr(request.state, "user", None),
        event_type="report_download",
        decision="allow",
        permission_key="imports_exports.read",
        target_type="compliance_report",
        target_id=f"{scope}:{report_format}",
        details={
            "assessment_date": assessment_date.isoformat(),
            "selected_assets": len(payload.asset_ids or []),
            "critical_findings": len(dataset.findings),
            "stale_assets": len(dataset.stale_assets),
        },
    )
    return StreamingResponse(
        BytesIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
