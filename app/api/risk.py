from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter(tags=["risk"])


class ContextValues(BaseModel):
    criticality: Literal["critical", "high", "medium", "low"] | None = None
    environment: Literal["production", "test", "development"] | None = None
    exposure: Literal["external", "internal", "isolated"] | None = None
    owner: str | None = Field(default=None, max_length=200)
    tags: list[str] | None = Field(default=None, max_length=50)


class ContextUpdate(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=500)
    values: ContextValues


class ContextCsvImport(BaseModel):
    csv_text: str = Field(min_length=1, max_length=5_000_000)


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    case_ids: list[str] = Field(min_length=1, max_length=500)
    assignee: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    comment: str | None = Field(default=None, max_length=4000)


class CampaignUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    assignee: str | None = Field(default=None, max_length=200)
    due_at: datetime | None = None
    comment: str | None = Field(default=None, max_length=4000)
    status: Literal["draft", "active", "completed", "cancelled"] | None = None


def service(request: Request):
    return request.app.state.container.services.risk


def actor(request: Request) -> str | None:
    return getattr(request.state, "user", {}).get("username")


@router.patch("/api/assets/context")
def update_context(request: Request, payload: ContextUpdate) -> dict:
    try:
        return service(request).set_contexts(
            payload.asset_ids, payload.values.model_dump(exclude_unset=True), actor(request)
        )
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "INVALID_ASSET_CONTEXT", "message": str(exc)}) from exc


@router.post("/api/assets/context/import")
def import_context(request: Request, payload: ContextCsvImport) -> dict:
    return service(request).import_contexts(payload.csv_text, actor(request))


@router.get("/api/risk/queue")
def risk_queue(
    request: Request,
    level: Literal["urgent", "high", "medium", "low"] | None = None,
    owner: Annotated[str | None, Query(max_length=200)] = None,
    environment: Literal["production", "test", "development"] | None = None,
    criticality: Literal["critical", "high", "medium", "low"] | None = None,
    exposure: Literal["external", "internal", "isolated"] | None = None,
    tag: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    return service(request).queue(
        level=level,
        owner=owner,
        environment=environment,
        criticality=criticality,
        exposure=exposure,
        tag=tag,
        limit=limit,
        offset=offset,
    )


@router.get("/api/risk/summary")
def risk_summary(request: Request) -> dict:
    return service(request).summary()


@router.post("/api/remediation/campaigns", status_code=201)
def create_campaign(request: Request, payload: CampaignCreate) -> dict:
    return service(request).create_campaign(payload.model_dump(mode="json"), actor(request))


@router.get("/api/remediation/campaigns")
def list_campaigns(request: Request) -> dict:
    return service(request).list_campaigns()


@router.get("/api/remediation/campaigns/{campaign_id}")
def get_campaign(request: Request, campaign_id: str) -> dict:
    result = service(request).get_campaign(campaign_id)
    if not result:
        raise HTTPException(404, detail={"code": "CAMPAIGN_NOT_FOUND", "message": "Campaign not found."})
    return result


@router.patch("/api/remediation/campaigns/{campaign_id}")
def update_campaign(request: Request, campaign_id: str, payload: CampaignUpdate) -> dict:
    result = service(request).update_campaign(
        campaign_id, payload.model_dump(exclude_unset=True, mode="json"), actor(request)
    )
    if not result:
        raise HTTPException(404, detail={"code": "CAMPAIGN_NOT_FOUND", "message": "Campaign not found."})
    return result


@router.post("/api/remediation/campaigns/{campaign_id}/verify", status_code=202)
def verify_campaign(
    request: Request, campaign_id: str,
    idempotency_key: str | None = Header(default=None, alias="X-Idempotency-Key"),
) -> dict:
    permissions = set(getattr(request.state, "user", {}).get("permissions") or [])
    required = {"risk.manage", "remediation.manage", "tasks.execute"}
    missing = sorted(required - permissions)
    if missing:
        raise HTTPException(403, detail={"code": "PERMISSION_DENIED", "message": f"Missing permissions: {', '.join(missing)}"})
    workflow, replay, asset_ids = request.app.state.container.services.vm_workflows.start_verification(
        campaign_id=campaign_id, options={}, actor=actor(request), idempotency_key=idempotency_key,
    )
    if not workflow:
        raise HTTPException(404, detail={"code": "CAMPAIGN_NOT_FOUND", "message": "Campaign not found."})
    return {
        "campaign_id": campaign_id, "asset_ids": asset_ids, "workflow_id": workflow["workflow_id"],
        "operation_id": workflow.get("operation_id"), "status": workflow["status"],
        "workflow": workflow, "idempotent_replay": replay,
    }
