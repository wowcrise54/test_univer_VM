from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from .. import auth as app_auth
from ..services import mcp_tokens as service

router = APIRouter(prefix="/api/auth/mcp-tokens", tags=["application-auth"])


class McpTokenCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=100)
    # Defaults to the administrator who issues the token.
    owner_user_id: int | None = Field(default=None, ge=1)
    scopes: list[str] = Field(min_length=1, max_length=len(service.MCP_SCOPES))
    expires_in_days: int = Field(default=service.DEFAULT_EXPIRES_IN_DAYS, ge=1, le=service.MAX_EXPIRES_IN_DAYS)
    ip_allowlist: list[str] = Field(default_factory=list, max_length=service.MAX_IP_ALLOWLIST)


class McpTokenRotateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    # How long the old token keeps working so clients can switch; 0 revokes it at once.
    grace_hours: int = Field(default=24, ge=0, le=720)
    expires_in_days: int = Field(default=service.DEFAULT_EXPIRES_IN_DAYS, ge=1, le=service.MAX_EXPIRES_IN_DAYS)


def _audit(request: Request, event_type: str, token: dict[str, Any], details: dict[str, Any] | None = None) -> None:
    app_auth.audit_event(
        request=request, user=request.state.user, event_type=event_type, decision="allow",
        permission_key="security.mcp_tokens.manage", target_type="mcp_token", target_id=token["token_id"],
        details={"name": token["name"], "owner": token["owner"]["username"], "scopes": token["scopes"], **(details or {})},
    )


@router.get("")
def list_mcp_tokens() -> dict[str, Any]:
    return service.list_tokens()


@router.post("", status_code=201)
def create_mcp_token(payload: McpTokenCreateRequest, request: Request) -> dict[str, Any]:
    actor = request.state.user
    token = service.create_token(
        name=payload.name,
        owner_user_id=payload.owner_user_id or actor["id"],
        scopes=payload.scopes,
        ip_allowlist=payload.ip_allowlist,
        expires_in_days=payload.expires_in_days,
        actor=actor,
    )
    _audit(request, "mcp_token_created", token, {"expires_at": token["expires_at"], "ip_allowlist": token["ip_allowlist"]})
    return token


@router.post("/{token_id}/rotate", status_code=201)
def rotate_mcp_token(token_id: int, payload: McpTokenRotateRequest, request: Request) -> dict[str, Any]:
    token = service.rotate_token(
        token_id, actor=request.state.user, grace_hours=payload.grace_hours, expires_in_days=payload.expires_in_days
    )
    _audit(request, "mcp_token_rotated", token, {"replaced": token["replaced_token_id"], "grace_hours": payload.grace_hours})
    return token


@router.post("/{token_id}/revoke")
def revoke_mcp_token(token_id: int, request: Request) -> dict[str, Any]:
    token = service.revoke_token(token_id, actor=request.state.user)
    _audit(request, "mcp_token_revoked", token)
    return token
