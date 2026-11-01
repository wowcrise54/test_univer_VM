from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import Response

from .. import auth as app_auth
from .. import db
from ..services.main_host import host
from .routers import auth_router


@auth_router.get("/bootstrap-status")
def auth_bootstrap_status() -> dict[str, Any]:
    with db.connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM app_users").fetchone()
        assert row is not None
        configured = int(row["count"] or 0) > 0
    return {"configured": configured}


@auth_router.post("/login")
def auth_login(payload: app_auth.LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    return app_auth.login(
        payload,
        request,
        response,
        hours=host.SETTINGS.auth_session_hours,
        secure=host.SETTINGS.auth_cookie_secure,
    )


@auth_router.post("/logout")
def auth_logout(request: Request, response: Response) -> dict[str, Any]:
    return app_auth.logout(request, response)


@auth_router.get("/me")
def auth_me(request: Request) -> dict[str, Any]:
    return {"authenticated": True, "user": request.state.user}


@auth_router.get("/users")
def auth_users() -> dict[str, Any]:
    return {"rows": app_auth.list_users()}


@auth_router.post("/users", status_code=201)
def auth_create_user(payload: app_auth.UserCreateRequest) -> dict[str, Any]:
    return app_auth.create_user(payload)


@auth_router.patch("/users/{user_id}")
def auth_update_user(user_id: int, payload: app_auth.UserUpdateRequest, request: Request) -> dict[str, Any]:
    return app_auth.update_user(user_id, payload, actor_id=request.state.user["id"])


@auth_router.delete("/users/{user_id}", status_code=204)
def auth_delete_user(user_id: int, request: Request) -> Response:
    deleted = app_auth.delete_user(user_id, actor_id=request.state.user["id"])
    # The row is gone, so keep who was deleted in the audit trail itself.
    app_auth.audit_event(
        request=request, user=request.state.user, event_type="user_deleted", decision="allow",
        permission_key="security.users.manage", target_type="user", target_id=str(user_id),
        details={"username": deleted["username"], "display_name": deleted["display_name"]},
    )
    return Response(status_code=204)


@auth_router.get("/permissions")
def auth_permissions() -> dict[str, Any]:
    return {"rows": app_auth.list_permissions()}


@auth_router.get("/roles")
def auth_roles() -> dict[str, Any]:
    return {"rows": app_auth.list_roles()}


@auth_router.post("/roles/clone", status_code=201)
def auth_clone_role(payload: app_auth.RoleCloneRequest) -> dict[str, Any]:
    return app_auth.clone_role(payload)


@auth_router.patch("/roles/{role_id}")
def auth_update_role(role_id: int, payload: app_auth.RoleUpdateRequest) -> dict[str, Any]:
    return app_auth.update_role(role_id, payload)


@auth_router.delete("/roles/{role_id}", status_code=204)
def auth_delete_role(role_id: int) -> Response:
    app_auth.delete_role(role_id)
    return Response(status_code=204)


@auth_router.get("/audit")
def auth_audit(limit: int = 200, offset: int = 0) -> dict[str, Any]:
    return app_auth.list_audit_events(limit=limit, offset=offset)
