from __future__ import annotations

from typing import Any

import requests
from fastapi import BackgroundTasks

from ..mpvm.common import http_error, simplify_named_items
from ..mpvm_client import AuthConfig, MpVmApiError, build_default_token_url, normalize_url
from ..services.main_host import host
from .routers import session_router
from .schemas import ConnectionRequest


@session_router.post("/api/session/connect")
def connect_session(payload: ConnectionRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    try:
        api_url = normalize_url(payload.api_url)
        token_url = normalize_url(payload.token_url) if payload.token_url else build_default_token_url(api_url)
        auth = AuthConfig(
            api_url=api_url,
            token_url=token_url,
            username=payload.username,
            password=payload.password,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            scope=payload.scope,
            access_token=payload.access_token,
            verify_tls=payload.verify_tls,
            timeout=payload.timeout,
        )
        client = host.MpVmClient(auth)
        access_token = client.ensure_access_token()
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc

    host.SESSION.client = client
    host.SESSION.access_token = access_token
    host.SESSION.api_url = api_url
    host.SESSION.token_url = token_url
    host.SESSION.username = payload.username
    host.SESSION.verify_tls = payload.verify_tls
    host.MPVM_ENV_CONNECT_RETRY_AFTER = 0.0
    host.MPVM_ENV_CONNECT_ERROR = None
    # Returning the authenticated session must not wait for stale scan recovery.
    # Recovery is queued after the HTTP response and uses its own bounded executor.
    background_tasks.add_task(host.resume_connected_workflows)
    return {
        "connected": True,
        "api_url": api_url,
        "token_url": token_url,
        "username": payload.username,
        "verify_tls": payload.verify_tls,
    }


@session_router.post("/api/session/disconnect")
def disconnect_session() -> dict[str, Any]:
    host.SESSION.client = None
    host.SESSION.access_token = None
    host.SESSION.api_url = None
    host.SESSION.token_url = None
    host.SESSION.username = None
    host.MPVM_ENV_CONNECT_RETRY_AFTER = 0.0
    return {"connected": False}


@session_router.get("/api/session")
def session_info() -> dict[str, Any]:
    connected = host.mpvm_session_connected()
    return {
        "connected": connected,
        "api_url": host.SESSION.api_url,
        "token_url": host.SESSION.token_url,
        "username": host.SESSION.username,
        "verify_tls": host.SESSION.verify_tls,
        "env_connect_error": None if connected else host.MPVM_ENV_CONNECT_ERROR,
    }


@session_router.get("/api/mpvm/lookups")
def mpvm_lookups() -> dict[str, Any]:
    client, token = host.require_mpvm()
    try:
        return {
            "credentials": simplify_named_items(client.list_credentials(token)),
            "scopes": simplify_named_items(client.list_scopes(token)),
            "scanner_profiles": simplify_named_items(client.list_scanner_profiles(token)),
            "agents": client.list_scanner_agents(token),
        }
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc
