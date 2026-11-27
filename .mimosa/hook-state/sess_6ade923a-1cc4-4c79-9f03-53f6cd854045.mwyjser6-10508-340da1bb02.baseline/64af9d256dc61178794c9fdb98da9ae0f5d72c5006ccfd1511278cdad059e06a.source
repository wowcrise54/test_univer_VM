from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

from fastapi import HTTPException

from ..mpvm_client import AuthConfig, MpVmApiError, build_default_token_url, normalize_url
from .main_host import host

if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient


def configure_session_from_env(*, force: bool = False) -> None:
    api_url = os.getenv("MPVM_API_URL") or os.getenv("MP10_API_URL")
    if not api_url:
        return
    now = time.monotonic()
    if not force and now < host.MPVM_ENV_CONNECT_RETRY_AFTER:
        return
    if not force and host.SESSION.client is not None and host.SESSION.access_token is not None:
        return
    with host.MPVM_ENV_CONNECT_LOCK:
        now = time.monotonic()
        if not force and now < host.MPVM_ENV_CONNECT_RETRY_AFTER:
            return
        if not force and host.SESSION.client is not None and host.SESSION.access_token is not None:
            return
        _configure_session_from_env_unlocked()


def _configure_session_from_env_unlocked() -> None:
    api_url = os.getenv("MPVM_API_URL") or os.getenv("MP10_API_URL")
    if not api_url:
        return
    try:
        normalized_api_url = normalize_url(api_url)
        token_url = normalize_url(os.getenv("MPVM_TOKEN_URL") or os.getenv("MP10_TOKEN_URL")) if (
            os.getenv("MPVM_TOKEN_URL") or os.getenv("MP10_TOKEN_URL")
        ) else build_default_token_url(normalized_api_url)
        verify_tls_env = os.getenv("MPVM_VERIFY_TLS") or os.getenv("MP10_VERIFY_TLS")
        if verify_tls_env is not None:
            verify_tls = verify_tls_env.lower() in {"1", "true", "yes", "on"}
        else:
            verify_tls = (os.getenv("MPVM_INSECURE") or os.getenv("MP10_INSECURE") or "").lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }

        auth = AuthConfig(
            api_url=normalized_api_url,
            token_url=token_url,
            username=os.getenv("MPVM_USERNAME") or os.getenv("MP10_USERNAME"),
            password=os.getenv("MPVM_PASSWORD") or os.getenv("MP10_PASSWORD"),
            client_id=os.getenv("MPVM_CLIENT_ID") or os.getenv("MP10_CLIENT_ID") or "mpx",
            client_secret=os.getenv("MPVM_CLIENT_SECRET") or os.getenv("MP10_CLIENT_SECRET"),
            scope=os.getenv("MPVM_SCOPE") or os.getenv("MP10_SCOPE") or "authorization offline_access mpx.api ptkb.api",
            access_token=os.getenv("MPVM_ACCESS_TOKEN") or os.getenv("MP10_ACCESS_TOKEN"),
            verify_tls=verify_tls,
            timeout=float(os.getenv("MPVM_TIMEOUT") or os.getenv("MP10_TIMEOUT") or "120"),
        )
        client = host.MpVmClient(auth)
        host.SESSION.client = client
        host.SESSION.access_token = client.ensure_access_token()
        host.SESSION.api_url = normalized_api_url
        host.SESSION.token_url = token_url
        host.SESSION.username = auth.username
        host.SESSION.verify_tls = auth.verify_tls
        host.MPVM_ENV_CONNECT_RETRY_AFTER = 0.0
        host.MPVM_ENV_CONNECT_ERROR = None
    except Exception as exc:
        host.SESSION.client = None
        host.SESSION.access_token = None
        host.MPVM_ENV_CONNECT_RETRY_AFTER = time.monotonic() + host.MPVM_ENV_CONNECT_BACKOFF_SECONDS
        host.MPVM_ENV_CONNECT_ERROR = env_connect_error_message(exc)
        host.log_exception("mpvm", "session.env_connect.failed")


def env_connect_error_message(exc: Exception) -> str:
    message = str(exc).strip()
    if isinstance(exc, MpVmApiError) and message.startswith("Missing authentication fields:"):
        # Report only presence, never the value: the variable is fixed when the
        # container is created, so "not passed" usually means a stale container.
        token = os.environ.get("MPVM_ACCESS_TOKEN", os.environ.get("MP10_ACCESS_TOKEN"))
        if token is None:
            token_state = "не передана в контейнер"
        elif not token.strip():
            token_state = "передана, но пустая (проверьте environment: в compose-файле)"
        else:
            token_state = "задана"
        message += (
            f". MPVM_ACCESS_TOKEN: {token_state}."
            " Задайте в .env MPVM_ACCESS_TOKEN или MPVM_USERNAME, MPVM_PASSWORD и MPVM_CLIENT_SECRET,"
            " затем пересоздайте контейнер (docker compose up -d)."
        )
    elif not message:
        message = type(exc).__name__
    return message[:500]


def mpvm_session_connected() -> bool:
    if not host.SESSION.client or not host.SESSION.access_token:
        host.configure_session_from_env()
    return host.SESSION.client is not None and host.SESSION.access_token is not None


def require_mpvm() -> tuple[MpVmClient, str]:
    host.mpvm_session_connected()
    if not host.SESSION.client or not host.SESSION.access_token:
        raise HTTPException(status_code=409, detail="MP VM connection is not configured. Connect first.")
    return host.SESSION.client, host.SESSION.access_token
