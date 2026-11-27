from __future__ import annotations

import logging
import time

import psycopg
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import auth as app_auth
from .. import db
from ..diagnostics import (
    capture_http_traffic,
    debug_mode_enabled,
    diagnostic_context,
    diagnostics_payload_limit,
    log_event,
    new_trace_id,
    normalize_correlation_id,
    parse_http_body,
    redact,
)
from ..services.main_host import host


def auth_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": {"code": code, "message": message, "component": "auth", "retryable": False}},
    )


async def application_auth_middleware(request: Request, call_next):
    path = request.url.path
    # SameSite=strict still sends the cookie from sibling subdomains, so only
    # same-origin (or user-initiated "none") browser mutations are accepted,
    # plus origins explicitly listed in MPVM_CORS_ALLOWED_ORIGINS.
    if (
        request.method not in {"GET", "HEAD", "OPTIONS"}
        and request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}
        and (request.headers.get("origin") or "").rstrip("/") not in host.SETTINGS.cors_origins
    ):
        return auth_error(403, "CROSS_SITE_REQUEST", "Межсайтовый запрос отклонён.")
    if not path.startswith("/api/") or path in host.PUBLIC_API_PATHS or request.method == "OPTIONS":
        return await call_next(request)
    try:
        # Session lookup is blocking SQL: keep it off the event loop.
        user = await run_in_threadpool(app_auth.get_session_user, request.cookies.get(app_auth.COOKIE_NAME))
    except psycopg.Error:
        return auth_error(503, "AUTH_DATABASE_UNAVAILABLE", "Авторизация временно недоступна.")
    if not user:
        return auth_error(401, "AUTH_REQUIRED", "Войдите в приложение.")
    request.state.user = user
    if path in {"/api/auth/me", "/api/auth/logout"}:
        return await call_next(request)
    from .authorization import request_permission

    permission = request_permission(request)
    effective = app_auth.effective_permissions(user)
    if permission and permission not in effective:
        await run_in_threadpool(
            app_auth.audit_event,
            request=request,
            user=user,
            event_type="access",
            decision="deny",
            permission_key=permission,
            target_type="api",
            target_id=path,
        )
        return auth_error(403, "PERMISSION_DENIED", f"Недостаточно прав: {permission}.")
    response = await call_next(request)
    if permission in host.AUDITED_PERMISSIONS and response.status_code < 400:
        await run_in_threadpool(
            app_auth.audit_event,
            request=request,
            user=user,
            event_type="critical_action",
            decision="allow",
            permission_key=permission,
            target_type="api",
            target_id=path,
        )
    return response


DEBUG_BODY_READ_CAP = 16 * 1024 * 1024


def _is_capturable_body(content_type: str) -> bool:
    """Only structured text is worth recording; uploads, HTML, JS and streams are not."""
    kind = content_type.lower()
    return any(marker in kind for marker in ("json", "xml", "x-www-form-urlencoded")) or kind.startswith("text/plain")


def _content_length(headers) -> int | None:
    value = headers.get("content-length")
    return int(value) if value and value.isdigit() else None


async def _capture_inbound_request(request: Request, trace_id: str, request_id: str) -> None:
    content_type = request.headers.get("content-type", "")
    length = _content_length(request.headers)
    payload = None
    skipped = None
    if length == 0 or (length is None and request.method in {"GET", "HEAD", "OPTIONS"}):
        skipped = "empty"
    elif not _is_capturable_body(content_type):
        skipped = "non_text_content_type"
    elif length is not None and length > DEBUG_BODY_READ_CAP:
        skipped = "too_large"
    else:
        payload = parse_http_body(await request.body(), content_type)
    capture_http_traffic(
        "http.inbound.request",
        payload=payload,
        headers=request.headers,
        body_skipped=skipped,
        trace_id=trace_id,
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        query=redact(dict(request.query_params)),
        client=request.client.host if request.client else None,
        content_type=content_type or None,
        content_length=length,
    )


def _capture_inbound_response(
    response, request: Request, trace_id: str, request_id: str, started: float
) -> None:
    """Record the response; the body is tapped from the stream without buffering it all."""
    content_type = response.headers.get("content-type", "")
    base = {
        "trace_id": trace_id,
        "request_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "content_type": content_type or None,
    }
    iterator = getattr(response, "body_iterator", None)
    if iterator is None or response.headers.get("content-encoding") or not _is_capturable_body(content_type):
        capture_http_traffic(
            "http.inbound.response",
            headers=response.headers,
            body_skipped="non_text_content_type",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            **base,
        )
        return
    limit = diagnostics_payload_limit()
    buffer = bytearray()
    state = {"total": 0}

    async def tap():
        try:
            async for chunk in iterator:
                data = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
                state["total"] += len(data)
                if len(buffer) <= limit:
                    buffer.extend(data[: limit + 1 - len(buffer)])
                yield chunk
        finally:
            try:
                truncated = state["total"] > limit
                capture_http_traffic(
                    "http.inbound.response",
                    payload=parse_http_body(bytes(buffer[:limit]), content_type) if not truncated
                    else bytes(buffer[:limit]).decode("utf-8", errors="replace"),
                    headers=response.headers,
                    duration_ms=round((time.perf_counter() - started) * 1000, 2),
                    response_bytes=state["total"],
                    **base,
                )
            except Exception:
                host.log_exception("app", "debug.capture.failed", direction="response")

    response.body_iterator = tap()


async def diagnostic_http_middleware(request: Request, call_next):
    trace_id = normalize_correlation_id(request.headers.get("x-trace-id")) or new_trace_id()
    request_id = normalize_correlation_id(request.headers.get("x-request-id")) or new_trace_id()
    started = time.perf_counter()
    request.state.trace_id = trace_id
    request.state.request_id = request_id
    with diagnostic_context(trace_id=trace_id, request_id=request_id):
        log_event(
            "app",
            "api.request.started",
            level=logging.DEBUG,
            method=request.method,
            path=request.url.path,
            query=redact(dict(request.query_params)),
        )
        debug_mode = debug_mode_enabled()
        if debug_mode:
            try:
                await _capture_inbound_request(request, trace_id, request_id)
            except Exception:  # Debug capture must never break the request itself.
                host.log_exception("app", "debug.capture.failed", direction="request")
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            host.UVICORN_LOGGER.exception(
                "api.request.failed method=%s path=%s duration_ms=%.2f trace_id=%s request_id=%s",
                request.method,
                request.url.path,
                duration_ms,
                trace_id,
                request_id,
            )
            host.log_exception(
                "app",
                "api.request.failed",
                method=request.method,
                path=request.url.path,
                duration_ms=duration_ms,
            )
            raise
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f'app;dur={duration_ms:.2f}'
        if debug_mode:
            try:
                _capture_inbound_response(response, request, trace_id, request_id, started)
            except Exception:
                host.log_exception("app", "debug.capture.failed", direction="response")
        size_header = response.headers.get("content-length")
        response_size = int(size_header) if size_header and size_header.isdigit() else None
        log_event(
            "app",
            "api.response",
            level=logging.INFO if response.status_code < 500 else logging.ERROR,
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            handler_and_serialization_ms=duration_ms,
            response_bytes=response_size,
            content_encoding=response.headers.get("content-encoding"),
            etag=response.headers.get("etag"),
            server_timing=response.headers.get("server-timing"),
        )
        host.UVICORN_LOGGER.info(
            "api.response method=%s path=%s status=%s duration_ms=%.2f trace_id=%s request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            trace_id,
            request_id,
        )
        return response


def error_component(path: str) -> str:
    if path.startswith("/api/session") or path.startswith("/api/mpvm"):
        return "mpvm"
    if path.startswith("/api/asset-cards"):
        return "asset_cards"
    if path.startswith("/api/vulnerability-passports"):
        return "vulnerability_passports"
    if path.startswith("/api/vulnerabilities"):
        return "vulnerabilities"
    if path.startswith("/api/scanner-tasks"):
        return "scanner_tasks"
    if path.startswith("/api/operations"):
        return "operations"
    return "application"


def operator_error_message(status_code: int, component: str, message: str) -> str:
    if status_code == 503:
        return "Локальная база данных недоступна. Проверьте PostgreSQL и повторите действие."
    if status_code == 502:
        return "MP VM не ответил на запрос. Проверьте подключение и повторите действие."
    if status_code == 409:
        return "Операция конфликтует с уже запущенной. Откройте центр операций для подробностей."
    if status_code == 404:
        return "Запрошенный объект не найден или уже был удалён."
    if status_code == 422:
        return "Проверьте заполненные поля и параметры запроса."
    return message or f"Ошибка компонента {component}."


def structured_http_error(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    message = str(detail.get("message") or detail.get("operator_message") or "Request failed")
    component = str(detail.get("component") or error_component(request.url.path))
    trace_id = getattr(request.state, "trace_id", None) or host.current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    payload = {
        "code": str(detail.get("code") or f"HTTP_{exc.status_code}"),
        "message": message,
        "operator_message": str(detail.get("operator_message") or operator_error_message(exc.status_code, component, message)),
        "component": component,
        "retryable": bool(detail.get("retryable", exc.status_code in {409, 429, 502, 503, 504})),
        "trace_id": trace_id,
        "request_id": request_id,
        "context": detail.get("context") or {key: value for key, value in detail.items() if key not in {"code", "message", "operator_message", "component", "retryable"}},
    }
    return JSONResponse(status_code=exc.status_code, content={"detail": payload}, headers=exc.headers)


def structured_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None) or host.current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=422,
        content={"detail": {
            "code": "VALIDATION_FAILED",
            "message": "Request validation failed.",
            "operator_message": "Проверьте заполненные поля и параметры запроса.",
            "component": error_component(request.url.path),
            "retryable": False,
            "trace_id": trace_id,
            "request_id": request_id,
            "context": {"fields": exc.errors()},
        }},
    )


def database_error_handler(request: Request, exc: psycopg.Error) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None) or host.current_trace_id()
    request_id = getattr(request.state, "request_id", None)
    programming_error = isinstance(exc, psycopg.ProgrammingError)
    status_code = 500 if programming_error else 503
    host.UVICORN_LOGGER.error(
        "api.database.failed status=%s method=%s path=%s trace_id=%s request_id=%s",
        status_code,
        request.method,
        request.url.path,
        trace_id,
        request_id,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    host.log_exception(
        "database",
        "api.database.query_failed" if programming_error else "api.database.failed",
        method=request.method,
        path=request.url.path,
        database=db.database_label(),
    )
    if programming_error:
        return JSONResponse(
            status_code=status_code,
            content={
                "detail": {
                    "code": "INTERNAL_DATABASE_QUERY_ERROR",
                    "message": "An internal database query failed.",
                    "operator_message": "Внутренняя ошибка запроса приложения к БД. PostgreSQL доступна; передайте журнал ошибки администратору.",
                    "component": "application",
                    "retryable": False,
                    "trace_id": trace_id,
                    "request_id": request_id,
                    "context": {},
                }
            },
        )
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": {
                "code": "DATABASE_UNAVAILABLE",
                "message": "Database is unavailable.",
                "operator_message": "Локальная база данных недоступна. Проверьте PostgreSQL и повторите действие.",
                "component": "database",
                "retryable": True,
                "trace_id": trace_id,
                "request_id": request_id,
                "context": {},
            }
        },
    )
