"""Personal access tokens of the MCP endpoint.

Each client gets its own token: random, shown once, stored as a hash, scoped,
expiring and revocable. A request with a valid token runs in an application
session of the token owner that is capped to the token's read scopes, so RBAC
and audit stay in the backend and the token can never write.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
from starlette.types import Scope

from mcp_server.principal import TOKEN_PREFIX, AuthRejected, Principal

from .. import auth as app_auth
from .. import db
from ..repositories import mcp_tokens as repository

SESSION_MINUTES = 60
MAX_ACTIVE_TOKENS_PER_OWNER = 20
MAX_IP_ALLOWLIST = 20
DEFAULT_EXPIRES_IN_DAYS = 90
MAX_EXPIRES_IN_DAYS = 365
# Retry hint for a throttled caller; the limiters use a five-minute window.
THROTTLE_RETRY_AFTER_SECONDS = 300

# Scope -> (label, permissions). Every permission is a read permission: a token never gets a write one.
MCP_SCOPES: dict[str, tuple[str, tuple[str, ...]]] = {
    "vulnerabilities:read": ("Уязвимости, хосты и паспорта", ("assets.read", "asset_cards.read", "passports.read")),
    "remediation:read": ("Устранение и SLA", ("remediation.read",)),
    "operations:read": ("Задачи сканирования и операции", ("tasks.read", "operations.read")),
    "risk:read": ("Приоритеты риска", ("risk.read",)),
}

_PUBLIC_ID = re.compile(r"[0-9a-f]{12}")
# A real attacker cannot learn which part was wrong: both limiters count every failure.
_IP_LIMITER = app_auth.LoginLimiter(attempts=60, window_seconds=300)
_TOKEN_LIMITER = app_auth.LoginLimiter(attempts=8, window_seconds=300)
# Burns the same time as a real comparison when the token id is unknown.


def _now() -> datetime:
    return datetime.now(UTC)


def _hash_secret(secret: str) -> str:
    # The secret has 256 bits of entropy, so a fast hash is enough; scrypt would only slow every request.
    return hashlib.sha256(secret.encode()).hexdigest()


_DUMMY_HASH = _hash_secret("unknown-token")


def split_token(token: str) -> tuple[str, str] | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    public_id, separator, secret = token[len(TOKEN_PREFIX):].partition("_")
    if not separator or not _PUBLIC_ID.fullmatch(public_id) or not 20 <= len(secret) <= 100:
        return None
    return public_id, secret


def scope_catalog() -> list[dict[str, Any]]:
    return [
        {"key": key, "label": label, "permissions": list(permissions)}
        for key, (label, permissions) in MCP_SCOPES.items()
    ]


def scope_permissions(scopes: list[str] | tuple[str, ...]) -> list[str]:
    return sorted({permission for scope in scopes for permission in MCP_SCOPES[scope][1]})


def validate_scopes(scopes: list[str]) -> list[str]:
    unknown = sorted(set(scopes) - set(MCP_SCOPES))
    if unknown:
        raise HTTPException(422, detail={"code": "INVALID_SCOPES", "message": f"Неизвестные области доступа: {', '.join(unknown)}."})
    return sorted(set(scopes))


def validate_ip_allowlist(values: list[str]) -> list[str]:
    networks: list[str] = []
    for value in values:
        try:
            networks.append(str(ipaddress.ip_network(value.strip(), strict=False)))
        except ValueError as exc:
            raise HTTPException(422, detail={"code": "INVALID_IP_ALLOWLIST", "message": f"Некорректный адрес или сеть: {value}."}) from exc
    return sorted(set(networks))


def _status(row: dict[str, Any], now: datetime) -> str:
    if row["revoked_at"] is not None:
        return "revoked"
    return "expired" if row["expires_at"] <= now else "active"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") if value is not None else None


def public_token(row: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """The token as shown to administrators: never the secret or its hash."""
    now = now or _now()
    return {
        "id": int(row["id"]),
        "token_id": f"{TOKEN_PREFIX}{row['public_id']}",
        "name": row["name"],
        "owner": {"id": int(row["owner_user_id"]), "username": row["owner_username"], "display_name": row["owner_display_name"]},
        "scopes": list(row["scopes"]),
        "ip_allowlist": list(row["ip_allowlist"] or []),
        "status": _status(row, now),
        "created_at": _iso(row["created_at"]),
        "created_by": row["created_by_username"],
        "expires_at": _iso(row["expires_at"]),
        "revoked_at": _iso(row["revoked_at"]),
        "revoked_by": row["revoked_by_username"],
        "last_used_at": _iso(row["last_used_at"]),
        "last_used_ip": row["last_used_ip"],
        "rotated_from": row["rotated_from"],
    }


def list_tokens() -> dict[str, Any]:
    now = _now()
    return {"rows": [public_token(row, now=now) for row in repository.list_tokens()], "scopes": scope_catalog()}


def _issue(
    conn: Any,
    *,
    name: str,
    owner_user_id: int,
    scopes: list[str],
    ip_allowlist: list[str],
    expires_in_days: int,
    actor: dict[str, Any],
    rotated_from: int | None = None,
) -> tuple[int, str]:
    owner = repository.lock_owner(conn, owner_user_id)
    if not owner:
        raise HTTPException(404, detail={"code": "USER_NOT_FOUND", "message": "Пользователь не найден."})
    if not owner["is_active"]:
        raise HTTPException(409, detail={"code": "OWNER_INACTIVE", "message": "Владелец токена отключён."})
    if repository.count_active(conn, owner_user_id, now=_now()) >= MAX_ACTIVE_TOKENS_PER_OWNER:
        raise HTTPException(409, detail={"code": "TOKEN_LIMIT", "message": f"У владельца уже {MAX_ACTIVE_TOKENS_PER_OWNER} действующих токенов: отзовите ненужные."})
    public_id, secret = secrets.token_hex(6), secrets.token_urlsafe(32)
    now = _now()
    token_pk = repository.insert_token(
        conn,
        public_id=public_id,
        name=name,
        owner_user_id=owner_user_id,
        secret_hash=_hash_secret(secret),
        scopes=scopes,
        ip_allowlist=ip_allowlist,
        created_by_username=actor.get("username"),
        created_at=now,
        expires_at=now + timedelta(days=expires_in_days),
        rotated_from=rotated_from,
    )
    return token_pk, f"{TOKEN_PREFIX}{public_id}_{secret}"


def create_token(
    *,
    name: str,
    owner_user_id: int,
    scopes: list[str],
    ip_allowlist: list[str],
    expires_in_days: int,
    actor: dict[str, Any],
) -> dict[str, Any]:
    scopes, ip_allowlist = validate_scopes(scopes), validate_ip_allowlist(ip_allowlist)
    with db.connect() as conn:
        token_pk, plaintext = _issue(
            conn, name=name.strip(), owner_user_id=owner_user_id, scopes=scopes,
            ip_allowlist=ip_allowlist, expires_in_days=expires_in_days, actor=actor,
        )
        row = repository.get_token(token_pk, conn=conn)
    assert row is not None
    # The only moment the secret exists outside the client that will use it.
    return {**public_token(row), "token": plaintext}


def revoke_token(token_id: int, *, actor: dict[str, Any]) -> dict[str, Any]:
    with db.connect() as conn:
        row = repository.get_token(token_id, conn=conn, lock=True)
        if not row:
            raise HTTPException(404, detail={"code": "TOKEN_NOT_FOUND", "message": "Токен не найден."})
        if not repository.revoke(conn, token_id, by_username=actor.get("username"), now=_now()):
            raise HTTPException(409, detail={"code": "TOKEN_REVOKED", "message": "Токен уже отозван."})
        row = repository.get_token(token_id, conn=conn)
    assert row is not None
    return public_token(row)


def rotate_token(token_id: int, *, actor: dict[str, Any], grace_hours: int, expires_in_days: int) -> dict[str, Any]:
    """Issue a replacement with the same owner and scopes; the old token works for ``grace_hours`` more."""
    now = _now()
    with db.connect() as conn:
        old = repository.get_token(token_id, conn=conn, lock=True)
        if not old:
            raise HTTPException(404, detail={"code": "TOKEN_NOT_FOUND", "message": "Токен не найден."})
        if _status(old, now) != "active":
            raise HTTPException(409, detail={"code": "TOKEN_NOT_ACTIVE", "message": "Заменить можно только действующий токен."})
        new_pk, plaintext = _issue(
            conn, name=old["name"], owner_user_id=int(old["owner_user_id"]), scopes=list(old["scopes"]),
            ip_allowlist=list(old["ip_allowlist"] or []), expires_in_days=expires_in_days, actor=actor, rotated_from=token_id,
        )
        if grace_hours <= 0:
            repository.revoke(conn, token_id, by_username=actor.get("username"), now=now)
        else:
            repository.limit_expiry(conn, token_id, now + timedelta(hours=grace_hours))
        new_row = repository.get_token(new_pk, conn=conn)
    assert new_row is not None
    return {**public_token(new_row), "token": plaintext, "replaced_token_id": f"{TOKEN_PREFIX}{old['public_id']}"}


def _client_ip(scope: Scope) -> str | None:
    client = scope.get("client")
    return str(client[0]) if client else None


def _ip_allowed(ip: str | None, allowlist: list[str]) -> bool:
    if not allowlist:
        return True
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network, strict=False) for network in allowlist)


def _check_limits(ip: str, token_key: str) -> None:
    try:
        _IP_LIMITER.check(ip)
        _TOKEN_LIMITER.check(token_key)
    except HTTPException as exc:
        raise AuthRejected(429, THROTTLE_RETRY_AFTER_SECONDS) from exc


def authenticate(token: str, *, scope: Scope) -> Principal:
    """Check a presented token. Every rejection looks the same to the caller and is audited."""
    ip = _client_ip(scope)
    ip_key = ip or "unknown"
    parts = split_token(token)
    public_id = parts[0] if parts else None
    token_key = f"{ip_key}:{public_id or '-'}"
    _check_limits(ip_key, token_key)

    def deny(reason: str, row: dict[str, Any] | None = None) -> AuthRejected:
        _IP_LIMITER.fail(ip_key)
        _TOKEN_LIMITER.fail(token_key)
        app_auth.audit_event(
            request=Request(scope), user=None, event_type="mcp_auth", decision="deny", target_type="mcp_token",
            target_id=f"{TOKEN_PREFIX}{public_id}" if public_id else None,
            details={"reason": reason, "owner": row["owner_username"] if row else None},
        )
        return AuthRejected(401)

    if parts is None:
        raise deny("malformed")
    row = repository.get_by_public_id(parts[0])
    expected = row["secret_hash"] if row else _DUMMY_HASH
    matches = hmac.compare_digest(_hash_secret(parts[1]), expected)
    if row is None or not matches:
        raise deny("unknown_or_wrong_secret", row)
    now = _now()
    if row["revoked_at"] is not None:
        raise deny("revoked", row)
    if row["expires_at"] <= now:
        raise deny("expired", row)
    if not row["owner_is_active"]:
        raise deny("owner_inactive", row)
    if not _ip_allowed(ip, list(row["ip_allowlist"] or [])):
        raise deny("ip_not_allowed", row)
    _TOKEN_LIMITER.clear(token_key)
    repository.touch_used(int(row["id"]), now=now, ip=ip)
    return Principal(
        key=int(row["id"]),
        token_id=f"{TOKEN_PREFIX}{row['public_id']}",
        name=row["name"],
        owner_id=int(row["owner_user_id"]),
        owner_username=row["owner_username"],
        client_ip=ip,
    )


def _audit_user(principal: Principal) -> dict[str, Any]:
    return {
        "id": principal.owner_id,
        "username": principal.owner_username,
        "mcp_token": {"id": principal.token_id, "name": principal.name},
    }


def open_session(principal: Principal) -> str:
    """A short session of the owner, capped to the token's scopes and ending no later than the token."""
    now = _now()
    row = repository.get_token(principal.key)
    if not row or row["revoked_at"] is not None or row["expires_at"] <= now or not row["owner_is_active"]:
        raise AuthRejected(401)
    lifetime = min(timedelta(minutes=SESSION_MINUTES), row["expires_at"] - now)
    cookie = app_auth.create_session(
        principal.owner_id, lifetime=lifetime, mcp_token_id=principal.key,
        permission_cap=scope_permissions(list(row["scopes"])),
    )
    app_auth.audit_event(
        request=None, user=_audit_user(principal),
        event_type="mcp_session", decision="allow", target_type="mcp_token", target_id=principal.token_id,
        details={"client_ip": principal.client_ip},
    )
    return cookie


def record_tool_call(principal: Principal, tool: str, *, ok: bool, error: str | None, duration_ms: int) -> None:
    app_auth.audit_event(
        request=None, user=_audit_user(principal),
        event_type="mcp_tool_call", decision="deny" if error == "PERMISSION_DENIED" else "allow", target_type="mcp_tool", target_id=tool,
        details={"ok": ok, "duration_ms": duration_ms, "client_ip": principal.client_ip, **({"error": error} if error else {})},
    )


class McpTokenAuthenticator:
    """Adapter that lets the MCP server use these functions without importing the application."""

    async def authenticate(self, token: str, *, scope: Scope) -> Principal:
        return await asyncio.to_thread(authenticate, token, scope=scope)

    async def open_session(self, principal: Principal) -> str:
        return await asyncio.to_thread(open_session, principal)

    async def record_tool_call(self, principal: Principal, tool: str, *, ok: bool, error: str | None, duration_ms: int) -> None:
        await asyncio.to_thread(record_tool_call, principal, tool, ok=ok, error=error, duration_ms=duration_ms)
