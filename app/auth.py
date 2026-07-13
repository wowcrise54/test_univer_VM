from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from . import db

ROLES = {"admin", "operator", "viewer"}
COOKIE_NAME = "mpvm_app_session"
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=1024)
    role: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError("Unsupported role")
        return value


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str | None) -> str | None:
        if value is not None and value not in ROLES:
            raise ValueError("Unsupported role")
        return value


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(expected))
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (TypeError, ValueError):
        return False


def public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "last_login_at": row.get("last_login_at"),
    }


def ensure_bootstrap_admin(username: str, password: str, display_name: str) -> bool:
    """Create the first administrator only when the user table is empty."""
    with db.connect() as conn:
        count = int(conn.execute("SELECT COUNT(*) AS count FROM app_users").fetchone()["count"] or 0)
        if count or not password:
            return False
        current = db.now_utc()
        conn.execute(
            """INSERT INTO app_users (username, display_name, password_hash, role, is_active, created_at, updated_at)
               VALUES (%s, %s, %s, 'admin', TRUE, %s, %s)""",
            (username.strip().lower(), display_name.strip() or username, hash_password(password), current, current),
        )
    return True


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM app_users WHERE username = %s", (username.strip().lower(),)).fetchone()
    if not row or not row["is_active"] or not verify_password(password, row["password_hash"]):
        # Keep the missing-user path computationally comparable.
        if not row:
            hash_password(password)
        return None
    return public_user(dict(row))


def create_session(user_id: int, *, hours: int) -> str:
    token = secrets.token_urlsafe(48)
    current = _utc_now()
    with db.connect() as conn:
        conn.execute("DELETE FROM app_auth_sessions WHERE expires_at <= %s OR revoked_at IS NOT NULL", (_iso(current),))
        conn.execute(
            """INSERT INTO app_auth_sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (str(uuid.uuid4()), user_id, _token_hash(token), _iso(current), _iso(current + timedelta(hours=hours)), _iso(current)),
        )
        conn.execute("UPDATE app_users SET last_login_at = %s, updated_at = %s WHERE id = %s", (_iso(current), _iso(current), user_id))
    return token


def get_session_user(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    current = _iso(_utc_now())
    with db.connect() as conn:
        row = conn.execute(
            """SELECT users.* FROM app_auth_sessions sessions
               JOIN app_users users ON users.id = sessions.user_id
               WHERE sessions.token_hash = %s AND sessions.revoked_at IS NULL
                 AND sessions.expires_at > %s AND users.is_active = TRUE""",
            (_token_hash(token), current),
        ).fetchone()
        if row:
            conn.execute("UPDATE app_auth_sessions SET last_seen_at = %s WHERE token_hash = %s", (current, _token_hash(token)))
    return public_user(dict(row)) if row else None


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with db.connect() as conn:
        conn.execute(
            "UPDATE app_auth_sessions SET revoked_at = COALESCE(revoked_at, %s) WHERE token_hash = %s",
            (db.now_utc(), _token_hash(token)),
        )


def list_users() -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM app_users ORDER BY username").fetchall()
    return [public_user(dict(row)) for row in rows]


def create_user(payload: UserCreateRequest) -> dict[str, Any]:
    current = db.now_utc()
    try:
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO app_users (username, display_name, password_hash, role, is_active, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, TRUE, %s, %s) RETURNING *""",
                (payload.username.strip().lower(), payload.display_name.strip(), hash_password(payload.password), payload.role, current, current),
            ).fetchone()
    except Exception as exc:
        if exc.__class__.__name__ == "UniqueViolation":
            raise HTTPException(status_code=409, detail={"code": "USERNAME_EXISTS", "message": "Пользователь уже существует."}) from exc
        raise
    return public_user(dict(row))


def update_user(user_id: int, payload: UserUpdateRequest, *, actor_id: int) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True)
    if user_id == actor_id and changes.get("is_active") is False:
        raise HTTPException(status_code=409, detail={"code": "SELF_DISABLE", "message": "Нельзя отключить собственную учётную запись."})
    if user_id == actor_id and changes.get("role") not in {None, "admin"}:
        raise HTTPException(status_code=409, detail={"code": "SELF_DEMOTE", "message": "Нельзя изменить собственную роль администратора."})
    with db.connect() as conn:
        existing = conn.execute("SELECT * FROM app_users WHERE id = %s", (user_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "message": "Пользователь не найден."})
        removes_admin = existing["role"] == "admin" and existing["is_active"] and (
            changes.get("is_active") is False or changes.get("role") not in {None, "admin"}
        )
        if removes_admin:
            admin_count = int(conn.execute("SELECT COUNT(*) AS count FROM app_users WHERE role = 'admin' AND is_active = TRUE").fetchone()["count"] or 0)
            if admin_count <= 1:
                raise HTTPException(status_code=409, detail={"code": "LAST_ADMIN", "message": "В системе должен остаться хотя бы один активный администратор."})
    if "password" in changes:
        changes["password_hash"] = hash_password(changes.pop("password"))
    if not changes:
        with db.connect() as conn:
            row = conn.execute("SELECT * FROM app_users WHERE id = %s", (user_id,)).fetchone()
    else:
        assignments = ", ".join(f"{key} = %s" for key in changes)
        values = [*changes.values(), db.now_utc(), user_id]
        with db.connect() as conn:
            row = conn.execute(f"UPDATE app_users SET {assignments}, updated_at = %s WHERE id = %s RETURNING *", values).fetchone()
            if row and (changes.get("is_active") is False or "password_hash" in changes):
                conn.execute("UPDATE app_auth_sessions SET revoked_at = %s WHERE user_id = %s AND revoked_at IS NULL", (db.now_utc(), user_id))
    if not row:
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "message": "Пользователь не найден."})
    return public_user(dict(row))


class LoginLimiter:
    def __init__(self, attempts: int = 8, window_seconds: int = 300) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._entries: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            entries = self._entries[key]
            while entries and now - entries[0] > self.window_seconds:
                entries.popleft()
            if len(entries) >= self.attempts:
                raise HTTPException(status_code=429, detail={"code": "LOGIN_RATE_LIMIT", "message": "Слишком много попыток входа. Повторите позже."})

    def fail(self, key: str) -> None:
        with self._lock:
            self._entries[key].append(time.monotonic())

    def clear(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)


LOGIN_LIMITER = LoginLimiter()


def login(payload: LoginRequest, request: Request, response: Response, *, hours: int, secure: bool) -> dict[str, Any]:
    key = f"{request.client.host if request.client else 'unknown'}:{payload.username.strip().lower()}"
    LOGIN_LIMITER.check(key)
    user = authenticate(payload.username, payload.password)
    if not user:
        LOGIN_LIMITER.fail(key)
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS", "message": "Неверное имя пользователя или пароль."})
    LOGIN_LIMITER.clear(key)
    token = create_session(user["id"], hours=hours)
    response.set_cookie(COOKIE_NAME, token, max_age=hours * 3600, httponly=True, secure=secure, samesite="strict", path="/")
    return {"authenticated": True, "user": user}


def logout(request: Request, response: Response) -> dict[str, Any]:
    revoke_session(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="strict")
    return {"authenticated": False}
