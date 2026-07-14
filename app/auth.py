from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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

COOKIE_NAME = "mpvm_app_session"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
SYSTEM_ROLE_KEYS = {"admin", "operator", "viewer"}
ELEVATION_MINUTES = 30

PERMISSIONS: dict[str, tuple[str, str]] = {
    "system.read": ("Система", "Просмотр состояния и общих настроек"),
    "connection.read": ("Подключение", "Просмотр состояния подключения MP VM"),
    "connection.manage": ("Подключение", "Изменение глобального подключения MP VM"),
    "tasks.read": ("Задачи", "Просмотр задач сканирования"),
    "tasks.manage": ("Задачи", "Создание, изменение и удаление задач"),
    "tasks.execute": ("Задачи", "Проверка, запуск и остановка задач"),
    "operations.read": ("Операции", "Просмотр операций"),
    "operations.cancel": ("Операции", "Остановка операций"),
    "operations.retry": ("Операции", "Повторный запуск операций"),
    "saved_views.read": ("Представления", "Просмотр сохранённых представлений"),
    "saved_views.manage": ("Представления", "Изменение сохранённых представлений"),
    "assets.read": ("Активы", "Просмотр активов и уязвимостей"),
    "asset_cards.read": ("Карточки активов", "Просмотр и запрос карточек"),
    "asset_cards.build": ("Карточки активов", "Построение и обновление карточек"),
    "asset_cards.manage": ("Карточки активов", "Редактирование и удаление карточек"),
    "passports.read": ("Паспорта", "Просмотр паспортов уязвимостей"),
    "passports.manage": ("Паспорта", "Синхронизация и изменение паспортов"),
    "imports_exports.read": ("Импорт и экспорт", "Формирование и скачивание отчётов"),
    "imports_exports.manage": ("Импорт и экспорт", "Импорт данных и запуск PDQL-экспорта"),
    "remediation.read": ("Устранение", "Просмотр очереди устранения и SLA"),
    "remediation.manage": ("Устранение", "Изменение кейсов устранения"),
    "remediation.policy": ("Устранение", "Изменение глобальной SLA-политики"),
    "risk.read": ("Риск", "Просмотр приоритетной очереди"),
    "risk.manage": ("Риск", "Контекст активов и кампании"),
    "automations.read": ("Автоматизация", "Просмотр сценариев и запусков"),
    "automations.manage": ("Автоматизация", "Проектирование, публикация и расписания"),
    "automations.execute": ("Автоматизация", "Запуск, остановка и повтор автоматизаций"),
    "notifications.read": ("Уведомления", "Просмотр уведомлений"),
    "notifications.manage": ("Уведомления", "Изменение состояния уведомлений"),
    "diagnostics.write": ("Диагностика", "Отправка клиентской диагностики"),
    "diagnostics.read": ("Диагностика", "Скачивание диагностических архивов"),
    "security.users.read": ("Безопасность", "Просмотр пользователей"),
    "security.users.manage": ("Безопасность", "Создание и изменение пользователей"),
    "security.roles.read": ("Безопасность", "Просмотр ролей и разрешений"),
    "security.roles.manage": ("Безопасность", "Создание и изменение ролей"),
    "security.audit.read": ("Безопасность", "Просмотр аудита доступа"),
}

VIEWER_PERMISSIONS = {
    key for key in PERMISSIONS
    if key.endswith(".read") and not key.startswith("security.") and key != "diagnostics.read"
} | {"diagnostics.write"}
OPERATOR_PERMISSIONS = VIEWER_PERMISSIONS | {
    "tasks.manage", "tasks.execute", "operations.cancel", "operations.retry",
    "saved_views.manage", "asset_cards.build", "asset_cards.manage",
    "passports.manage", "imports_exports.manage", "notifications.manage",
    "risk.manage", "remediation.manage",
}
BUILTIN_ROLE_PERMISSIONS = {
    "viewer": VIEWER_PERMISSIONS,
    "operator": OPERATOR_PERMISSIONS,
    "admin": set(PERMISSIONS),
}
BUILTIN_ROLE_NAMES = {"admin": "Администратор", "operator": "Оператор", "viewer": "Наблюдатель"}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class ReauthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=1024)
    role_ids: list[int] = Field(default_factory=list, min_length=1)
    role: str | None = None  # Backward-compatible input during rollout.


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    role_ids: list[int] | None = Field(default=None, min_length=1)
    role: str | None = None
    is_active: bool | None = None


class RoleCloneRequest(BaseModel):
    source_role_id: int
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=500)


class RoleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    permission_keys: list[str] | None = None

    @field_validator("permission_keys")
    @classmethod
    def valid_permissions(cls, value: list[str] | None) -> list[str] | None:
        unknown = set(value or ()) - set(PERMISSIONS)
        if unknown:
            raise ValueError(f"Unsupported permissions: {', '.join(sorted(unknown))}")
        return sorted(set(value)) if value is not None else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt": return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(expected)))
        return hmac.compare_digest(digest.hex(), expected)
    except (TypeError, ValueError):
        return False


def ensure_rbac_catalog() -> None:
    """Seed immutable templates and migrate the former app_users.role values once."""
    current = db.now_utc()
    with db.connect() as conn:
        for key, (domain, description) in PERMISSIONS.items():
            conn.execute("""INSERT INTO app_permissions(permission_key,domain,action,description)
                VALUES (%s,%s,%s,%s) ON CONFLICT(permission_key) DO UPDATE SET
                domain=EXCLUDED.domain, action=EXCLUDED.action, description=EXCLUDED.description""",
                (key, domain, key.split(".", 1)[1], description))
        role_ids: dict[str, int] = {}
        for key in ("admin", "operator", "viewer"):
            row = conn.execute("""INSERT INTO app_roles(role_key,name,description,is_system,created_at,updated_at)
                VALUES(%s,%s,%s,TRUE,%s,%s) ON CONFLICT(role_key) DO UPDATE SET
                name=EXCLUDED.name, description=EXCLUDED.description, is_system=TRUE, updated_at=EXCLUDED.updated_at RETURNING id""",
                (key, BUILTIN_ROLE_NAMES[key], f"Системная роль {BUILTIN_ROLE_NAMES[key].lower()}", current, current)).fetchone()
            assert row is not None
            role_ids[key] = int(row["id"])
            conn.execute("DELETE FROM app_role_permissions WHERE role_id=%s", (row["id"],))
            for permission in sorted(BUILTIN_ROLE_PERMISSIONS[key]):
                conn.execute("INSERT INTO app_role_permissions(role_id,permission_key) VALUES(%s,%s) ON CONFLICT DO NOTHING", (row["id"], permission))
        legacy_row = conn.execute("""SELECT EXISTS(SELECT 1 FROM information_schema.columns
            WHERE table_name='app_users' AND column_name='role') AS present""").fetchone()
        assert legacy_row is not None
        legacy = legacy_row["present"]
        if legacy:
            conn.execute("""INSERT INTO app_user_roles(user_id,role_id)
                SELECT users.id, roles.id FROM app_users users JOIN app_roles roles ON roles.role_key=users.role
                ON CONFLICT DO NOTHING""")
            conn.execute("ALTER TABLE app_users DROP COLUMN role")


def _roles_for_user(conn, user_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("""SELECT roles.* FROM app_user_roles ur JOIN app_roles roles ON roles.id=ur.role_id
        WHERE ur.user_id=%s ORDER BY roles.is_system DESC, roles.name""", (user_id,)).fetchall()
    return [{"id": int(row["id"]), "key": row.get("role_key"), "name": row["name"], "is_system": bool(row["is_system"])} for row in rows]


def _permissions_for_user(conn, user_id: int) -> list[str]:
    rows = conn.execute("""SELECT DISTINCT rp.permission_key FROM app_user_roles ur
        JOIN app_role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=%s ORDER BY rp.permission_key""", (user_id,)).fetchall()
    return [row["permission_key"] for row in rows]


def public_user(row: dict[str, Any], *, roles: list[dict[str, Any]] | None = None, permissions: list[str] | None = None) -> dict[str, Any]:
    roles = roles or row.get("roles") or []
    keys = [role.get("key") for role in roles]
    primary = "admin" if "admin" in keys else "operator" if "operator" in keys else "viewer" if "viewer" in keys else (roles[0]["name"] if roles else None)
    return {"id": int(row["id"]), "username": row["username"], "display_name": row["display_name"],
        "role": primary, "roles": roles, "permissions": permissions or row.get("permissions") or [],
        "is_active": bool(row["is_active"]), "created_at": row.get("created_at"), "updated_at": row.get("updated_at"),
        "last_login_at": row.get("last_login_at"), "elevated_until": row.get("elevated_until")}


def ensure_bootstrap_admin(username: str, password: str, display_name: str) -> bool:
    with db.connect() as conn:
        count_row = conn.execute("SELECT COUNT(*) AS count FROM app_users").fetchone()
        assert count_row is not None
        if int(count_row["count"] or 0) or not password: return False
        current = db.now_utc()
        row = conn.execute("""INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
            VALUES(%s,%s,%s,TRUE,%s,%s) RETURNING id""", (username.strip().lower(), display_name.strip() or username, hash_password(password), current, current)).fetchone()
        role = conn.execute("SELECT id FROM app_roles WHERE role_key='admin'").fetchone()
        assert row is not None and role is not None
        conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role["id"]))
    return True


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM app_users WHERE username=%s", (username.strip().lower(),)).fetchone()
        if row and row["is_active"] and verify_password(password, row["password_hash"]):
            return public_user(dict(row), roles=_roles_for_user(conn, row["id"]), permissions=_permissions_for_user(conn, row["id"]))
    if not row: hash_password(password)
    return None


def create_session(user_id: int, *, hours: int) -> str:
    token, current = secrets.token_urlsafe(48), _utc_now()
    with db.connect() as conn:
        conn.execute("DELETE FROM app_auth_sessions WHERE expires_at<=%s OR revoked_at IS NOT NULL", (_iso(current),))
        conn.execute("""INSERT INTO app_auth_sessions(id,user_id,token_hash,created_at,expires_at,last_seen_at)
            VALUES(%s,%s,%s,%s,%s,%s)""", (str(uuid.uuid4()), user_id, _token_hash(token), _iso(current), _iso(current+timedelta(hours=hours)), _iso(current)))
        conn.execute("UPDATE app_users SET last_login_at=%s,updated_at=%s WHERE id=%s", (_iso(current), _iso(current), user_id))
    return token


def get_session_user(token: str | None) -> dict[str, Any] | None:
    if not token: return None
    current, hashed = _iso(_utc_now()), _token_hash(token)
    with db.connect() as conn:
        row = conn.execute("""SELECT users.*,sessions.elevated_until FROM app_auth_sessions sessions JOIN app_users users ON users.id=sessions.user_id
            WHERE sessions.token_hash=%s AND sessions.revoked_at IS NULL AND sessions.expires_at>%s AND users.is_active=TRUE""", (hashed, current)).fetchone()
        if not row: return None
        conn.execute("UPDATE app_auth_sessions SET last_seen_at=%s WHERE token_hash=%s AND last_seen_at<%s", (current, hashed, _iso(_utc_now()-timedelta(minutes=5))))
        return public_user(dict(row), roles=_roles_for_user(conn, row["id"]), permissions=_permissions_for_user(conn, row["id"]))


def revoke_session(token: str | None) -> None:
    if token:
        with db.connect() as conn: conn.execute("UPDATE app_auth_sessions SET revoked_at=COALESCE(revoked_at,%s) WHERE token_hash=%s", (db.now_utc(), _token_hash(token)))


def is_elevated(user: dict[str, Any]) -> bool:
    try: return datetime.fromisoformat(str(user.get("elevated_until"))) > _utc_now()
    except (TypeError, ValueError): return False


def reauthenticate(token: str | None, password: str) -> dict[str, Any]:
    if not token: raise HTTPException(401, detail={"code": "AUTH_REQUIRED", "message": "Войдите в приложение."})
    hashed = _token_hash(token)
    with db.connect() as conn:
        row = conn.execute("""SELECT users.* FROM app_auth_sessions sessions JOIN app_users users ON users.id=sessions.user_id
            WHERE sessions.token_hash=%s AND sessions.revoked_at IS NULL""", (hashed,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            raise HTTPException(401, detail={"code": "REAUTH_FAILED", "message": "Неверный пароль."})
        elevated = _iso(_utc_now()+timedelta(minutes=ELEVATION_MINUTES))
        conn.execute("UPDATE app_auth_sessions SET elevated_until=%s WHERE token_hash=%s", (elevated, hashed))
    return {"elevated_until": elevated}


def list_users() -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM app_users ORDER BY username").fetchall()
        return [public_user(dict(row), roles=_roles_for_user(conn,row["id"]), permissions=_permissions_for_user(conn,row["id"])) for row in rows]


def _resolve_role_ids(conn, role_ids: list[int], legacy_role: str | None = None) -> list[int]:
    if legacy_role:
        row = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (legacy_role,)).fetchone()
        role_ids = [int(row["id"])] if row else []
    ids = sorted(set(int(value) for value in role_ids))
    found = conn.execute("SELECT id FROM app_roles WHERE id=ANY(%s)", (ids,)).fetchall() if ids else []
    if len(found) != len(ids): raise HTTPException(422, detail={"code":"INVALID_ROLES","message":"Одна или несколько ролей не найдены."})
    return ids


def _replace_user_roles(conn, user_id: int, role_ids: list[int]) -> None:
    conn.execute("DELETE FROM app_user_roles WHERE user_id=%s", (user_id,))
    for role_id in role_ids: conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (user_id,role_id))


def create_user(payload: UserCreateRequest) -> dict[str, Any]:
    current = db.now_utc()
    try:
        with db.connect() as conn:
            role_ids = _resolve_role_ids(conn,payload.role_ids,payload.role)
            row = conn.execute("""INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
                VALUES(%s,%s,%s,TRUE,%s,%s) RETURNING *""", (payload.username.strip().lower(),payload.display_name.strip(),hash_password(payload.password),current,current)).fetchone()
            assert row is not None
            _replace_user_roles(conn,row["id"],role_ids)
            return public_user(dict(row),roles=_roles_for_user(conn,row["id"]),permissions=_permissions_for_user(conn,row["id"]))
    except Exception as exc:
        if exc.__class__.__name__=="UniqueViolation": raise HTTPException(409,detail={"code":"USERNAME_EXISTS","message":"Пользователь уже существует."}) from exc
        raise


def update_user(user_id: int, payload: UserUpdateRequest, *, actor_id: int) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True); role_ids = changes.pop("role_ids",None); legacy_role=changes.pop("role",None)
    if user_id==actor_id and changes.get("is_active") is False: raise HTTPException(409,detail={"code":"SELF_DISABLE","message":"Нельзя отключить себя."})
    with db.connect() as conn:
        existing=conn.execute("SELECT * FROM app_users WHERE id=%s FOR UPDATE",(user_id,)).fetchone()
        if not existing: raise HTTPException(404,detail={"code":"USER_NOT_FOUND","message":"Пользователь не найден."})
        old_roles=_roles_for_user(conn,user_id); requested=_resolve_role_ids(conn,role_ids or [],legacy_role) if role_ids is not None or legacy_role else None
        admin_row = conn.execute("SELECT EXISTS(SELECT 1 FROM app_roles WHERE id=ANY(%s) AND role_key='admin') AS yes",(requested,)).fetchone() if requested is not None else None
        removes_admin=any(r["key"]=="admin" for r in old_roles) and (changes.get("is_active") is False or (requested is not None and not bool(admin_row and admin_row["yes"])))
        if user_id==actor_id and requested is not None and removes_admin: raise HTTPException(409,detail={"code":"SELF_DEMOTE","message":"Нельзя снять с себя роль администратора."})
        admin_count = conn.execute("""SELECT COUNT(DISTINCT ur.user_id) AS count FROM app_user_roles ur JOIN app_users u ON u.id=ur.user_id JOIN app_roles r ON r.id=ur.role_id WHERE r.role_key='admin' AND u.is_active=TRUE""").fetchone()
        assert admin_count is not None
        if removes_admin and int(admin_count["count"] or 0)<=1:
            raise HTTPException(409,detail={"code":"LAST_ADMIN","message":"Должен остаться активный администратор."})
        if "password" in changes: changes["password_hash"]=hash_password(changes.pop("password"))
        if changes:
            assignments=", ".join(f"{key}=%s" for key in changes); row=conn.execute(f"UPDATE app_users SET {assignments},updated_at=%s WHERE id=%s RETURNING *",[*changes.values(),db.now_utc(),user_id]).fetchone()
        else: row=existing
        if requested is not None: _replace_user_roles(conn,user_id,requested)
        if changes.get("is_active") is False or "password_hash" in changes or requested is not None:
            conn.execute("UPDATE app_auth_sessions SET revoked_at=%s,elevated_until=NULL WHERE user_id=%s AND revoked_at IS NULL",(db.now_utc(),user_id))
        assert row is not None
        return public_user(dict(row),roles=_roles_for_user(conn,user_id),permissions=_permissions_for_user(conn,user_id))


def list_permissions() -> list[dict[str,str]]:
    return [{"key":key,"domain":domain,"description":description} for key,(domain,description) in sorted(PERMISSIONS.items())]


def list_roles() -> list[dict[str,Any]]:
    with db.connect() as conn:
        rows=conn.execute("""SELECT roles.*,COUNT(DISTINCT ur.user_id) AS user_count FROM app_roles roles LEFT JOIN app_user_roles ur ON ur.role_id=roles.id GROUP BY roles.id ORDER BY roles.is_system DESC,roles.name""").fetchall()
        result=[]
        for row in rows:
            perms=[item["permission_key"] for item in conn.execute("SELECT permission_key FROM app_role_permissions WHERE role_id=%s ORDER BY permission_key",(row["id"],)).fetchall()]
            result.append({"id":int(row["id"]),"key":row.get("role_key"),"name":row["name"],"description":row["description"],"is_system":bool(row["is_system"]),"user_count":int(row["user_count"]),"permission_keys":perms})
        return result


def clone_role(payload: RoleCloneRequest) -> dict[str,Any]:
    current=db.now_utc()
    with db.connect() as conn:
        source=conn.execute("SELECT * FROM app_roles WHERE id=%s",(payload.source_role_id,)).fetchone()
        if not source: raise HTTPException(404,detail={"code":"ROLE_NOT_FOUND","message":"Роль не найдена."})
        try: row=conn.execute("""INSERT INTO app_roles(name,description,is_system,created_at,updated_at) VALUES(%s,%s,FALSE,%s,%s) RETURNING *""",(payload.name.strip(),payload.description.strip(),current,current)).fetchone()
        except Exception as exc:
            if exc.__class__.__name__=="UniqueViolation": raise HTTPException(409,detail={"code":"ROLE_EXISTS","message":"Роль с таким именем уже существует."}) from exc
            raise
        assert row is not None
        conn.execute("INSERT INTO app_role_permissions(role_id,permission_key) SELECT %s,permission_key FROM app_role_permissions WHERE role_id=%s",(row["id"],source["id"]))
    return next(role for role in list_roles() if role["id"]==row["id"])


def update_role(role_id:int,payload:RoleUpdateRequest)->dict[str,Any]:
    changes=payload.model_dump(exclude_unset=True); permissions=changes.pop("permission_keys",None)
    with db.connect() as conn:
        role=conn.execute("SELECT * FROM app_roles WHERE id=%s FOR UPDATE",(role_id,)).fetchone()
        if not role: raise HTTPException(404,detail={"code":"ROLE_NOT_FOUND","message":"Роль не найдена."})
        if role["is_system"]: raise HTTPException(409,detail={"code":"SYSTEM_ROLE_IMMUTABLE","message":"Системную роль нельзя изменить."})
        if changes:
            assignments=", ".join(f"{key}=%s" for key in changes); conn.execute(f"UPDATE app_roles SET {assignments},updated_at=%s WHERE id=%s",[*changes.values(),db.now_utc(),role_id])
        if permissions is not None:
            conn.execute("DELETE FROM app_role_permissions WHERE role_id=%s",(role_id,))
            for key in permissions: conn.execute("INSERT INTO app_role_permissions(role_id,permission_key) VALUES(%s,%s)",(role_id,key))
        conn.execute("""UPDATE app_auth_sessions sessions SET elevated_until=NULL
            FROM app_user_roles ur WHERE ur.user_id=sessions.user_id AND ur.role_id=%s""", (role_id,))
    return next(role for role in list_roles() if role["id"]==role_id)


def delete_role(role_id:int)->None:
    with db.connect() as conn:
        role=conn.execute("SELECT * FROM app_roles WHERE id=%s FOR UPDATE",(role_id,)).fetchone()
        if not role: raise HTTPException(404,detail={"code":"ROLE_NOT_FOUND","message":"Роль не найдена."})
        if role["is_system"]: raise HTTPException(409,detail={"code":"SYSTEM_ROLE_IMMUTABLE","message":"Системную роль нельзя удалить."})
        assigned = conn.execute("SELECT EXISTS(SELECT 1 FROM app_user_roles WHERE role_id=%s) AS assigned",(role_id,)).fetchone()
        assert assigned is not None
        if assigned["assigned"]: raise HTTPException(409,detail={"code":"ROLE_ASSIGNED","message":"Сначала снимите роль со всех пользователей."})
        conn.execute("DELETE FROM app_roles WHERE id=%s",(role_id,))


def audit_event(*,request:Request|None,user:dict[str,Any]|None,event_type:str,decision:str,permission_key:str|None=None,target_type:str|None=None,target_id:str|None=None,details:dict[str,Any]|None=None)->None:
    try:
        with db.connect() as conn: conn.execute("""INSERT INTO app_auth_audit_events(actor_user_id,actor_username,event_type,permission_key,decision,target_type,target_id,ip_address,user_agent,trace_id,request_id,details_json,created_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",((user or {}).get("id"),(user or {}).get("username"),event_type,permission_key,decision,target_type,target_id,request.client.host if request and request.client else None,request.headers.get("user-agent") if request else None,getattr(request.state,"trace_id",None) if request else None,getattr(request.state,"request_id",None) if request else None,json.dumps(details or {},ensure_ascii=False),db.now_utc()))
    except Exception: pass


def list_audit_events(limit:int=200,offset:int=0)->dict[str,Any]:
    limit=max(1,min(500,limit)); offset=max(0,offset)
    with db.connect() as conn:
        total_row=conn.execute("SELECT COUNT(*) AS count FROM app_auth_audit_events").fetchone()
        assert total_row is not None
        total=total_row["count"]
        rows=conn.execute("SELECT * FROM app_auth_audit_events ORDER BY id DESC LIMIT %s OFFSET %s",(limit,offset)).fetchall()
    return {"total":int(total),"rows":[{**dict(row),"details":json.loads(row.get("details_json") or "{}") } for row in rows],"limit":limit,"offset":offset}


def cleanup_audit_events(retention_days:int=365)->int:
    cutoff=_iso(_utc_now()-timedelta(days=retention_days))
    with db.connect() as conn: result=conn.execute("DELETE FROM app_auth_audit_events WHERE created_at<%s",(cutoff,))
    return int(result.rowcount or 0)


class LoginLimiter:
    def __init__(self,attempts:int=8,window_seconds:int=300):
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._entries: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
    def check(self,key:str)->None:
        now=time.monotonic()
        with self._lock:
            entries=self._entries[key]
            while entries and now-entries[0]>self.window_seconds: entries.popleft()
            if len(entries)>=self.attempts: raise HTTPException(429,detail={"code":"LOGIN_RATE_LIMIT","message":"Слишком много попыток входа."})
    def fail(self,key:str)->None:
        with self._lock: self._entries[key].append(time.monotonic())
    def clear(self,key:str)->None:
        with self._lock: self._entries.pop(key,None)


LOGIN_LIMITER=LoginLimiter()


def login(payload:LoginRequest,request:Request,response:Response,*,hours:int,secure:bool)->dict[str,Any]:
    key=f"{request.client.host if request.client else 'unknown'}:{payload.username.strip().lower()}"; LOGIN_LIMITER.check(key); user=authenticate(payload.username,payload.password)
    if not user:
        LOGIN_LIMITER.fail(key); audit_event(request=request,user=None,event_type="login",decision="deny",details={"username":payload.username.strip().lower()}); raise HTTPException(401,detail={"code":"INVALID_CREDENTIALS","message":"Неверное имя пользователя или пароль."})
    LOGIN_LIMITER.clear(key); token=create_session(user["id"],hours=hours); response.set_cookie(COOKIE_NAME,token,max_age=hours*3600,httponly=True,secure=secure,samesite="strict",path="/"); audit_event(request=request,user=user,event_type="login",decision="allow"); return {"authenticated":True,"user":user}


def logout(request:Request,response:Response)->dict[str,Any]:
    user=getattr(request.state,"user",None); revoke_session(request.cookies.get(COOKIE_NAME)); response.delete_cookie(COOKIE_NAME,path="/",httponly=True,samesite="strict"); audit_event(request=request,user=user,event_type="logout",decision="allow"); return {"authenticated":False}


_UUID_PATH = re.compile(r"/[0-9a-fA-F-]{16,}")


def required_permission(method:str,path:str)->str|None:
    """Declarative policy map for every API domain; unknown writes are denied."""
    method=method.upper()
    if path.startswith("/api/vm/workflows/") and path.endswith("/cancel"): return "operations.cancel"
    if path.startswith("/api/vm/workflows/") and path.endswith("/retry"): return "operations.retry"
    if path=="/api/vm/workflows/scan": return "tasks.execute"
    if path.startswith("/api/vm"): return "operations.read"
    if path.startswith("/api/auth/users"): return "security.users.read" if method in {"GET","HEAD"} else "security.users.manage"
    if path.startswith("/api/auth/roles") or path=="/api/auth/permissions": return "security.roles.read" if method in {"GET","HEAD"} else "security.roles.manage"
    if path.startswith("/api/auth/audit"): return "security.audit.read"
    if path=="/api/auth/reauth": return None
    if path.startswith("/api/diagnostics/frontend"): return "diagnostics.write"
    if path.startswith("/api/session/connect") or path.startswith("/api/session/disconnect"): return "connection.manage"
    if path.startswith("/api/session") or path.startswith("/api/mpvm/lookups") or path.startswith("/api/mpvm/scanner-tasks/remote"): return "connection.read"
    if path.startswith("/api/operations/") and path.endswith("/diagnostics"): return "diagnostics.read"
    if path.startswith("/api/operations"):
        if path.endswith("/cancel"): return "operations.cancel"
        if path.endswith("/retry"): return "operations.retry"
        return "operations.read"
    if path.startswith("/api/saved-views"): return "saved_views.read" if method in {"GET","HEAD"} else "saved_views.manage"
    if path.startswith("/api/scanner-tasks"):
        if any(path.endswith(s) for s in ("/start","/stop","/validate")): return "tasks.execute"
        return "tasks.read" if method in {"GET","HEAD"} else "tasks.manage"
    if path.startswith("/api/reports/") or path.startswith("/api/asset-card-query/export") or (path.startswith("/api/exports/") and method=="GET"): return "imports_exports.read"
    if path.startswith("/api/import") or path.startswith("/api/exports/pdql"): return "imports_exports.manage"
    if path.startswith("/api/risk"): return "risk.read"
    if path.startswith("/api/assets/context"): return "risk.read" if method in {"GET","HEAD"} else "risk.manage"
    if path.startswith("/api/assets") or path.startswith("/api/vulnerabilities") or path.startswith("/api/coverage"): return "assets.read"
    if path.startswith("/api/asset-card-query"): return "asset_cards.read"
    if path.startswith("/api/asset-cards"):
        if any(marker in path for marker in ("/build","/refresh-scan")): return "asset_cards.build" if method not in {"GET","HEAD"} else "asset_cards.read"
        return "asset_cards.read" if method in {"GET","HEAD"} or path.endswith("/query-assets") else "asset_cards.manage"
    if path.startswith("/api/vulnerability-passports"):
        return "passports.read" if method in {"GET","HEAD"} or path.endswith("/query") else "passports.manage"
    if path.startswith("/api/remediation/policy"): return "remediation.read" if method in {"GET","HEAD"} else "remediation.policy"
    if path.startswith("/api/remediation"): return "remediation.read" if method in {"GET","HEAD"} else "remediation.manage"
    if path.startswith("/api/automations"):
        if any(path.endswith(s) for s in ("/run","/cancel","/retry")): return "automations.execute"
        return "automations.read" if method in {"GET","HEAD"} else "automations.manage"
    if path.startswith("/api/notifications"): return "notifications.read" if method in {"GET","HEAD"} else "notifications.manage"
    if path.startswith("/api/system") or path=="/api/defaults": return "system.read"
    return "system.read" if method in {"GET","HEAD"} else "__deny__"
