"""SQL of MCP personal access tokens."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .. import db

_SELECT = """
    SELECT t.*, owner.username AS owner_username, owner.display_name AS owner_display_name,
           owner.is_active AS owner_is_active
    FROM app_mcp_tokens t JOIN app_users owner ON owner.id = t.owner_user_id
"""


def insert_token(
    conn: Any,
    *,
    public_id: str,
    name: str,
    owner_user_id: int,
    secret_hash: str,
    scopes: list[str],
    ip_allowlist: list[str],
    created_by_username: str | None,
    created_at: datetime,
    expires_at: datetime,
    rotated_from: int | None = None,
) -> int:
    row = conn.execute(
        """INSERT INTO app_mcp_tokens(public_id,name,owner_user_id,secret_hash,scopes,ip_allowlist,
               created_by_username,created_at,expires_at,rotated_from)
           VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (public_id, name, owner_user_id, secret_hash, scopes, ip_allowlist, created_by_username,
         created_at, expires_at, rotated_from),
    ).fetchone()
    assert row is not None
    return int(row["id"])


def lock_owner(conn: Any, user_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT id, is_active FROM app_users WHERE id = %s FOR UPDATE", (user_id,)).fetchone()
    return dict(row) if row else None


def count_active(conn: Any, owner_user_id: int, *, now: datetime) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM app_mcp_tokens WHERE owner_user_id = %s AND revoked_at IS NULL AND expires_at > %s",
        (owner_user_id, now),
    ).fetchone()
    assert row is not None
    return int(row["count"])


def list_tokens() -> list[dict[str, Any]]:
    with db.connect() as conn:
        return [dict(row) for row in conn.execute(f"{_SELECT} ORDER BY t.created_at DESC, t.id DESC").fetchall()]


def get_token(token_id: int, *, conn: Any = None, lock: bool = False) -> dict[str, Any] | None:
    sql = f"{_SELECT} WHERE t.id = %s" + (" FOR UPDATE OF t" if lock else "")
    if conn is not None:
        row = conn.execute(sql, (token_id,)).fetchone()
    else:
        with db.connect() as own:
            row = own.execute(sql, (token_id,)).fetchone()
    return dict(row) if row else None


def get_by_public_id(public_id: str) -> dict[str, Any] | None:
    with db.connect() as conn:
        row = conn.execute(f"{_SELECT} WHERE t.public_id = %s", (public_id,)).fetchone()
    return dict(row) if row else None


def touch_used(token_id: int, *, now: datetime, ip: str | None, min_interval_seconds: int = 60) -> None:
    """Record the last use, at most once per interval so busy clients do not write on every request."""
    with db.connect() as conn:
        conn.execute(
            """UPDATE app_mcp_tokens SET last_used_at = %s, last_used_ip = %s
               WHERE id = %s AND (last_used_at IS NULL OR last_used_at < %s - make_interval(secs => %s))""",
            (now, ip, token_id, now, min_interval_seconds),
        )


def revoke(conn: Any, token_id: int, *, by_username: str | None, now: datetime) -> bool:
    """Revoke a token and end the sessions it opened. False when it was already revoked."""
    row = conn.execute(
        """UPDATE app_mcp_tokens SET revoked_at = %s, revoked_by_username = %s
           WHERE id = %s AND revoked_at IS NULL RETURNING id""",
        (now, by_username, token_id),
    ).fetchone()
    conn.execute(
        "UPDATE app_auth_sessions SET revoked_at = %s WHERE mcp_token_id = %s AND revoked_at IS NULL",
        (now.isoformat(timespec="microseconds"), token_id),
    )
    return row is not None


def limit_expiry(conn: Any, token_id: int, expires_at: datetime) -> None:
    """Move an expiry earlier (never later) and end sessions that would outlive it."""
    conn.execute(
        "UPDATE app_mcp_tokens SET expires_at = LEAST(expires_at, %s) WHERE id = %s",
        (expires_at, token_id),
    )
    conn.execute(
        "UPDATE app_auth_sessions SET expires_at = LEAST(expires_at, %s) WHERE mcp_token_id = %s",
        (expires_at.isoformat(timespec="microseconds"), token_id),
    )
