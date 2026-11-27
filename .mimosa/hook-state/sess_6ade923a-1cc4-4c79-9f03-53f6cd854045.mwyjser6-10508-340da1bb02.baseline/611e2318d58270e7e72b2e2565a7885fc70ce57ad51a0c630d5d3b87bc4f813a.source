"""Repository for user-saved view filters, keyed by route."""

from __future__ import annotations

import json
from typing import Any

from ..persistence import codecs, connection, schema
from ..persistence.codecs import json_loads


def list_saved_views(route: str) -> list[dict[str, Any]]:
    schema.init_db()
    with connection.connect() as conn:
        rows = conn.execute("SELECT * FROM saved_views WHERE route = %s ORDER BY name", (route,)).fetchall()
    return [decode_saved_view(dict(row)) for row in rows]


def save_view(route: str, name: str, filters: dict[str, Any]) -> dict[str, Any]:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO saved_views (route, name, filters_json, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(route, name) DO UPDATE SET filters_json = EXCLUDED.filters_json, updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (route, name, json.dumps(filters, ensure_ascii=False), current, current),
        ).fetchone()
    assert row is not None
    return decode_saved_view(dict(row))


def delete_saved_view(view_id: int) -> bool:
    schema.init_db()
    with connection.connect() as conn:
        result = conn.execute("DELETE FROM saved_views WHERE id = %s", (view_id,))
    return bool(result.rowcount)


def decode_saved_view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "route": row.get("route"),
        "name": row.get("name"),
        "filters": json_loads(row.get("filters_json"), {}),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }
