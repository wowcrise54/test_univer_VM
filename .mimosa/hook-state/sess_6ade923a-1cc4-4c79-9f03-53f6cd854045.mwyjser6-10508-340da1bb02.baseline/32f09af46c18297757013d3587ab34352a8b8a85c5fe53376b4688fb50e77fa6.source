"""Generic SQL helpers shared by repositories."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psycopg

from app.diagnostics import log_event


def rows_to_dicts(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]

def validated_sort_sql(sort_by: str | None, sort_dir: str | None, allowed: dict[str, str], *, default: str) -> tuple[str, str]:
    key = sort_by or default
    expression = allowed.get(key)
    if not expression:
        raise ValueError(f"Unsupported sort column: {key}")
    return expression, "DESC" if str(sort_dir or "").lower() == "desc" else "ASC"

def chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]

def copy_rows(
    cursor: psycopg.Cursor[Any],
    table: str,
    columns: tuple[str, ...],
    rows: list[tuple[Any, ...]],
) -> None:
    if not rows:
        return
    column_sql = ", ".join(columns)
    started = datetime.now(UTC)
    with cursor.copy(f"COPY {table} ({column_sql}) FROM STDIN") as copy:
        for row in rows:
            copy.write_row(row)
    log_event(
        "database",
        "db.copy.completed",
        level=10,
        table=table,
        row_count=len(rows),
        duration_ms=round((datetime.now(UTC) - started).total_seconds() * 1000, 2),
    )
