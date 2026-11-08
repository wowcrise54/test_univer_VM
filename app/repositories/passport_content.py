from __future__ import annotations

import json
from typing import Any

import psycopg


def _same_json(left: Any, right: Any) -> bool:
    """JSON numbers compare by value, but booleans are never numbers."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_same_json(value, right[key]) for key, value in left.items())
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def partition_details(
    conn: psycopg.Connection[dict[str, Any]],
    details: list[tuple[str, dict[str, Any]]],
    current: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Return only new or semantically changed passport details.

    The caller owns the write lock and transaction.  Equal details still mark
    the passport as seen and checked, while malformed stored JSON is treated
    as changed so it can be repaired by the normal upsert.
    """
    if not details:
        return []

    identifiers = [identifier for identifier, _ in details]
    rows = conn.execute(
        "SELECT internal_id, raw_detail_json "
        "FROM vulnerability_passports WHERE internal_id = ANY(%s)",
        (identifiers,),
    ).fetchall()
    previous = {row["internal_id"]: row["raw_detail_json"] for row in rows}

    changed: list[tuple[str, dict[str, Any]]] = []
    unchanged: list[str] = []
    for identifier, detail in details:
        raw = previous.get(identifier)
        try:
            old = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            old = None
        if isinstance(old, dict) and _same_json(old, detail):
            unchanged.append(identifier)
        else:
            changed.append((identifier, detail))

    if unchanged:
        conn.execute(
            "UPDATE vulnerability_passports "
            "SET detail_updated_at = %s, last_seen = %s "
            "WHERE internal_id = ANY(%s)",
            (current, current, unchanged),
        )
    return changed
