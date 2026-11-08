from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
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


def _clean_detail_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _same_detail_column(column: str, stored: Any, expected: str | None) -> bool:
    if stored == expected:
        return True
    if column != "score" or stored is None or expected is None:
        return False
    try:
        return Decimal(str(stored).replace(",", ".")) == Decimal(expected.replace(",", "."))
    except InvalidOperation:
        return False


def _detail_columns(detail: dict[str, Any]) -> dict[str, str | None]:
    raw_vulnerability = detail.get("vulnerability")
    raw_cvss = detail.get("cvss")
    vulnerability: dict[str, Any] = raw_vulnerability if isinstance(raw_vulnerability, dict) else {}
    cvss: dict[str, Any] = raw_cvss if isinstance(raw_cvss, dict) else {}

    def first(*values: Any) -> str | None:
        for value in values:
            if value is not None and value != "":
                return _clean_detail_value(value)
        return None

    return {
        "name": first(detail.get("name"), detail.get("displayName"), detail.get("title"), vulnerability.get("name")),
        "severity": first(detail.get("severityRating"), detail.get("severity")),
        "score": first(detail.get("score"), detail.get("cvss3Score"), cvss.get("score")),
        "issue_time": first(detail.get("issueTime"), detail.get("publishedAt")),
        "package_id": _clean_detail_value(detail.get("packageId")),
        "package_version": _clean_detail_value(detail.get("packageVersion")),
    }


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
        "SELECT internal_id, raw_detail_json, name, severity, score, issue_time, package_id, package_version "
        "FROM vulnerability_passports WHERE internal_id = ANY(%s)",
        (identifiers,),
    ).fetchall()
    previous = {row["internal_id"]: dict(row) for row in rows}

    changed: list[tuple[str, dict[str, Any]]] = []
    unchanged: list[str] = []
    for identifier, detail in details:
        row = previous.get(identifier)
        raw = row.get("raw_detail_json") if row else None
        try:
            old = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            old = None
        expected_columns = _detail_columns(detail)
        normalized_matches = row is not None and all(
            expected is None or _same_detail_column(column, row.get(column), expected)
            for column, expected in expected_columns.items()
        )
        if isinstance(old, dict) and _same_json(old, detail) and normalized_matches:
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
