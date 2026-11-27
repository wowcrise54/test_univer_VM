"""Repositories for detailed vulnerability passport values: upserts, refresh candidate selection, and the shared detail upsert SQL."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from ...persistence import codecs, connection, locks, schema
from ...persistence.codecs import _parse_timestamp, clean_value, first_non_empty
from ..asset_cards.passport_links import reconcile_asset_card_vulnerability_passport_links
from ..passport_content import partition_details
from .counts import invalidate_passport_totals
from .serializers import decode_vulnerability_passport

VULNERABILITY_PASSPORT_DETAIL_UPSERT_SQL = """
    INSERT INTO vulnerability_passports (
        internal_id, name, severity, score, issue_time, package_id, package_version,
        raw_detail_json, first_seen, last_seen, detail_updated_at
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT(internal_id) DO UPDATE SET
        name = COALESCE(EXCLUDED.name, vulnerability_passports.name),
        severity = COALESCE(EXCLUDED.severity, vulnerability_passports.severity),
        score = COALESCE(EXCLUDED.score, vulnerability_passports.score),
        issue_time = COALESCE(EXCLUDED.issue_time, vulnerability_passports.issue_time),
        package_id = COALESCE(EXCLUDED.package_id, vulnerability_passports.package_id),
        package_version = COALESCE(EXCLUDED.package_version, vulnerability_passports.package_version),
        raw_detail_json = EXCLUDED.raw_detail_json,
        last_seen = EXCLUDED.last_seen,
        detail_updated_at = EXCLUDED.detail_updated_at
"""


def vulnerability_passport_detail_values(
    internal_id: str,
    raw_detail: dict[str, Any],
    current: str,
) -> tuple[Any, ...]:
    vulnerability = raw_detail.get("vulnerability")
    if not isinstance(vulnerability, dict):
        vulnerability = {}
    cvss = raw_detail.get("cvss")
    if not isinstance(cvss, dict):
        cvss = {}
    name = clean_value(
        first_non_empty(
            raw_detail.get("name"),
            raw_detail.get("displayName"),
            raw_detail.get("title"),
            vulnerability.get("name"),
        )
    )
    severity = clean_value(first_non_empty(raw_detail.get("severityRating"), raw_detail.get("severity")))
    score = clean_value(
        first_non_empty(raw_detail.get("score"), raw_detail.get("cvss3Score"), cvss.get("score"))
    )
    return (
        internal_id,
        name,
        severity,
        score,
        clean_value(first_non_empty(raw_detail.get("issueTime"), raw_detail.get("publishedAt"))),
        clean_value(raw_detail.get("packageId")),
        clean_value(raw_detail.get("packageVersion")),
        json.dumps(raw_detail or {}, ensure_ascii=False),
        current,
        current,
        current,
    )


def _upsert_vulnerability_passport_details(
    conn: psycopg.Connection[dict[str, Any]],
    details: list[tuple[str, dict[str, Any]]],
    current: str,
    *,
    reconcile_links: bool = True,
) -> int:
    if not details:
        return 0
    locks._lock_vulnerability_passport_writes(conn)
    changed = partition_details(conn, details, current)
    values = [vulnerability_passport_detail_values(internal_id, raw_detail, current) for internal_id, raw_detail in changed]
    values.sort(key=lambda value: value[0])
    if values:
        with conn.cursor() as cursor:
            cursor.executemany(VULNERABILITY_PASSPORT_DETAIL_UPSERT_SQL, values)
    if reconcile_links and values:
        reconcile_asset_card_vulnerability_passport_links(conn, [value[0] for value in values], current)
    return len(details)


def upsert_vulnerability_passport_detail(internal_id: str, raw_detail: dict[str, Any]) -> dict[str, Any] | None:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        row = conn.execute(
            VULNERABILITY_PASSPORT_DETAIL_UPSERT_SQL + " RETURNING *",
            vulnerability_passport_detail_values(internal_id, raw_detail, current),
        ).fetchone()
        reconcile_asset_card_vulnerability_passport_links(conn, [internal_id], current)
    # The upsert may INSERT a passport row and updates filter columns (name,
    # severity, score): cached list totals are stale.
    invalidate_passport_totals()
    return decode_vulnerability_passport(dict(row)) if row else None


def upsert_vulnerability_passport_details(details: list[tuple[str, dict[str, Any]]]) -> int:
    schema.init_db()
    current = codecs.now_utc()
    with connection.connect() as conn:
        saved = _upsert_vulnerability_passport_details(conn, details, current)
    if saved:
        # The batch may INSERT passport rows and updates filter columns:
        # cached list totals are stale.
        invalidate_passport_totals()
    return saved


def vulnerability_passport_detail_refresh_candidates(
    internal_ids: list[Any],
    *,
    ttl_hours: int,
    force: bool = False,
) -> dict[str, Any]:
    schema.init_db()
    ordered_ids = list(dict.fromkeys(clean_value(value) for value in internal_ids if clean_value(value)))
    if not ordered_ids:
        return {"requested": [], "eligible": [], "skipped_fresh": []}
    if force:
        return {"requested": ordered_ids, "eligible": ordered_ids, "skipped_fresh": []}
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT internal_id, detail_updated_at, (raw_detail_json IS NOT NULL) AS has_detail
            FROM vulnerability_passports
            WHERE internal_id = ANY(%s)
            """,
            (ordered_ids,),
        ).fetchall()
    by_id = {clean_value(row.get("internal_id")): dict(row) for row in rows}
    # codecs.now_utc() is the app clock (tests freeze it); a raw datetime.now
    # here desyncs the TTL from the frozen clock and time-bombs the suite.
    now = _parse_timestamp(codecs.now_utc())
    cutoff = (now or datetime.now(UTC)) - timedelta(hours=max(0, ttl_hours))
    eligible: list[Any] = []
    skipped_fresh: list[Any] = []
    for internal_id in ordered_ids:
        row = by_id.get(internal_id)
        updated_at = _parse_timestamp(row.get("detail_updated_at")) if row else None
        if row and row.get("has_detail") and updated_at is not None and updated_at >= cutoff:
            skipped_fresh.append(internal_id)
        else:
            eligible.append(internal_id)
    return {"requested": ordered_ids, "eligible": eligible, "skipped_fresh": skipped_fresh}
