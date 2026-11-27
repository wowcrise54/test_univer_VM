"""Repository for vulnerability passport trend rows."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection, locks, schema
from ...persistence.codecs import clean_value
from ..asset_cards.passport_links import reconcile_asset_card_vulnerability_passport_links
from .counts import invalidate_passport_totals


def replace_vulnerability_passport_trends(
    passports: list[dict[str, Any]],
    *,
    source_pdql: str,
    pdql_token: str | None = None,
    reconcile_links: bool = False,
) -> dict[str, Any]:
    """Atomically replace the current trend snapshot without degrading passport data."""

    schema.init_db()
    current = codecs.now_utc()
    skipped = 0
    parent_values: list[tuple[Any, ...]] = []
    trend_values: list[tuple[Any, ...]] = []
    saved_ids: list[str] = []
    for passport in passports:
        internal_id = clean_value(passport.get("internal_id"))
        if not internal_id:
            skipped += 1
            continue
        cves = passport.get("cves") if isinstance(passport.get("cves"), list) else []
        raw_record = (
            passport.get("raw_record")
            if isinstance(passport.get("raw_record"), dict)
            else {}
        )
        parent_values.append(
            (
                internal_id,
                clean_value(passport.get("external_id")),
                clean_value(passport.get("name")),
                clean_value(passport.get("severity")),
                clean_value(passport.get("score")),
                clean_value(passport.get("issue_time")),
                json.dumps(cves, ensure_ascii=False, default=str),
                json.dumps(raw_record, ensure_ascii=False, default=str),
                current,
                current,
            )
        )
        trend_values.append(
            (
                internal_id,
                clean_value(passport.get("description")),
                clean_value(passport.get("is_trend_since")),
                json.dumps(
                    passport.get("vendors") or [], ensure_ascii=False, default=str
                ),
                json.dumps(
                    passport.get("affected_components") or [],
                    ensure_ascii=False,
                    default=str,
                ),
                source_pdql,
                pdql_token,
                current,
            )
        )
        saved_ids.append(internal_id)

    parent_values.sort(key=lambda value: value[0])
    trend_values.sort(key=lambda value: value[0])
    saved_ids.sort()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        # Serialize full-snapshot replacements while still allowing readers to
        # see the previously committed snapshot until this transaction commits.
        conn.execute("LOCK TABLE vulnerability_passport_trends IN EXCLUSIVE MODE")
        if parent_values:
            with conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO vulnerability_passports (
                        internal_id, external_id, name, severity, score, issue_time,
                        cves_json, raw_record_json, first_seen, last_seen
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(internal_id) DO UPDATE SET
                        external_id = COALESCE(
                            EXCLUDED.external_id, vulnerability_passports.external_id
                        ),
                        name = COALESCE(EXCLUDED.name, vulnerability_passports.name),
                        severity = COALESCE(
                            EXCLUDED.severity, vulnerability_passports.severity
                        ),
                        score = COALESCE(EXCLUDED.score, vulnerability_passports.score),
                        issue_time = COALESCE(
                            EXCLUDED.issue_time, vulnerability_passports.issue_time
                        ),
                        cves_json = CASE
                            WHEN EXCLUDED.cves_json <> '[]'
                                THEN EXCLUDED.cves_json
                            ELSE vulnerability_passports.cves_json
                        END,
                        last_seen = EXCLUDED.last_seen
                    """,
                    parent_values,
                )
        conn.execute("DELETE FROM vulnerability_passport_trends")
        if trend_values:
            with conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO vulnerability_passport_trends (
                        passport_internal_id, description, is_trend_since,
                        vendors_json, affected_components_json, source_pdql,
                        pdql_token, synced_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    trend_values,
                )
        links_created = (
            reconcile_asset_card_vulnerability_passport_links(conn, saved_ids, current)
            if reconcile_links
            else 0
        )
    # Parent upserts may INSERT passport rows and update filter columns.
    invalidate_passport_totals()
    return {
        "saved": len(trend_values),
        "skipped": skipped,
        "passport_links": links_created,
        "synced_at": current,
    }
