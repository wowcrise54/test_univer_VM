"""Repository for the vulnerability passport catalog: batched upserts under the passport write lock, reads, deletion, and listing."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from ...persistence import codecs, connection, locks, schema
from ...persistence.codecs import clean_value
from ...persistence.sql import validated_sort_sql
from ..asset_cards.passport_links import reconcile_asset_card_vulnerability_passport_links
from ..passport_replacements import rebind_reissued_findings
from .counts import cached_passport_total, invalidate_passport_totals, passport_total_key, remember_passport_total
from .replacements import _plan_passport_id_replacements
from .serializers import decode_vulnerability_passport, decode_vulnerability_passport_summary

# Connection pool: 0 disables pooling (a new connection per ``connection.connect()`` call).
# Keep max_size below the server's max_connections minus background clients.
# Passports are written in bounded batches so each statement stays short and the
# refresh job can report progress.
PASSPORT_SAVE_BATCH_SIZE = 5000


def upsert_vulnerability_passports(
    passports: list[dict[str, Any]],
    *,
    source_pdql: str | None = None,
    pdql_token: str | None = None,
    progress: Callable[[str, int, int], None] | None = None,
    full_catalog: bool = False,
    allow_replacements: bool = True,
) -> dict[str, Any]:
    """Upsert the catalog; ``progress(stage, done, total)`` reports "save" and "link" steps.

    ``full_catalog`` states that ``passports`` is the complete MP VM catalog, so
    every stored passport missing from it is gone upstream and may be merged
    into the passport that replaced it.
    """
    schema.init_db()
    current = codecs.now_utc()
    skipped = 0
    replaced = 0
    saved_ids: list[str] = []
    values: list[tuple[Any, ...]] = []
    for passport in passports:
        internal_id = clean_value(passport.get("internal_id"))
        if not internal_id:
            skipped += 1
            continue
        values.append(
            (
                internal_id,
                clean_value(passport.get("external_id")),
                clean_value(passport.get("name")),
                clean_value(passport.get("severity")),
                clean_value(passport.get("score")),
                clean_value(passport.get("issue_time")),
                clean_value(passport.get("package_id")),
                clean_value(passport.get("package_version")),
                json.dumps(passport.get("cves") or [], ensure_ascii=False),
                json.dumps(passport.get("metrics") or {}, ensure_ascii=False),
                json.dumps(passport.get("raw_record") or {}, ensure_ascii=False),
                source_pdql,
                pdql_token,
                current,
                current,
            )
        )
        saved_ids.append(internal_id)
    # One row per passport: a batched upsert cannot touch the same row twice.
    values = sorted({value[0]: value for value in values}.values(), key=lambda value: value[0])
    saved_ids = [value[0] for value in values]
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        with conn.cursor() as cursor:
            known_ids: set[str] = set()
            for offset in range(0, len(saved_ids), 5000):
                batch = saved_ids[offset : offset + 5000]
                if batch:
                    known_ids.update(
                        row["internal_id"]
                        for row in cursor.execute(
                            "SELECT internal_id FROM vulnerability_passports WHERE internal_id = ANY(%s)",
                            (batch,),
                        ).fetchall()
                    )

            # Only new or content-changed passports are rewritten (and so fire
            # the CVE/OS-family trigger and need their links rebuilt); a refresh
            # of an unchanged catalog just touches last_seen.
            changed_passport_ids: list[str] = []
            for offset in range(0, len(values), PASSPORT_SAVE_BATCH_SIZE):
                value_batch = values[offset : offset + PASSPORT_SAVE_BATCH_SIZE]
                columns = list(zip(*value_batch, strict=True))
                changed_rows = cursor.execute(
                    """
                INSERT INTO vulnerability_passports (
                    internal_id, external_id, name, severity, score, issue_time,
                    package_id, package_version, cves_json, metrics_json,
                    raw_record_json, source_pdql, pdql_token, first_seen, last_seen
                )
                SELECT incoming.internal_id, incoming.external_id, incoming.name,
                       incoming.severity, incoming.score, incoming.issue_time,
                       incoming.package_id, incoming.package_version,
                       incoming.cves_json, incoming.metrics_json,
                       incoming.raw_record_json, incoming.source_pdql,
                       incoming.pdql_token, incoming.first_seen, incoming.last_seen
                FROM unnest(
                    %s::text[], %s::text[], %s::text[], %s::text[], %s::text[],
                    %s::text[], %s::text[], %s::text[], %s::text[], %s::text[],
                    %s::text[], %s::text[], %s::text[], %s::text[], %s::text[]
                ) AS incoming(
                    internal_id, external_id, name, severity, score, issue_time,
                    package_id, package_version, cves_json, metrics_json,
                    raw_record_json, source_pdql, pdql_token, first_seen, last_seen
                )
                ON CONFLICT(internal_id) DO UPDATE SET
                    external_id = EXCLUDED.external_id,
                    name = EXCLUDED.name,
                    severity = EXCLUDED.severity,
                    score = EXCLUDED.score,
                    issue_time = EXCLUDED.issue_time,
                    package_id = EXCLUDED.package_id,
                    package_version = EXCLUDED.package_version,
                    cves_json = EXCLUDED.cves_json,
                    metrics_json = EXCLUDED.metrics_json,
                    raw_record_json = EXCLUDED.raw_record_json,
                    source_pdql = EXCLUDED.source_pdql,
                    pdql_token = EXCLUDED.pdql_token,
                    last_seen = EXCLUDED.last_seen
                WHERE (
                    vulnerability_passports.external_id,
                    vulnerability_passports.name,
                    vulnerability_passports.severity,
                    vulnerability_passports.score,
                    vulnerability_passports.issue_time,
                    vulnerability_passports.package_id,
                    vulnerability_passports.package_version,
                    vulnerability_passports.cves_json,
                    vulnerability_passports.metrics_json,
                    vulnerability_passports.raw_record_json
                ) IS DISTINCT FROM (
                    EXCLUDED.external_id,
                    EXCLUDED.name,
                    EXCLUDED.severity,
                    EXCLUDED.score,
                    EXCLUDED.issue_time,
                    EXCLUDED.package_id,
                    EXCLUDED.package_version,
                    EXCLUDED.cves_json,
                    EXCLUDED.metrics_json,
                    EXCLUDED.raw_record_json
                )
                RETURNING internal_id
                    """,
                    [list(column) for column in columns],
                ).fetchall()
                batch_changed = [row["internal_id"] for row in changed_rows]
                changed_passport_ids.extend(batch_changed)
                # Unchanged rows kept their content; mark them as seen without
                # touching the columns the CVE/OS-family trigger watches.
                cursor.execute(
                    """
                    UPDATE vulnerability_passports
                    SET last_seen = %s, source_pdql = %s, pdql_token = %s
                    WHERE internal_id = ANY(%s)
                      AND internal_id <> ALL(%s)
                    """,
                    (current, source_pdql, pdql_token, list(columns[0]), batch_changed),
                )
                if progress:
                    progress("save", min(offset + PASSPORT_SAVE_BATCH_SIZE, len(values)), len(values))
            id_replacements, ambiguous, stale = (
                _plan_passport_id_replacements(cursor, values, known_ids, full_catalog=full_catalog)
                if allow_replacements else ([], 0, 0)
            )
            if id_replacements:
                cursor.execute(
                    """
                    CREATE TEMP TABLE passport_id_replacements (
                        old_id TEXT PRIMARY KEY,
                        new_id TEXT NOT NULL
                    ) ON COMMIT DROP
                    """
                )
                cursor.executemany(
                    "INSERT INTO passport_id_replacements(old_id, new_id) VALUES (%s, %s)",
                    id_replacements,
                )
                # Several old rows can fold into one new row: take the earliest
                # first_seen and the most recently loaded detail among them.
                cursor.execute(
                    """
                    UPDATE vulnerability_passports AS target
                    SET raw_detail_json = COALESCE(target.raw_detail_json, previous.raw_detail_json),
                        first_seen = LEAST(target.first_seen, previous.first_seen),
                        detail_updated_at = CASE WHEN target.raw_detail_json IS NULL
                            THEN NULL ELSE target.detail_updated_at END
                    FROM (
                        SELECT replacement.new_id,
                               MIN(old.first_seen) AS first_seen,
                               (ARRAY_AGG(old.raw_detail_json
                                          ORDER BY old.detail_updated_at DESC NULLS LAST)
                                FILTER (WHERE old.raw_detail_json IS NOT NULL))[1] AS raw_detail_json
                        FROM passport_id_replacements AS replacement
                        JOIN vulnerability_passports AS old
                          ON old.internal_id = replacement.old_id
                        GROUP BY replacement.new_id
                    ) AS previous
                    WHERE target.internal_id = previous.new_id
                    """
                )
                cursor.execute(
                    """
                    DELETE FROM asset_card_vulnerability_passports AS old_link
                    USING passport_id_replacements AS replacement,
                          asset_card_vulnerability_passports AS new_link
                    WHERE old_link.passport_internal_id = replacement.old_id
                      AND new_link.passport_internal_id = replacement.new_id
                      AND new_link.asset_vulnerability_id = old_link.asset_vulnerability_id
                    """
                )
                cursor.execute(
                    """
                    UPDATE asset_card_vulnerability_passports AS link
                    SET passport_internal_id = replacement.new_id
                    FROM passport_id_replacements AS replacement
                    WHERE link.passport_internal_id = replacement.old_id
                    """
                )
                cursor.execute(
                    """
                    UPDATE remediation_cases AS remediation
                    SET passport_internal_id = replacement.new_id
                    FROM passport_id_replacements AS replacement
                    WHERE remediation.passport_internal_id = replacement.old_id
                    """
                )
                cursor.execute(
                    """
                    INSERT INTO vulnerability_passport_trends (
                        passport_internal_id, description, is_trend_since,
                        vendors_json, affected_components_json, source_pdql,
                        pdql_token, synced_at
                    )
                    SELECT replacement.new_id, trend.description, trend.is_trend_since,
                           trend.vendors_json, trend.affected_components_json,
                           trend.source_pdql, trend.pdql_token, trend.synced_at
                    FROM vulnerability_passport_trends AS trend
                    JOIN passport_id_replacements AS replacement
                      ON replacement.old_id = trend.passport_internal_id
                    ON CONFLICT (passport_internal_id) DO NOTHING
                    """
                )
                # A later detail relink must still resolve findings with no CVE.
                # Only normalized IDs change; scan evidence/timestamps stay intact.
                rebind_reissued_findings(conn)
                # A single large DELETE pays for all FK checks in one statement
                # and can exceed PostgreSQL statement_timeout on large catalogs.
                for offset in range(0, len(id_replacements), 1000):
                    old_ids = [old_id for old_id, _ in id_replacements[offset : offset + 1000]]
                    cursor.execute(
                        "DELETE FROM vulnerability_passports WHERE internal_id = ANY(%s)",
                        (old_ids,),
                    )
                replaced = len(id_replacements)
        # A passport that absorbed older ones can now be the best match for
        # findings that were linked to none of them, so relink it as well.
        relink_ids = list(
            dict.fromkeys([*changed_passport_ids, *(new_id for _, new_id in id_replacements)])
        )
        links_created = reconcile_asset_card_vulnerability_passport_links(
            conn,
            relink_ids,
            current,
            progress=(lambda done, total: progress("link", done, total)) if progress else None,
        )
    # Rows and filter columns changed: cached list totals are stale.
    invalidate_passport_totals()
    return {
        "saved": len(values),
        "changed": len(changed_passport_ids),
        "skipped": skipped,
        "replaced": replaced,
        "ambiguous": ambiguous,
        "stale": stale,
        "passport_links": links_created,
    }


def get_vulnerability_passport(internal_id: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerability_passports WHERE internal_id = %s",
            (internal_id,),
        ).fetchone()
    return decode_vulnerability_passport(dict(row)) if row else None


def delete_vulnerability_passport(internal_id: str) -> bool:
    schema.init_db()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        row = conn.execute(
            "DELETE FROM vulnerability_passports WHERE internal_id = %s RETURNING internal_id",
            (internal_id,),
        ).fetchone()
    # Invalidate even when nothing was deleted: a concurrent writer may have
    # committed between our read of the cache key and this point.
    invalidate_passport_totals()
    return row is not None


def list_vulnerability_passports(
    *,
    q: str | None = None,
    severity: str | None = None,
    pdql_token: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str | None = None,
) -> dict[str, Any]:
    schema.init_db()
    filters: list[str] = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append(
            """
            (
                internal_id ILIKE %s OR external_id ILIKE %s OR name ILIKE %s OR
                package_id ILIKE %s OR package_version ILIKE %s OR cves_json ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like, like])
    if severity:
        # LOWER(severity) — not LOWER(COALESCE(severity, '')) — so the predicate
        # matches the idx_vulnerability_passports_severity_lower index. The
        # COALESCE variant is equivalent for every non-empty filter (the
        # ``if severity`` guard above rejects empty input; NULL severity never
        # equals a non-empty literal).
        filters.append("LOWER(severity) = LOWER(%s)")
        params.append(severity)
    if pdql_token:
        filters.append("pdql_token = %s")
        params.append(pdql_token)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = min(200, max(1, limit))
    offset = max(0, offset)
    if sort_by:
        sort_expression, direction = validated_sort_sql(
            sort_by,
            sort_dir,
            {
                "name": "LOWER(name)", "external_id": "LOWER(external_id)",
                "severity": "CASE LOWER(COALESCE(severity, '')) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'none' THEN 5 ELSE 6 END",
                "score": "CASE WHEN REPLACE(COALESCE(score, ''), ',', '.') ~ '^[0-9]+([.][0-9]+)?$' THEN REPLACE(score, ',', '.')::numeric ELSE NULL END",
                "package": "LOWER(package_id)", "issue_time": "issue_time", "detail_updated_at": "detail_updated_at", "internal_id": "LOWER(internal_id)",
            },
            default="severity",
        )
        order_sql = f"{sort_expression} {direction} NULLS LAST, internal_id ASC"
    else:
        order_sql = """
            CASE LOWER(COALESCE(severity, '')) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'none' THEN 5 ELSE 6 END,
            CASE WHEN REPLACE(COALESCE(score, ''), ',', '.') ~ '^[0-9]+([.][0-9]+)?$' THEN REPLACE(score, ',', '.')::numeric ELSE NULL END DESC NULLS LAST,
            name NULLS LAST, internal_id
        """

    counts_key = passport_total_key(q, severity, pdql_token)
    total = cached_passport_total(counts_key)
    with connection.connect() as conn:
        if total is None:
            # The total only changes when the catalog changes (every write
            # path invalidates the memo), so page switches reuse it.
            total_row = conn.execute(f"SELECT COUNT(*) AS count FROM vulnerability_passports {where}", params).fetchone()
            assert total_row is not None
            total = int(total_row["count"] or 0)
            remember_passport_total(counts_key, total)
        # Deferred join: sort and page on the narrow ``id`` column first,
        # then fetch the wide rows (including the raw_detail_json blob needed
        # for short_description) for the page only. Sorting 500k rows with a
        # 2.4 KB average blob is what made the list endpoint slow.
        page_ids = [
            row["id"]
            for row in conn.execute(
                f"SELECT id FROM vulnerability_passports {where} ORDER BY {order_sql} LIMIT %s OFFSET %s",
                [*params, limit, offset],
            ).fetchall()
        ]
        if page_ids:
            rows = conn.execute(
                f"""
                SELECT
                    id, internal_id, external_id, name, severity, score, issue_time,
                    package_id, package_version, cves_json, metrics_json,
                    raw_detail_json, first_seen, last_seen, detail_updated_at,
                    (raw_detail_json IS NOT NULL) AS has_detail
                FROM vulnerability_passports
                WHERE id = ANY(%s)
                ORDER BY {order_sql}
                """,
                (page_ids,),
            ).fetchall()
        else:
            rows = []
    return {
        "total": total,
        "rows": [decode_vulnerability_passport_summary(dict(row)) for row in rows],
        "limit": limit,
        "offset": offset,
    }
