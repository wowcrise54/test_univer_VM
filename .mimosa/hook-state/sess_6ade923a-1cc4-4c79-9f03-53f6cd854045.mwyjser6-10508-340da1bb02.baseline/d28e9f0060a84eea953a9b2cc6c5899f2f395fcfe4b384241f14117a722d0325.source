"""Rebuild of asset card to vulnerability passport links after catalog, detail, or trend changes."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import psycopg

from ...diagnostics import log_event
from ...persistence import connection, locks, schema

_RECONCILE_CHUNK_FINDINGS = 5000


# A full relink handles this many findings per statement.
_RECONCILE_FULL_CHUNK_FINDINGS = 10000


# Above this many changed passports a relink of every asset is the cheaper plan.
_RECONCILE_TARGETED_MAX_PASSPORTS = 20000


def _passport_link_scopes(
    conn: psycopg.Connection[dict[str, Any]],
    passport_ids: list[str] | None,
    asset_id: str | None,
) -> list[tuple[str, tuple[Any, ...]]]:
    """Finding scopes (SQL condition, parameters) to relink, each a bounded statement.

    One statement over every finding of every asset exceeds statement_timeout on
    a large catalog, which rolled back the whole passport save with it.
    """

    if asset_id is not None:
        return [("finding.asset_id = %s", (asset_id,))]
    if passport_ids is not None and len(passport_ids) > _RECONCILE_TARGETED_MAX_PASSPORTS:
        # Looking up the findings of this many passports costs more than
        # relinking every asset (a full catalog refresh timed out here).
        passport_ids = None
    if passport_ids is None:
        # Chunk by finding id, not by asset: an asset can own any number of
        # findings, so a fixed asset count gave statements of unbounded size.
        starts = [
            row["id"]
            for row in conn.execute(
                """
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS position
                    FROM asset_card_vulnerabilities
                ) AS ordered
                WHERE (position - 1) %% %s = 0
                ORDER BY id
                """,
                (_RECONCILE_FULL_CHUNK_FINDINGS,),
            ).fetchall()
        ]
        scopes: list[tuple[str, tuple[Any, ...]]] = [
            ("finding.id >= %s AND finding.id < %s", (low, high))
            for low, high in zip(starts, starts[1:], strict=False)
        ]
        if starts:
            scopes.append(("finding.id >= %s", (starts[-1],)))
        return scopes
    if not passport_ids:
        return []
    # A changed passport can only affect findings that name it, share a CVE with
    # it, or are linked to it now.
    finding_ids = [
        row["id"]
        for row in conn.execute(
            """
            SELECT finding.id
            FROM asset_card_vulnerabilities AS finding
            WHERE finding.vulnerability_id = ANY(%s)
            UNION
            SELECT finding.id
            FROM vulnerability_passport_cves AS passport_cve
            JOIN asset_card_vulnerabilities AS finding
              ON UPPER(TRIM(finding.cve_name)) = passport_cve.cve_name
            WHERE passport_cve.passport_internal_id = ANY(%s)
            UNION
            SELECT link.asset_vulnerability_id
            FROM asset_card_vulnerability_passports AS link
            WHERE link.passport_internal_id = ANY(%s)
            ORDER BY 1
            """,
            (passport_ids, passport_ids, passport_ids),
        ).fetchall()
    ]
    return [
        ("finding.id = ANY(%s)", (finding_ids[offset : offset + _RECONCILE_CHUNK_FINDINGS],))
        for offset in range(0, len(finding_ids), _RECONCILE_CHUNK_FINDINGS)
    ]


def reconcile_asset_card_vulnerability_passport_links(
    conn: psycopg.Connection[dict[str, Any]],
    passport_ids: list[str] | None,
    linked_at: str,
    asset_id: str | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> int:
    """Choose one best passport per finding using vulnerability and host OS context.

    ``passport_ids`` limits the relink to findings those passports can affect;
    ``None`` relinks every finding, one bounded chunk of assets at a time.
    ``progress(done_chunks, total_chunks)`` is called after each chunk.
    """

    locks._lock_vulnerability_passport_writes(conn)
    inserted_total = 0
    scopes = _passport_link_scopes(conn, passport_ids, asset_id)
    for done, (scope_sql, scope_params) in enumerate(scopes, start=1):
        chunk_started = time.perf_counter()
        conn.execute(
            f"""
            DELETE FROM asset_card_vulnerability_passports AS link
            USING asset_card_vulnerabilities AS finding
            WHERE finding.id = link.asset_vulnerability_id
              AND {scope_sql}
            """,
            scope_params,
        )
        inserted = conn.execute(
            f"""
            WITH scoped_finding AS MATERIALIZED (
                SELECT finding.id, finding.asset_id, finding.group_id,
                       finding.vulnerability_id, finding.cve_name
                FROM asset_card_vulnerabilities AS finding
                WHERE {scope_sql}
            ), group_image AS MATERIALIZED (
                -- Parse each group's JSON once, not once per finding.
                SELECT vulnerability_group.id,
                       vulnerability_group.group_json::jsonb ->> 'image_os_name' AS image_os_name,
                       vulnerability_group.group_json::jsonb ->> 'image_os_version' AS image_os_version
                FROM asset_card_vulnerability_groups AS vulnerability_group
                WHERE vulnerability_group.id IN (SELECT group_id FROM scoped_finding)
            ), finding_base AS (
                SELECT
                    finding.id AS finding_id,
                    NULLIF(TRIM(finding.vulnerability_id), '') AS vulnerability_id,
                    UPPER(NULLIF(TRIM(finding.cve_name), '')) AS cve_name,
                    LOWER(COALESCE(
                        NULLIF(group_image.image_os_name, ''),
                        card.os_name,
                        ''
                    )) AS os_name,
                    LOWER(COALESCE(
                        NULLIF(group_image.image_os_version, ''),
                        card.os_version,
                        ''
                    )) AS os_version
                FROM scoped_finding AS finding
                JOIN asset_cards AS card ON card.asset_id = finding.asset_id
                JOIN group_image ON group_image.id = finding.group_id
            ), finding_context AS (
                SELECT finding_base.*,
                    SUBSTRING(
                        os_version FROM
                        '[0-9]+[.][0-9]+[.][0-9]+|[0-9]+[.][0-9]+|[0-9]+'
                    ) AS os_version_token,
                    CASE
                        WHEN os_name ~ 'windows' THEN 'windows'
                        WHEN os_name ~ 'ubuntu' THEN 'ubuntu'
                        WHEN os_name ~ 'debian' THEN 'debian'
                        WHEN os_name ~ 'red hat|redhat|rhel' THEN 'rhel'
                        WHEN os_name ~ 'centos' THEN 'centos'
                        WHEN os_name ~ 'rocky' THEN 'rocky'
                        WHEN os_name ~ 'alma' THEN 'almalinux'
                        WHEN os_name ~ 'oracle.*linux' THEN 'oraclelinux'
                        WHEN os_name ~ 'astra' THEN 'astra'
                        WHEN os_name ~ '(^|[^a-z])alt([^a-z]|$)' THEN 'altlinux'
                        WHEN os_name ~ 'suse|sles|opensuse' THEN 'suse'
                        ELSE NULL
                    END AS os_family
                FROM finding_base
            ), relevant_passport AS MATERIALIZED (
                -- Two index-driven lookups; an OR of IN-subqueries made every
                -- chunk scan the whole passport catalog.
                SELECT vulnerability_id AS internal_id FROM finding_base
                WHERE vulnerability_id IS NOT NULL
                UNION
                SELECT matched.passport_internal_id
                FROM (SELECT DISTINCT cve_name FROM finding_base WHERE cve_name IS NOT NULL) AS wanted
                JOIN vulnerability_passport_cves AS matched
                  ON matched.cve_name = wanted.cve_name
            ), passport_context AS (
                SELECT
                    passport.internal_id,
                    passport.issue_time,
                    passport.raw_detail_json IS NOT NULL AS has_detail,
                    LOWER(CONCAT_WS(
                        ' ', passport.name, passport.package_id, passport.package_version
                    )) AS label_text,
                    COALESCE(passport_cve.cve_name, '') AS cve_name,
                    passport_os.os_family
                FROM relevant_passport
                JOIN vulnerability_passports AS passport
                  ON passport.internal_id = relevant_passport.internal_id
                LEFT JOIN vulnerability_passport_cves AS passport_cve
                  ON passport_cve.passport_internal_id = passport.internal_id
                LEFT JOIN vulnerability_passport_os_family AS passport_os
                  ON passport_os.passport_internal_id = passport.internal_id
            ), candidates AS (
                SELECT
                    finding.finding_id,
                    passport.internal_id,
                    'vulner_id'::text AS match_method,
                    1000 AS match_score,
                    passport.has_detail,
                    passport.issue_time
                FROM finding_context AS finding
                JOIN passport_context AS passport
                  ON passport.internal_id = finding.vulnerability_id

                UNION ALL

                SELECT
                    finding.finding_id,
                    passport.internal_id,
                    CASE
                        WHEN passport.os_family = finding.os_family
                             AND finding.os_version_token IS NOT NULL
                             AND POSITION(finding.os_version_token IN passport.label_text) > 0
                            THEN 'cve_os_version'
                        WHEN passport.os_family = finding.os_family THEN 'cve_os'
                        ELSE 'cve_generic'
                    END AS match_method,
                    100
                        + CASE WHEN passport.os_family = finding.os_family THEN 50 ELSE 0 END
                        + CASE
                            WHEN passport.os_family = finding.os_family
                                 AND finding.os_version_token IS NOT NULL
                                 AND POSITION(finding.os_version_token IN passport.label_text) > 0
                                THEN 20 ELSE 0
                          END AS match_score,
                    passport.has_detail,
                    passport.issue_time
                FROM finding_context AS finding
                JOIN passport_context AS passport
                  ON passport.cve_name = finding.cve_name
                WHERE finding.cve_name IS NOT NULL
                  AND passport.cve_name <> ''
                  AND (
                      passport.os_family IS NULL
                      OR (
                          finding.os_family IS NOT NULL
                          AND passport.os_family = finding.os_family
                      )
                  )
            ), ranked AS (
                SELECT candidates.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY finding_id
                        ORDER BY match_score DESC, has_detail DESC,
                                 issue_time DESC NULLS LAST, internal_id
                    ) AS candidate_rank
                FROM candidates
            )
            INSERT INTO asset_card_vulnerability_passports (
                asset_vulnerability_id, passport_internal_id, match_method, linked_at
            )
            SELECT finding_id, internal_id, match_method, %s
            FROM ranked
            WHERE candidate_rank = 1
            ON CONFLICT(asset_vulnerability_id) DO UPDATE SET
                passport_internal_id = EXCLUDED.passport_internal_id,
                match_method = EXCLUDED.match_method,
                linked_at = EXCLUDED.linked_at
            """,
        (*scope_params, linked_at),
        )
        inserted_total += max(inserted.rowcount or 0, 0)
        if len(scopes) > 1:
            log_event(
                "passport-link",
                "relink.chunk.completed",
                chunk=done,
                chunks=len(scopes),
                links=max(inserted.rowcount or 0, 0),
                duration_ms=round((time.perf_counter() - chunk_started) * 1000),
            )
        if progress:
            progress(done, len(scopes))
    return inserted_total


def list_asset_card_links_for_vulnerability_passport(passport_id: str) -> list[dict[str, Any]]:
    schema.init_db()
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT
                card.asset_id,
                card.display_name,
                card.ip_address,
                card.fqdn,
                finding.cve_name,
                finding.name AS vulnerability_name,
                finding.vulnerability_instance_id,
                link.match_method,
                link.linked_at
            FROM asset_card_vulnerability_passports AS link
            JOIN asset_card_vulnerabilities AS finding
                ON finding.id = link.asset_vulnerability_id
            JOIN asset_cards AS card ON card.asset_id = finding.asset_id
            WHERE link.passport_internal_id = %s
            ORDER BY card.display_name NULLS LAST, card.asset_id, finding.cve_name NULLS LAST
            """,
            (passport_id,),
        ).fetchall()
    return [dict(row) for row in rows]
