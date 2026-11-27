"""Read the host package collection and matching local passport rules."""

from datetime import datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from ...persistence import connection


def inventory_package_names() -> list[dict[str, Any]]:
    with connection.connect() as conn:
        return conn.execute(
            """
            SELECT DISTINCT card.os_name, card.os_version, item.data_json::jsonb ->> 'name' AS package
            FROM asset_cards AS card
            JOIN asset_card_collections AS collection ON collection.asset_id = card.asset_id
              AND collection.name = 'packages'
              AND collection.parent_object_id = card.root_json::jsonb ->> 'objectId'
            JOIN asset_card_collection_items AS item
              ON item.asset_id = collection.asset_id AND item.collection_path = collection.path
            WHERE item.object_type IN (
                'OperatingSystem.UNIX.Linux.Debian.UbuntuPackage',
                'OperatingSystem.UNIX.Linux.Debian.DebianPackage'
            )
            """
        ).fetchall()


def read_inventory(conn: psycopg.Connection[dict[str, Any]], asset_id: str) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT card.os_name, card.os_version, card.last_seen,
               inventory.complete, inventory.packages
        FROM asset_cards AS card
        LEFT JOIN LATERAL (
            SELECT NOT collection.truncated
                   AND COUNT(*) = collection.reported_count
                   AND COUNT(*) = collection.fetched_count AS complete,
                   jsonb_agg(jsonb_build_array(item.data_json::jsonb->>'name',
                                             item.data_json::jsonb->>'version')) AS packages
            FROM asset_card_collections AS collection
            JOIN asset_card_collection_items AS item
              ON item.asset_id = collection.asset_id AND item.collection_path = collection.path
            WHERE collection.asset_id = card.asset_id
              AND collection.name = 'packages'
              AND collection.parent_object_id = card.root_json::jsonb->>'objectId'
              AND item.object_type = CASE lower(trim(card.os_name))
                  WHEN 'ubuntu' THEN 'OperatingSystem.UNIX.Linux.Debian.UbuntuPackage'
                  WHEN 'debian' THEN 'OperatingSystem.UNIX.Linux.Debian.DebianPackage'
              END
            GROUP BY collection.path, collection.truncated,
                     collection.reported_count, collection.fetched_count
            ORDER BY collection.path
            LIMIT 1
        ) AS inventory ON TRUE
        WHERE card.asset_id = %s
        """,
        (asset_id,),
    ).fetchone()


def read_existing_cves(conn: psycopg.Connection[dict[str, Any]], asset_id: str) -> set[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT UPPER(TRIM(cve_name)) AS cve
        FROM asset_card_vulnerabilities
        WHERE asset_id = %s AND cve_name IS NOT NULL
        """,
        (asset_id,),
    ).fetchall()
    return {row["cve"] for row in rows}


def read_rules(conn: psycopg.Connection[dict[str, Any]], vendor: str, release: str, packages: list[str]) -> list[dict[str, Any]]:
    return conn.execute(
        """
        SELECT passport_id, package_name, default_status, versions
        FROM wazuh_cti_package_rules
        WHERE vendor = %s AND release = %s AND package_name = ANY(%s)
        ORDER BY package_name, passport_id
        """,
        (vendor, release, packages),
    ).fetchall()


def due_asset_ids(after: str, cutoff: datetime, limit: int) -> list[str]:
    with connection.connect() as conn:
        rows = conn.execute(
            """
            SELECT card.asset_id
            FROM asset_cards AS card
            LEFT JOIN wazuh_asset_assessments AS assessment USING (asset_id)
            WHERE card.asset_id > %s
              AND lower(trim(card.os_name)) IN ('ubuntu', 'debian')
              AND (assessment.inventory_at IS DISTINCT FROM card.last_seen
                   OR assessment.checked_at < %s)
            ORDER BY card.asset_id
            LIMIT %s
            """,
            (after, cutoff, limit),
        ).fetchall()
    return [row["asset_id"] for row in rows]


def claim_due_asset(conn: psycopg.Connection[dict[str, Any]], asset_id: str, cutoff: datetime) -> bool:
    claim = conn.execute(
        "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0)) AS acquired",
        (f"wazuh-asset-assessment:{asset_id}",),
    ).fetchone()
    if claim is None or not claim["acquired"]:
        return False
    return conn.execute(
        """
        SELECT 1
        FROM asset_cards AS card
        LEFT JOIN wazuh_asset_assessments AS assessment USING (asset_id)
        WHERE card.asset_id = %s
          AND lower(trim(card.os_name)) IN ('ubuntu', 'debian')
          AND (assessment.inventory_at IS DISTINCT FROM card.last_seen
               OR assessment.checked_at < %s)
        """,
        (asset_id, cutoff),
    ).fetchone() is not None


def save_assessment(conn: psycopg.Connection[dict[str, Any]], asset_id: str, result: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO wazuh_asset_assessments (asset_id, inventory_at, checked_at, result)
        SELECT asset_id, last_seen, clock_timestamp(), %s
        FROM asset_cards
        WHERE asset_id = %s AND last_seen = %s
        ON CONFLICT (asset_id) DO UPDATE
        SET inventory_at = EXCLUDED.inventory_at, checked_at = EXCLUDED.checked_at, result = EXCLUDED.result
        """,
        (Jsonb(result), asset_id, result["inventory_at"]),
    )


def read_assessment(conn: psycopg.Connection[dict[str, Any]], asset_id: str) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT card.os_name, card.os_version, card.last_seen, assessment.checked_at, assessment.result
        FROM asset_cards AS card
        LEFT JOIN wazuh_asset_assessments AS assessment
          ON assessment.asset_id = card.asset_id AND assessment.inventory_at = card.last_seen
        WHERE card.asset_id = %s
        """,
        (asset_id,),
    ).fetchone()


def read_passports(conn: psycopg.Connection[dict[str, Any]], passport_ids: list[str]) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT internal_id, name, NULLIF(score, '') AS cvss_score
        FROM vulnerability_passports
        WHERE internal_id = ANY(%s)
        """,
        (passport_ids,),
    ).fetchall()
    return {row["internal_id"]: row for row in rows}
