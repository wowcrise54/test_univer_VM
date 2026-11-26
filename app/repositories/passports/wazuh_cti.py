"""Persistence for the CVE-level Wazuh CTI passports."""

import json
from typing import Any

from psycopg.types.json import Jsonb

from ...persistence import codecs, connection, locks, schema
from .counts import invalidate_passport_totals
from .serializers import decode_vulnerability_passport


def create_passports() -> int:
    schema.init_db()
    now = codecs.now_utc()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        inserted = conn.execute(
            """
            INSERT INTO vulnerability_passports (internal_id, name, cves_json, first_seen, last_seen)
            SELECT 'wazuh-cti:' || cve_name, 'wazuh-cti · ' || cve_name,
                   json_build_array(json_build_object(
                       'display_name', cve_name,
                       'url', 'https://cti.wazuh.com/vulnerabilities/cves/' || cve_name
                   ))::text, %s, %s
            FROM (
                SELECT DISTINCT cve_name FROM vulnerability_passport_cves
                WHERE cve_name ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                  AND passport_internal_id NOT LIKE 'wazuh-cti:%%'
            ) AS observed
            ON CONFLICT (internal_id) DO NOTHING
            """,
            (now, now),
        ).rowcount
    if inserted:
        invalidate_passport_totals()
    return inserted


def save_detail(
    passport_id: str, detail: dict[str, Any], rules: list[tuple[str, str, str, str, list[dict[str, Any]]]],
) -> dict[str, Any] | None:
    now = codecs.now_utc()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        row = conn.execute(
            """
            UPDATE vulnerability_passports
            SET raw_detail_json = %s, severity = %s, score = %s, issue_time = %s,
                detail_updated_at = %s, last_seen = %s
            WHERE internal_id = %s
            RETURNING *
            """,
            (
                json.dumps(detail, ensure_ascii=False), detail["severity"],
                codecs.clean_value(detail["score"]), detail["publishedAt"], now, now, passport_id,
            ),
        ).fetchone()
        if row:
            conn.execute("DELETE FROM wazuh_cti_package_rules WHERE passport_id = %s", (passport_id,))
            if rules:
                with conn.cursor() as cursor:
                    cursor.executemany(
                        """
                        INSERT INTO wazuh_cti_package_rules
                            (passport_id, vendor, release, package_name, default_status, versions)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        [(passport_id, vendor, release, name, default, Jsonb(versions))
                         for vendor, release, name, default, versions in rules],
                    )
    if row:
        invalidate_passport_totals()
        return decode_vulnerability_passport(row)
    return None
