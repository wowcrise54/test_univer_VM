"""Planning of vulnerability passport identifier replacements before catalog upserts."""

from __future__ import annotations

from typing import Any

import psycopg

from ...mpvm.passport_records import plan_passport_replacements


def _plan_passport_id_replacements(
    cursor: psycopg.Cursor[dict[str, Any]],
    values: list[tuple[Any, ...]],
    known_ids: set[str],
    *,
    full_catalog: bool,
) -> tuple[list[tuple[str, str]], int, int]:
    """Pair stored passports MP VM re-issued under a new id with their successors.

    Returns ``(replacements, ambiguous, stale)``: ``(old_id, new_id)`` pairs to
    merge, successors that could not be told apart, and (complete refresh only)
    passports gone from MP VM that still have no successor.
    """

    columns = ("internal_id", "external_id", "package_id", "package_version")
    incoming = [
        dict(zip(columns, (value[0], value[1], value[6], value[7]), strict=True))
        for value in values
        if value[1]
    ]
    if not incoming:
        return [], 0, 0
    incoming_ids = {value[0] for value in values}
    if full_catalog:
        # Anything stored that the complete catalog did not return is gone from
        # MP VM. This also repairs duplicates left by earlier refreshes.
        stale_rows = [
            dict(row)
            for row in cursor.execute(
                """
                SELECT internal_id, external_id, package_id, package_version
                FROM vulnerability_passports
                WHERE external_id IS NOT NULL
                """
            ).fetchall()
            if row["internal_id"] not in incoming_ids
        ]
        successors = incoming
    else:
        # Without the full catalog an unseen passport may still be alive: trust
        # only exact matches, and only for passports new to the database.
        successors = [row for row in incoming if row["internal_id"] not in known_ids]
        stale_rows = []
        external_ids = sorted({row["external_id"] for row in successors})
        for offset in range(0, len(external_ids), 5000):
            stale_rows.extend(
                dict(row)
                for row in cursor.execute(
                    """
                    SELECT internal_id, external_id, package_id, package_version
                    FROM vulnerability_passports
                    WHERE external_id = ANY(%s)
                    FOR UPDATE
                    """,
                    (external_ids[offset : offset + 5000],),
                ).fetchall()
                if row["internal_id"] not in incoming_ids
            )
    pairs, ambiguous = plan_passport_replacements(successors, stale_rows, loose=full_catalog)
    paired_old = {old_id for old_id, _ in pairs}
    stale = (
        sum(1 for row in stale_rows if row["internal_id"] not in paired_old)
        if full_catalog
        else 0
    )
    return pairs, ambiguous, stale
