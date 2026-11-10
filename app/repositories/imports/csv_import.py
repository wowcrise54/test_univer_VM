"""Repository for importing MP VM CSV exports: rows are upserted into PostgreSQL in a single transaction; asset removal from MP VM happens only in a separate later operation."""

from __future__ import annotations

import json
from typing import Any

from ...persistence import codecs, connection, schema
from ...persistence.codecs import clean_value, first_value, make_csv_reader, normalize_row
from .assets import (
    cleanup_orphans,
    collect_asset_identity,
    delete_findings_for_assets,
    empty_asset_identity_set,
    resolve_assets_for_replacement,
    upsert_asset,
    upsert_software,
)
from .runs import create_import_run, finish_import_run


def import_csv_text(
    csv_text: str,
    *,
    source: str,
    pdql: str | None = None,
    csv_filename: str | None = None,
    delete_after_export: bool = False,
) -> dict[str, Any]:
    schema.init_db()
    run_id = create_import_run(
        source=source,
        pdql=pdql,
        csv_filename=csv_filename,
        delete_after_export=delete_after_export,
    )
    row_count = 0
    finding_count = 0
    asset_ids: set[int] = set()
    try:
        reader = make_csv_reader(csv_text)
        rows: list[tuple[dict[str, Any], dict[str, str]]] = []
        for raw_row in reader:
            row = normalize_row(raw_row)
            if not any(row.values()):
                continue
            rows.append((raw_row, row))
        row_count = len(rows)

        with connection.connect() as conn:
            prepared_rows: list[tuple[dict[str, Any], dict[str, str], int, int | None]] = []
            affected = empty_asset_identity_set()

            for raw_row, row in rows:
                asset_id = upsert_asset(conn, row)
                if asset_id is None:
                    continue
                asset_ids.add(asset_id)
                collect_asset_identity(affected, row)
                software_id = upsert_software(conn, row)
                prepared_rows.append((raw_row, row, asset_id, software_id))

            replacement_asset_ids = resolve_assets_for_replacement(conn, affected, asset_ids)
            delete_findings_for_assets(conn, replacement_asset_ids)

            for raw_row, row, asset_id, software_id in prepared_rows:
                conn.execute(
                    """
                    INSERT INTO vulnerability_findings (
                        import_run_id, asset_id, software_id, kind, vulnerability_name,
                        cve, severity, raw_row_json, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        run_id,
                        asset_id,
                        software_id,
                        "os" if row.get("OsVulner") or row.get("Host.OsName") else "software",
                        first_value(row, "SoftVulner", "OsVulner", "Vulnerability", "Vulner"),
                        clean_value(row.get("CVE")),
                        clean_value(row.get("SeverityRating") or row.get("Severity")),
                        json.dumps(raw_row, ensure_ascii=False),
                        codecs.now_utc(),
                    ),
                )
                finding_count += 1
            cleanup_orphans(conn)
        finish_import_run(
            run_id,
            row_count=row_count,
            asset_count=len(asset_ids),
            finding_count=finding_count,
        )
    except Exception as exc:
        finish_import_run(
            run_id,
            row_count=row_count,
            asset_count=len(asset_ids),
            finding_count=finding_count,
            status="failed",
            error=str(exc),
        )
        raise

    return {
        "run_id": run_id,
        "row_count": row_count,
        "asset_count": len(asset_ids),
        "finding_count": finding_count,
    }
