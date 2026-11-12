"""Repository for assets: findings listing, dashboard summary, and asset removal records."""

from __future__ import annotations

import json
from typing import Any

from ..persistence import codecs, connection
from ..persistence.sql import rows_to_dicts, validated_sort_sql


def list_asset_findings(
    *,
    q: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str | None = None,
) -> dict[str, Any]:
    filters: list[str] = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append(
            "(a.ip_address ILIKE %s OR a.fqdn ILIKE %s OR s.name ILIKE %s OR vf.vulnerability_name ILIKE %s OR vf.cve ILIKE %s)"
        )
        params.extend([like, like, like, like, like])
    if severity:
        filters.append("LOWER(COALESCE(vf.severity, '')) = LOWER(%s)")
        params.append(severity)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    if sort_by:
        sort_expression, direction = validated_sort_sql(
            sort_by,
            sort_dir,
            {"ip_address": "LOWER(a.ip_address)", "fqdn": "LOWER(a.fqdn)", "software_name": "LOWER(s.name)", "software_version": "LOWER(s.version)", "vulnerability_name": "LOWER(vf.vulnerability_name)", "cve": "LOWER(vf.cve)", "severity": "CASE LOWER(COALESCE(vf.severity, '')) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'none' THEN 5 ELSE 6 END", "created_at": "vf.created_at"},
            default="severity",
        )
        order_sql = f"{sort_expression} {direction} NULLS LAST, vf.id ASC"
    else:
        order_sql = """
            CASE LOWER(COALESCE(vf.severity, '')) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'none' THEN 5 ELSE 6 END,
            a.ip_address, s.name, vf.cve
        """

    with connection.connect() as conn:
        total_row = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM vulnerability_findings vf
            JOIN assets a ON a.id = vf.asset_id
            LEFT JOIN software s ON s.id = vf.software_id
            {where}
            """,
            params,
        ).fetchone()
        rows = conn.execute(
            f"""
            SELECT
                vf.id,
                vf.import_run_id,
                vf.kind,
                a.ip_address,
                a.fqdn,
                s.name AS software_name,
                s.version AS software_version,
                vf.vulnerability_name,
                vf.cve,
                vf.severity,
                vf.created_at
            FROM vulnerability_findings vf
            JOIN assets a ON a.id = vf.asset_id
            LEFT JOIN software s ON s.id = vf.software_id
            {where}
            ORDER BY {order_sql}
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    assert total_row is not None
    return {"total": int(total_row["count"]), "rows": rows_to_dicts(rows), "limit": limit, "offset": offset}


def get_summary() -> dict[str, Any]:
    with connection.connect() as conn:
        counts = conn.execute(
            """
            SELECT
                COUNT(DISTINCT asset_id) AS assets,
                COUNT(DISTINCT software_id) AS software,
                COUNT(*) AS findings,
                SUM(CASE WHEN cve IS NOT NULL AND cve != '' THEN 1 ELSE 0 END) AS cve_rows
            FROM vulnerability_findings
            """
        ).fetchone()
        severity_rows = conn.execute(
            """
            SELECT COALESCE(NULLIF(LOWER(severity), ''), 'empty') AS severity, COUNT(*) AS count
            FROM vulnerability_findings
            GROUP BY COALESCE(NULLIF(LOWER(severity), ''), 'empty')
            ORDER BY count DESC
            """
        ).fetchall()
        recent_imports = conn.execute(
            """
            SELECT id, source, csv_filename, row_count, asset_count, finding_count, status, started_at, finished_at
            FROM import_runs
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()
    assert counts is not None
    return {
        "assets": int(counts["assets"] or 0),
        "software": int(counts["software"] or 0),
        "findings": int(counts["findings"] or 0),
        "cve_rows": int(counts["cve_rows"] or 0),
        "severity": rows_to_dicts(severity_rows),
        "recent_imports": rows_to_dicts(recent_imports),
    }


def record_asset_removal(
    *,
    import_run_id: int | None,
    operation_id: str | None,
    asset_ids: list[str],
    status: str,
    message: str | None = None,
    raw_response: dict[str, Any] | None = None,
) -> int:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO asset_removal_operations (
                import_run_id, operation_id, asset_ids_json, status, message,
                raw_response_json, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                import_run_id,
                operation_id,
                json.dumps(asset_ids, ensure_ascii=False),
                status,
                message,
                json.dumps(raw_response or {}, ensure_ascii=False),
                current,
                current,
            ),
        ).fetchone()
        assert row is not None
        removal_id = int(row["id"])
        if import_run_id and operation_id:
            conn.execute(
                "UPDATE import_runs SET asset_removal_operation_id = %s WHERE id = %s",
                (operation_id, import_run_id),
            )
        return removal_id
