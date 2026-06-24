from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = (
    os.getenv("MPVM_DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or "postgresql://mpvm:mpvm@localhost:5432/mpvm"
)


def database_label() -> str:
    if "@" not in DATABASE_URL:
        return DATABASE_URL
    scheme, rest = DATABASE_URL.split("://", 1)
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> psycopg.Connection[dict[str, Any]]:
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    statements = [
        """
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id BIGSERIAL PRIMARY KEY,
            mp_task_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            scope_id TEXT,
            profile_id TEXT,
            agent_ids_json TEXT NOT NULL DEFAULT '[]',
            credential_id TEXT,
            include_targets_json TEXT NOT NULL DEFAULT '[]',
            exclude_targets_json TEXT NOT NULL DEFAULT '[]',
            host_discovery_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            host_discovery_profile_id TEXT,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'created',
            last_remote_response_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            deleted_at TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS import_runs (
            id BIGSERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            pdql TEXT,
            csv_filename TEXT,
            row_count INTEGER NOT NULL DEFAULT 0,
            asset_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            error TEXT,
            delete_after_export BOOLEAN NOT NULL DEFAULT FALSE,
            asset_removal_operation_id TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assets (
            id BIGSERIAL PRIMARY KEY,
            asset_key TEXT UNIQUE NOT NULL,
            mp_asset_id TEXT,
            ip_address TEXT,
            fqdn TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS software (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            UNIQUE(name, version)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS vulnerability_findings (
            id BIGSERIAL PRIMARY KEY,
            import_run_id BIGINT NOT NULL REFERENCES import_runs(id) ON DELETE CASCADE,
            asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            software_id BIGINT REFERENCES software(id) ON DELETE SET NULL,
            kind TEXT NOT NULL DEFAULT 'software',
            vulnerability_name TEXT,
            cve TEXT,
            severity TEXT,
            raw_row_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_removal_operations (
            id BIGSERIAL PRIMARY KEY,
            import_run_id BIGINT REFERENCES import_runs(id) ON DELETE SET NULL,
            operation_id TEXT,
            asset_ids_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL,
            message TEXT,
            raw_response_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS vulnerability_passports (
            id BIGSERIAL PRIMARY KEY,
            internal_id TEXT UNIQUE NOT NULL,
            external_id TEXT,
            name TEXT,
            severity TEXT,
            score TEXT,
            issue_time TEXT,
            package_id TEXT,
            package_version TEXT,
            cves_json TEXT NOT NULL DEFAULT '[]',
            metrics_json TEXT NOT NULL DEFAULT '{}',
            raw_record_json TEXT NOT NULL DEFAULT '{}',
            raw_detail_json TEXT,
            source_pdql TEXT,
            pdql_token TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            detail_updated_at TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_assets_fqdn_lower ON assets((LOWER(fqdn)))",
        "CREATE INDEX IF NOT EXISTS idx_assets_mp_asset_id ON assets(mp_asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_asset ON vulnerability_findings(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_software ON vulnerability_findings(software_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_import_run ON vulnerability_findings(import_run_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity_lower ON vulnerability_findings((LOWER(severity)))",
        "CREATE INDEX IF NOT EXISTS idx_findings_cve ON vulnerability_findings(cve)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passports_name_lower ON vulnerability_passports((LOWER(name)))",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passports_external_id ON vulnerability_passports(external_id)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passports_severity_lower ON vulnerability_passports((LOWER(severity)))",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passports_package ON vulnerability_passports(package_id, package_version)",
    ]
    with connect() as conn:
        for statement in statements:
            conn.execute(statement)


def rows_to_dicts(rows: list[Any]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def record_scan_task(
    *,
    mp_task_id: str,
    payload: dict[str, Any],
    status: str,
    remote_response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = now_utc()
    include = payload.get("include") if isinstance(payload.get("include"), dict) else {}
    exclude = payload.get("exclude") if isinstance(payload.get("exclude"), dict) else {}
    agents = payload.get("agents") if isinstance(payload.get("agents"), dict) else {}
    host_discovery = payload.get("hostDiscovery") if isinstance(payload.get("hostDiscovery"), dict) else {}
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_tasks (
                mp_task_id, name, description, scope_id, profile_id, agent_ids_json, credential_id,
                include_targets_json, exclude_targets_json, host_discovery_enabled,
                host_discovery_profile_id, payload_json, status, last_remote_response_json,
                created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(mp_task_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                scope_id = EXCLUDED.scope_id,
                profile_id = EXCLUDED.profile_id,
                agent_ids_json = EXCLUDED.agent_ids_json,
                credential_id = EXCLUDED.credential_id,
                include_targets_json = EXCLUDED.include_targets_json,
                exclude_targets_json = EXCLUDED.exclude_targets_json,
                host_discovery_enabled = EXCLUDED.host_discovery_enabled,
                host_discovery_profile_id = EXCLUDED.host_discovery_profile_id,
                payload_json = EXCLUDED.payload_json,
                status = EXCLUDED.status,
                last_remote_response_json = EXCLUDED.last_remote_response_json,
                updated_at = EXCLUDED.updated_at,
                deleted_at = NULL
            """,
            (
                mp_task_id,
                payload.get("name", mp_task_id),
                payload.get("description", ""),
                payload.get("scope"),
                payload.get("profile"),
                json.dumps(agents.get("agentIds", []), ensure_ascii=False),
                _credential_id_from_payload(payload),
                json.dumps(include.get("targets", []), ensure_ascii=False),
                json.dumps(exclude.get("targets", []), ensure_ascii=False),
                bool(host_discovery.get("enabled")),
                host_discovery.get("profile"),
                json.dumps(payload, ensure_ascii=False),
                status,
                json.dumps(remote_response or {}, ensure_ascii=False),
                current,
                current,
            ),
        )
    return get_scan_task(mp_task_id) or {}


def update_scan_task_status(mp_task_id: str, status: str, remote_response: dict[str, Any] | None = None) -> None:
    current = now_utc()
    with connect() as conn:
        conn.execute(
            """
            UPDATE scan_tasks
            SET status = %s, last_remote_response_json = %s, updated_at = %s
            WHERE mp_task_id = %s
            """,
            (status, json.dumps(remote_response or {}, ensure_ascii=False), current, mp_task_id),
        )


def mark_scan_task_deleted(mp_task_id: str, remote_response: dict[str, Any] | None = None) -> None:
    current = now_utc()
    with connect() as conn:
        conn.execute(
            """
            UPDATE scan_tasks
            SET status = 'deleted', deleted_at = %s, updated_at = %s, last_remote_response_json = %s
            WHERE mp_task_id = %s
            """,
            (current, current, json.dumps(remote_response or {}, ensure_ascii=False), mp_task_id),
        )


def delete_scan_task(mp_task_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM scan_tasks WHERE mp_task_id = %s", (mp_task_id,))


def list_scan_tasks() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scan_tasks ORDER BY updated_at DESC, id DESC").fetchall()
    return [_decode_scan_task(dict(row)) for row in rows]


def get_scan_task(mp_task_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan_tasks WHERE mp_task_id = %s", (mp_task_id,)).fetchone()
    return _decode_scan_task(dict(row)) if row else None


def create_import_run(
    *,
    source: str,
    pdql: str | None = None,
    csv_filename: str | None = None,
    delete_after_export: bool = False,
) -> int:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO import_runs (source, pdql, csv_filename, delete_after_export, started_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (source, pdql, csv_filename, delete_after_export, current),
        ).fetchone()
        return int(row["id"])


def finish_import_run(
    run_id: int,
    *,
    row_count: int,
    asset_count: int,
    finding_count: int,
    status: str = "completed",
    error: str | None = None,
    asset_removal_operation_id: str | None = None,
) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE import_runs
            SET row_count = %s, asset_count = %s, finding_count = %s, status = %s, error = %s,
                asset_removal_operation_id = %s, finished_at = %s
            WHERE id = %s
            """,
            (
                row_count,
                asset_count,
                finding_count,
                status,
                error,
                asset_removal_operation_id,
                now_utc(),
                run_id,
            ),
        )


def import_csv_text(
    csv_text: str,
    *,
    source: str,
    pdql: str | None = None,
    csv_filename: str | None = None,
    delete_after_export: bool = False,
) -> dict[str, Any]:
    init_db()
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

        with connect() as conn:
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
                        now_utc(),
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


def empty_asset_identity_set() -> dict[str, set[str]]:
    return {"fqdns": set(), "mp_asset_ids": set(), "ips": set()}


def collect_asset_identity(affected: dict[str, set[str]], row: dict[str, str]) -> None:
    fqdn = first_value(row, "Host.Fqdn", "Fqdn", "HostName", "Hostname")
    mp_asset_id = first_value(row, "AssetId", "Host.@Id", "@Host", "HostId", "Id")
    ip_address = first_value(row, "Host.IpAddress", "IpAddress", "IP")
    if fqdn:
        affected["fqdns"].add(fqdn.casefold())
    if mp_asset_id:
        affected["mp_asset_ids"].add(mp_asset_id)
    if ip_address:
        affected["ips"].add(ip_address)


def resolve_assets_for_replacement(
    conn: psycopg.Connection[dict[str, Any]],
    affected: dict[str, set[str]],
    current_asset_ids: set[int],
) -> set[int]:
    """Find all local assets whose previous findings must be replaced by this import."""

    result = set(current_asset_ids)
    result.update(select_asset_ids_by_values(conn, "LOWER(fqdn)", affected["fqdns"]))
    result.update(select_asset_ids_by_values(conn, "mp_asset_id", affected["mp_asset_ids"]))

    # Use IP only for rows without a better identity; this keeps DHCP/reused IP
    # churn from wiping another host when FQDN is present in the export.
    if not affected["fqdns"] and not affected["mp_asset_ids"]:
        result.update(select_asset_ids_by_values(conn, "ip_address", affected["ips"]))
    return result


def select_asset_ids_by_values(
    conn: psycopg.Connection[dict[str, Any]],
    expression: str,
    values: set[str],
) -> set[int]:
    if not values:
        return set()
    result: set[int] = set()
    for chunk in chunked(sorted(values), 400):
        rows = conn.execute(
            f"SELECT id FROM assets WHERE {expression} = ANY(%s)",
            (chunk,),
        ).fetchall()
        result.update(int(row["id"]) for row in rows)
    return result


def delete_findings_for_assets(conn: psycopg.Connection[dict[str, Any]], asset_ids: set[int]) -> None:
    if not asset_ids:
        return
    for chunk in chunked(sorted(asset_ids), 400):
        conn.execute("DELETE FROM vulnerability_findings WHERE asset_id = ANY(%s)", (chunk,))


def cleanup_orphans(conn: psycopg.Connection[dict[str, Any]]) -> None:
    conn.execute(
        """
        DELETE FROM software
        WHERE NOT EXISTS (
            SELECT 1 FROM vulnerability_findings vf WHERE vf.software_id = software.id
        )
        """
    )
    conn.execute(
        """
        DELETE FROM assets
        WHERE NOT EXISTS (
            SELECT 1 FROM vulnerability_findings vf WHERE vf.asset_id = assets.id
        )
        """
    )


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def list_asset_findings(
    *,
    q: str | None = None,
    severity: str | None = None,
    limit: int = 200,
    offset: int = 0,
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

    with connect() as conn:
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
            ORDER BY
                CASE LOWER(COALESCE(vf.severity, ''))
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'none' THEN 5
                    ELSE 6
                END,
                a.ip_address,
                s.name,
                vf.cve
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    return {"total": int(total_row["count"]), "rows": rows_to_dicts(rows), "limit": limit, "offset": offset}


def get_summary() -> dict[str, Any]:
    with connect() as conn:
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
    return {
        "assets": int(counts["assets"] or 0),
        "software": int(counts["software"] or 0),
        "findings": int(counts["findings"] or 0),
        "cve_rows": int(counts["cve_rows"] or 0),
        "severity": rows_to_dicts(severity_rows),
        "recent_imports": rows_to_dicts(recent_imports),
    }


def upsert_vulnerability_passports(
    passports: list[dict[str, Any]],
    *,
    source_pdql: str | None = None,
    pdql_token: str | None = None,
) -> dict[str, Any]:
    init_db()
    current = now_utc()
    saved = 0
    skipped = 0
    with connect() as conn:
        for passport in passports:
            internal_id = clean_value(passport.get("internal_id"))
            if not internal_id:
                skipped += 1
                continue
            conn.execute(
                """
                INSERT INTO vulnerability_passports (
                    internal_id, external_id, name, severity, score, issue_time,
                    package_id, package_version, cves_json, metrics_json,
                    raw_record_json, source_pdql, pdql_token, first_seen, last_seen
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                """,
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
                ),
            )
            saved += 1
    return {"saved": saved, "skipped": skipped}


def upsert_vulnerability_passport_detail(internal_id: str, raw_detail: dict[str, Any]) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO vulnerability_passports (
                internal_id, raw_detail_json, first_seen, last_seen, detail_updated_at
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(internal_id) DO UPDATE SET
                raw_detail_json = EXCLUDED.raw_detail_json,
                last_seen = EXCLUDED.last_seen,
                detail_updated_at = EXCLUDED.detail_updated_at
            RETURNING *
            """,
            (
                internal_id,
                json.dumps(raw_detail or {}, ensure_ascii=False),
                current,
                current,
                current,
            ),
        ).fetchone()
    return decode_vulnerability_passport(dict(row)) if row else None


def get_vulnerability_passport(internal_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerability_passports WHERE internal_id = %s",
            (internal_id,),
        ).fetchone()
    return decode_vulnerability_passport(dict(row)) if row else None


def list_vulnerability_passports(
    *,
    q: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append(
            """
            (
                internal_id ILIKE %s OR external_id ILIKE %s OR name ILIKE %s OR
                package_id ILIKE %s OR package_version ILIKE %s OR cves_json ILIKE %s OR
                raw_record_json ILIKE %s OR COALESCE(raw_detail_json, '') ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like, like, like, like])
    if severity:
        filters.append("LOWER(COALESCE(severity, '')) = LOWER(%s)")
        params.append(severity)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = max(1, min(limit, 50000))
    offset = max(0, offset)

    with connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM vulnerability_passports {where}", params).fetchone()
        rows = conn.execute(
            f"""
            SELECT *
            FROM vulnerability_passports
            {where}
            ORDER BY
                CASE LOWER(COALESCE(severity, ''))
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'none' THEN 5
                    ELSE 6
                END,
                CASE
                    WHEN REPLACE(COALESCE(score, ''), ',', '.') ~ '^[0-9]+([.][0-9]+)?$'
                    THEN REPLACE(score, ',', '.')::numeric
                    ELSE NULL
                END DESC NULLS LAST,
                name NULLS LAST,
                internal_id
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    return {
        "total": int(total_row["count"] or 0),
        "rows": [decode_vulnerability_passport(dict(row)) for row in rows],
        "limit": limit,
        "offset": offset,
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
    current = now_utc()
    with connect() as conn:
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
        removal_id = int(row["id"])
        if import_run_id and operation_id:
            conn.execute(
                "UPDATE import_runs SET asset_removal_operation_id = %s WHERE id = %s",
                (operation_id, import_run_id),
            )
        return removal_id


def make_csv_reader(csv_text: str) -> csv.DictReader:
    if not csv_text.strip():
        return csv.DictReader(io.StringIO(""))
    try:
        dialect = csv.Sniffer().sniff(csv_text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return csv.DictReader(io.StringIO(csv_text), dialect=dialect)


def normalize_row(row: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in row.items():
        clean_key = (key or "").strip("\ufeff")
        normalized[clean_key] = clean_value(value) or ""
    return normalized


def upsert_asset(conn: psycopg.Connection[dict[str, Any]], row: dict[str, str]) -> int | None:
    ip_address = first_value(row, "Host.IpAddress", "IpAddress", "IP")
    fqdn = first_value(row, "Host.Fqdn", "Fqdn", "HostName", "Hostname")
    mp_asset_id = first_value(row, "AssetId", "Host.@Id", "@Host", "HostId", "Id")
    if not ip_address and not fqdn and not mp_asset_id:
        return None
    asset_key = mp_asset_id or f"{ip_address or ''}|{(fqdn or '').casefold()}"
    current = now_utc()
    row_result = conn.execute(
        """
        INSERT INTO assets (asset_key, mp_asset_id, ip_address, fqdn, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT(asset_key) DO UPDATE SET
            mp_asset_id = COALESCE(EXCLUDED.mp_asset_id, assets.mp_asset_id),
            ip_address = COALESCE(EXCLUDED.ip_address, assets.ip_address),
            fqdn = COALESCE(EXCLUDED.fqdn, assets.fqdn),
            last_seen = EXCLUDED.last_seen
        RETURNING id
        """,
        (asset_key, mp_asset_id, ip_address, fqdn, current, current),
    ).fetchone()
    return int(row_result["id"])


def upsert_software(conn: psycopg.Connection[dict[str, Any]], row: dict[str, str]) -> int | None:
    name = first_value(row, "SoftName", "Host.Softs.Name", "SoftwareName")
    version = first_value(row, "SoftVersion", "Host.Softs.Version", "SoftwareVersion") or ""
    if not name:
        return None
    row_result = conn.execute(
        """
        INSERT INTO software (name, version)
        VALUES (%s, %s)
        ON CONFLICT(name, version) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
        """,
        (name, version),
    ).fetchone()
    return int(row_result["id"])


def first_value(row: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = clean_value(row.get(key))
        if value:
            return value
    return None


def clean_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def decode_vulnerability_passport(row: dict[str, Any]) -> dict[str, Any]:
    cves = json_loads(row.get("cves_json"), [])
    metrics = json_loads(row.get("metrics_json"), {})
    raw_record = json_loads(row.get("raw_record_json"), {})
    raw_detail = json_loads(row.get("raw_detail_json"), None)
    return {
        "id": row.get("id"),
        "internal_id": row.get("internal_id"),
        "external_id": row.get("external_id"),
        "name": row.get("name"),
        "severity": row.get("severity"),
        "score": row.get("score"),
        "issue_time": row.get("issue_time"),
        "package_id": row.get("package_id"),
        "package_version": row.get("package_version"),
        "cves": cves if isinstance(cves, list) else [],
        "metrics": metrics if isinstance(metrics, dict) else {},
        "raw_record": raw_record if isinstance(raw_record, dict) else {},
        "raw_detail": raw_detail if isinstance(raw_detail, dict) else None,
        "source_pdql": row.get("source_pdql"),
        "pdql_token": row.get("pdql_token"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "detail_updated_at": row.get("detail_updated_at"),
    }


def json_loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _decode_scan_task(row: dict[str, Any]) -> dict[str, Any]:
    for key in (
        "agent_ids_json",
        "include_targets_json",
        "exclude_targets_json",
        "payload_json",
        "last_remote_response_json",
    ):
        decoded_key = key.replace("_json", "")
        try:
            row[decoded_key] = json.loads(row.get(key) or "{}")
        except json.JSONDecodeError:
            row[decoded_key] = None
    return row


def _credential_id_from_payload(payload: dict[str, Any]) -> str | None:
    try:
        return payload["overrides"]["transports"]["windows"]["wmi_and_rpc_and_re"]["connection"]["auth"]["ref_value"]
    except (KeyError, TypeError):
        return None
