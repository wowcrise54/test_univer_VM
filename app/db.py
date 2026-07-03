from __future__ import annotations

import csv
import io
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .diagnostics import (
    DiagnosticConnection,
    DiagnosticCursor,
    log_event,
    log_exception,
)


DATABASE_URL = (
    os.getenv("MPVM_DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or "postgresql://mpvm:mpvm@localhost:5432/mpvm"
)
_DB_INITIALIZED = False
_DB_INIT_LOCK = threading.Lock()


def database_label() -> str:
    if "@" not in DATABASE_URL:
        return DATABASE_URL
    scheme, rest = DATABASE_URL.split("://", 1)
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def lease_until_utc(seconds: int = 45) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def asset_card_parent_path(path: Any) -> str | None:
    value = clean_value(path)
    if not value or value == "asset":
        return None
    if value.endswith("]") and "[" in value:
        return value.rsplit("[", 1)[0]
    if "." in value:
        return value.rsplit(".", 1)[0]
    return "asset"


def asset_card_path_depth(path: Any) -> int:
    value = clean_value(path)
    if not value or value == "asset":
        return 0
    return value.count(".") + value.count("[") + (0 if value.startswith("asset") else 1)


def connect() -> psycopg.Connection[dict[str, Any]]:
    started = datetime.now(timezone.utc)
    try:
        connection = DiagnosticConnection.connect(
            DATABASE_URL,
            row_factory=dict_row,
            cursor_factory=DiagnosticCursor,
        )
    except Exception:
        log_exception("database", "db.connection.failed", database=database_label())
        raise
    elapsed_ms = (datetime.now(timezone.utc) - started).total_seconds() * 1000
    log_event(
        "database",
        "db.connection.opened",
        level=10,
        database=database_label(),
        duration_ms=round(elapsed_ms, 2),
    )
    return connection


def init_db() -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    with _DB_INIT_LOCK:
        if _DB_INITIALIZED:
            return
        _initialize_schema()
        _DB_INITIALIZED = True


def _initialize_schema() -> None:
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
        """
        CREATE TABLE IF NOT EXISTS vulnerability_passport_detail_jobs (
            job_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            requested_count INTEGER NOT NULL DEFAULT 0,
            eligible_count INTEGER NOT NULL DEFAULT 0,
            processed_count INTEGER NOT NULL DEFAULT 0,
            loaded_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            skipped_fresh_count INTEGER NOT NULL DEFAULT 0,
            cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
            errors_json TEXT NOT NULL DEFAULT '[]',
            message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_build_jobs (
            job_id TEXT PRIMARY KEY,
            trace_id TEXT,
            asset_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            status TEXT NOT NULL,
            stage TEXT NOT NULL DEFAULT 'queued',
            progress_percent INTEGER NOT NULL DEFAULT 0,
            request_json TEXT NOT NULL DEFAULT '{}',
            stats_json TEXT NOT NULL DEFAULT '{}',
            discovered_requests INTEGER NOT NULL DEFAULT 0,
            completed_requests INTEGER NOT NULL DEFAULT 0,
            node_count INTEGER NOT NULL DEFAULT 0,
            collection_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            warning_count INTEGER NOT NULL DEFAULT 0,
            cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
            message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_postprocess_runs (
            run_id TEXT PRIMARY KEY,
            mp_task_id TEXT NOT NULL,
            mp_run_id TEXT,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            options_json TEXT NOT NULL DEFAULT '{}',
            started_from TEXT NOT NULL,
            run_started_at TEXT,
            total_job_count INTEGER NOT NULL DEFAULT 0,
            successful_job_count INTEGER NOT NULL DEFAULT 0,
            target_count INTEGER NOT NULL DEFAULT 0,
            asset_count INTEGER NOT NULL DEFAULT 0,
            completed_count INTEGER NOT NULL DEFAULT 0,
            failed_count INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            error TEXT,
            worker_id TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_postprocess_items (
            id BIGSERIAL PRIMARY KEY,
            postprocess_run_id TEXT NOT NULL REFERENCES scan_postprocess_runs(run_id) ON DELETE CASCADE,
            item_key TEXT NOT NULL,
            mp_job_id TEXT,
            target TEXT,
            asset_id TEXT,
            display_name TEXT,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            build_job_id TEXT,
            removal_operation_id TEXT,
            message TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(postprocess_run_id, item_key)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_cards (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT UNIQUE NOT NULL,
            display_name TEXT,
            asset_type TEXT,
            fqdn TEXT,
            hostname TEXT,
            ip_address TEXT,
            os_name TEXT,
            os_version TEXT,
            vulnerability_level TEXT,
            token_timestamp BIGINT,
            asset_token TEXT,
            root_json TEXT NOT NULL DEFAULT '{}',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            nodes_json TEXT NOT NULL DEFAULT '[]',
            collections_json TEXT NOT NULL DEFAULT '[]',
            table_rows_json TEXT NOT NULL DEFAULT '[]',
            vulnerabilities_json TEXT NOT NULL DEFAULT '{}',
            stats_json TEXT NOT NULL DEFAULT '{}',
            raw_card_json TEXT NOT NULL DEFAULT '{}',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_nodes (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            parent_path TEXT,
            depth INTEGER NOT NULL DEFAULT 0,
            title TEXT,
            display_name TEXT,
            object_id TEXT,
            object_type TEXT,
            vulnerability_level TEXT,
            data_json TEXT NOT NULL DEFAULT '{}',
            node_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_collections (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            parent_path TEXT,
            depth INTEGER NOT NULL DEFAULT 0,
            name TEXT,
            title TEXT,
            value_type TEXT,
            kind TEXT,
            parent_type TEXT,
            parent_object_id TEXT,
            reported_count INTEGER,
            fetched_count INTEGER,
            truncated BOOLEAN NOT NULL DEFAULT FALSE,
            collection_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_collection_items (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            collection_path TEXT NOT NULL,
            item_index INTEGER NOT NULL,
            item_path TEXT NOT NULL,
            display_name TEXT,
            object_id TEXT,
            object_type TEXT,
            vulnerability_level TEXT,
            data_json TEXT NOT NULL DEFAULT '{}',
            item_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, item_path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_table_rows (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            row_order INTEGER NOT NULL,
            path TEXT NOT NULL,
            name TEXT,
            title TEXT,
            value_text TEXT,
            value_type TEXT,
            kind TEXT,
            parent_type TEXT,
            parent_object_id TEXT,
            row_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        )
        """,
        "ALTER TABLE asset_cards ADD COLUMN IF NOT EXISTS vulnerabilities_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS trace_id TEXT",
        "ALTER TABLE vulnerability_passport_detail_jobs ADD COLUMN IF NOT EXISTS request_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE vulnerability_passport_detail_jobs ADD COLUMN IF NOT EXISTS worker_id TEXT",
        "ALTER TABLE vulnerability_passport_detail_jobs ADD COLUMN IF NOT EXISTS lease_until TEXT",
        "ALTER TABLE vulnerability_passport_detail_jobs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS worker_id TEXT",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS lease_until TEXT",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scan_postprocess_runs ADD COLUMN IF NOT EXISTS lease_until TEXT",
        "ALTER TABLE scan_postprocess_runs ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_card_nodes ADD COLUMN IF NOT EXISTS parent_path TEXT",
        "ALTER TABLE asset_card_nodes ADD COLUMN IF NOT EXISTS depth INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_card_collections ADD COLUMN IF NOT EXISTS parent_path TEXT",
        "ALTER TABLE asset_card_collections ADD COLUMN IF NOT EXISTS depth INTEGER NOT NULL DEFAULT 0",
        """
        UPDATE asset_card_nodes
        SET parent_path = CASE
            WHEN path = 'asset' THEN NULL
            WHEN path ~ '\\[[0-9]+\\]$' THEN regexp_replace(path, '\\[[0-9]+\\]$', '')
            WHEN strpos(path, '.') > 0 THEN regexp_replace(path, '\\.[^.]+$', '')
            ELSE 'asset'
        END,
            depth = (length(path) - length(replace(path, '.', ''))) +
                    (length(path) - length(replace(path, '[', '')))
        WHERE (parent_path IS NULL OR depth = 0) AND path <> 'asset'
        """,
        """
        UPDATE asset_card_collections
        SET parent_path = CASE
            WHEN path = 'asset' THEN NULL
            WHEN path ~ '\\[[0-9]+\\]$' THEN regexp_replace(path, '\\[[0-9]+\\]$', '')
            WHEN strpos(path, '.') > 0 THEN regexp_replace(path, '\\.[^.]+$', '')
            ELSE 'asset'
        END,
            depth = (length(path) - length(replace(path, '.', ''))) +
                    (length(path) - length(replace(path, '[', '')))
        WHERE (parent_path IS NULL OR depth = 0) AND path <> 'asset'
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_vulnerability_groups (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            source_type TEXT NOT NULL,
            collection_type TEXT NOT NULL,
            collection_id TEXT NOT NULL,
            name TEXT,
            severity TEXT,
            vulnerability_count INTEGER NOT NULL DEFAULT 0,
            cvss_score NUMERIC,
            group_order INTEGER NOT NULL,
            truncated BOOLEAN NOT NULL DEFAULT FALSE,
            group_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, source_type, collection_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_vulnerabilities (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            group_id BIGINT NOT NULL REFERENCES asset_card_vulnerability_groups(id) ON DELETE CASCADE,
            vulnerability_instance_id TEXT,
            vulnerability_id TEXT,
            object_id TEXT,
            cve_name TEXT,
            name TEXT,
            severity TEXT,
            cvss_score NUMERIC,
            description_key TEXT,
            vulnerability_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, vulnerability_instance_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_vulnerability_passports (
            asset_vulnerability_id BIGINT NOT NULL REFERENCES asset_card_vulnerabilities(id) ON DELETE CASCADE,
            passport_internal_id TEXT NOT NULL REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
            match_method TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY(asset_vulnerability_id, passport_internal_id)
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
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passports_pdql_token ON vulnerability_passports(pdql_token)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passport_detail_jobs_created ON vulnerability_passport_detail_jobs(created_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerability_passport_detail_jobs_single_active ON vulnerability_passport_detail_jobs ((1)) WHERE status IN ('queued', 'running', 'cancelling')",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_build_jobs_created ON asset_card_build_jobs(created_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_card_build_jobs_single_active ON asset_card_build_jobs ((1)) WHERE status IN ('queued', 'running', 'cancelling')",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_runs_task_created ON scan_postprocess_runs(mp_task_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_runs_status ON scan_postprocess_runs(status, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_items_run_status ON scan_postprocess_items(postprocess_run_id, status, id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_items_asset ON scan_postprocess_items(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_display_name_lower ON asset_cards((LOWER(display_name)))",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_fqdn_lower ON asset_cards((LOWER(fqdn)))",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_ip ON asset_cards(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_type ON asset_cards(asset_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_nodes_asset_path ON asset_card_nodes(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_nodes_parent ON asset_card_nodes(asset_id, parent_path, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_nodes_type ON asset_card_nodes(object_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collections_asset_path ON asset_card_collections(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collections_parent ON asset_card_collections(asset_id, parent_path, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collections_name ON asset_card_collections(name)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collection_items_asset_collection ON asset_card_collection_items(asset_id, collection_path, item_index)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collection_items_asset_path ON asset_card_collection_items(asset_id, item_path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collection_items_type ON asset_card_collection_items(object_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_table_rows_asset_path ON asset_card_table_rows(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_table_rows_kind ON asset_card_table_rows(kind)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_groups_asset_source ON asset_card_vulnerability_groups(asset_id, source_type, group_order)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_asset_cve ON asset_card_vulnerabilities(asset_id, cve_name)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_vulnerability_id ON asset_card_vulnerabilities(vulnerability_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_asset_vulnerability_id ON asset_card_vulnerabilities(asset_id, vulnerability_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_passports_passport ON asset_card_vulnerability_passports(passport_internal_id)",
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
        postprocess_rows = conn.execute(
            """
            SELECT DISTINCT ON (mp_task_id) *
            FROM scan_postprocess_runs
            ORDER BY mp_task_id, created_at DESC
            """
        ).fetchall()
    latest = {str(row["mp_task_id"]): decode_scan_postprocess_run(dict(row)) for row in postprocess_rows}
    result = [_decode_scan_task(dict(row)) for row in rows]
    for task in result:
        task["postprocess"] = latest.get(str(task.get("mp_task_id")))
    return result


def get_scan_task(mp_task_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan_tasks WHERE mp_task_id = %s", (mp_task_id,)).fetchone()
    return _decode_scan_task(dict(row)) if row else None


SCAN_POSTPROCESS_ACTIVE_STATUSES = {"monitoring", "resolving", "processing", "waiting"}
SCAN_POSTPROCESS_FAILED_ITEM_STATUSES = {"resolution_failed", "build_failed", "removal_failed"}


def create_scan_postprocess_run(
    run_id: str,
    *,
    mp_task_id: str,
    started_from: str,
    options: dict[str, Any],
) -> dict[str, Any]:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO scan_postprocess_runs (
                run_id, mp_task_id, status, stage, options_json, started_from,
                created_at, updated_at
            )
            VALUES (%s, %s, 'monitoring', 'waiting_for_run', %s, %s, %s, %s)
            RETURNING *
            """,
            (run_id, mp_task_id, json.dumps(options, ensure_ascii=False), started_from, current, current),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row))


def get_scan_postprocess_run(run_id: str, *, include_items: bool = False) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan_postprocess_runs WHERE run_id = %s", (run_id,)).fetchone()
        items = (
            conn.execute(
                "SELECT * FROM scan_postprocess_items WHERE postprocess_run_id = %s ORDER BY id",
                (run_id,),
            ).fetchall()
            if row and include_items
            else []
        )
    if not row:
        return None
    result = decode_scan_postprocess_run(dict(row))
    if include_items:
        result["items"] = [decode_scan_postprocess_item(dict(item)) for item in items]
    return result


def get_latest_scan_postprocess_run(mp_task_id: str, *, include_items: bool = False) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE mp_task_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (mp_task_id,),
        ).fetchone()
    if not row:
        return None
    return get_scan_postprocess_run(str(row["run_id"]), include_items=include_items)


def list_resumable_scan_postprocess_runs() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting')
              AND worker_id IS NULL
            ORDER BY created_at
            """
        ).fetchall()
    return [decode_scan_postprocess_run(dict(row)) for row in rows]


def claim_scan_postprocess_run(run_id: str, worker_id: str) -> dict[str, Any] | None:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = %s, lease_until = %s,
                attempt_count = attempt_count + 1,
                started_at = COALESCE(started_at, %s), updated_at = %s
            WHERE run_id = %s
              AND worker_id IS NULL
              AND status IN ('monitoring', 'resolving', 'processing', 'waiting')
            RETURNING *
            """,
            (worker_id, lease_until_utc(), current, current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def release_scan_postprocess_leases() -> None:
    current = now_utc()
    with connect() as conn:
        conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = NULL, lease_until = NULL, updated_at = %s
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting')
            """,
            (current,),
        )
        conn.execute(
            """
            UPDATE scan_postprocess_items
            SET status = 'queued', stage = 'queued', updated_at = %s
            WHERE status IN ('building', 'card_saved')
            """,
            (current,),
        )


def heartbeat_background_job(kind: str, job_id: str) -> None:
    tables = {
        "asset-card": ("asset_card_build_jobs", "job_id"),
        "passport-details": ("vulnerability_passport_detail_jobs", "job_id"),
        "scan-postprocess": ("scan_postprocess_runs", "run_id"),
    }
    table = tables.get(kind)
    if table is None:
        raise ValueError(f"Unknown background job kind: {kind}")
    table_name, id_column = table
    with connect() as conn:
        conn.execute(
            f"UPDATE {table_name} SET lease_until = %s, updated_at = %s WHERE {id_column} = %s",
            (lease_until_utc(), now_utc(), job_id),
        )


def update_scan_postprocess_run(run_id: str, **values: Any) -> dict[str, Any] | None:
    allowed = {
        "mp_run_id",
        "status",
        "stage",
        "run_started_at",
        "total_job_count",
        "successful_job_count",
        "target_count",
        "asset_count",
        "completed_count",
        "failed_count",
        "message",
        "error",
        "worker_id",
    }
    updates = [(key, value) for key, value in values.items() if key in allowed]
    if not updates:
        return get_scan_postprocess_run(run_id)
    current = now_utc()
    assignments = ", ".join(f"{key} = %s" for key, _ in updates)
    params = [value for _, value in updates]
    params.extend([current, run_id])
    with connect() as conn:
        row = conn.execute(
            f"UPDATE scan_postprocess_runs SET {assignments}, updated_at = %s WHERE run_id = %s RETURNING *",
            params,
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def finish_scan_postprocess_run(
    run_id: str,
    *,
    status: str,
    stage: str,
    message: str | None = None,
    error: str | None = None,
) -> dict[str, Any] | None:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET status = %s, stage = %s, message = %s, error = %s,
                worker_id = NULL, lease_until = NULL, finished_at = %s, updated_at = %s
            WHERE run_id = %s
            RETURNING *
            """,
            (status, stage, message, error, current, current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def upsert_scan_postprocess_item(
    postprocess_run_id: str,
    *,
    item_key: str,
    mp_job_id: str | None,
    target: str | None,
    asset_id: str | None,
    display_name: str | None,
    status: str,
    stage: str,
) -> dict[str, Any]:
    current = now_utc()
    # PDQL fields are not guaranteed to be scalars (for example HostName may
    # be an object with displayName/objectId).  Keep the persistence boundary
    # defensive so one unexpected response shape cannot stall the whole scan
    # post-processing queue with psycopg's "cannot adapt type 'dict'" error.
    mp_job_id = text_parameter(mp_job_id)
    target = text_parameter(target)
    asset_id = text_parameter(asset_id)
    display_name = text_parameter(display_name)
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO scan_postprocess_items (
                postprocess_run_id, item_key, mp_job_id, target, asset_id,
                display_name, status, stage, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(postprocess_run_id, item_key) DO UPDATE SET
                mp_job_id = COALESCE(EXCLUDED.mp_job_id, scan_postprocess_items.mp_job_id),
                target = COALESCE(EXCLUDED.target, scan_postprocess_items.target),
                asset_id = COALESCE(EXCLUDED.asset_id, scan_postprocess_items.asset_id),
                display_name = COALESCE(EXCLUDED.display_name, scan_postprocess_items.display_name),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (
                postprocess_run_id,
                item_key,
                mp_job_id,
                target,
                asset_id,
                display_name,
                status,
                stage,
                current,
                current,
            ),
        ).fetchone()
    return decode_scan_postprocess_item(dict(row))


def update_scan_postprocess_item(item_id: int, **values: Any) -> dict[str, Any] | None:
    allowed = {
        "status",
        "stage",
        "build_job_id",
        "removal_operation_id",
        "message",
        "error",
        "started_at",
        "finished_at",
    }
    updates = [(key, value) for key, value in values.items() if key in allowed]
    if not updates:
        return None
    current = now_utc()
    assignments = ", ".join(f"{key} = %s" for key, _ in updates)
    params = [value for _, value in updates]
    params.extend([current, item_id])
    with connect() as conn:
        row = conn.execute(
            f"UPDATE scan_postprocess_items SET {assignments}, updated_at = %s WHERE id = %s RETURNING *",
            params,
        ).fetchone()
    return decode_scan_postprocess_item(dict(row)) if row else None


def list_scan_postprocess_items(run_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_postprocess_items WHERE postprocess_run_id = %s ORDER BY id",
            (run_id,),
        ).fetchall()
    return [decode_scan_postprocess_item(dict(row)) for row in rows]


def refresh_scan_postprocess_counts(run_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE asset_id IS NOT NULL) AS asset_count,
                COUNT(*) FILTER (WHERE status = 'completed') AS completed_count,
                COUNT(*) FILTER (WHERE status IN ('resolution_failed', 'build_failed', 'removal_failed')) AS failed_count
            FROM scan_postprocess_items
            WHERE postprocess_run_id = %s
            """,
            (run_id,),
        ).fetchone()
    return update_scan_postprocess_run(
        run_id,
        asset_count=int(row["asset_count"] or 0),
        completed_count=int(row["completed_count"] or 0),
        failed_count=int(row["failed_count"] or 0),
    )


def decode_scan_postprocess_run(row: dict[str, Any]) -> dict[str, Any]:
    options = json_loads(row.get("options_json"), {})
    return {
        "run_id": row.get("run_id"),
        "mp_task_id": row.get("mp_task_id"),
        "mp_run_id": row.get("mp_run_id"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "options": options if isinstance(options, dict) else {},
        "started_from": row.get("started_from"),
        "run_started_at": row.get("run_started_at"),
        "total_job_count": int(row.get("total_job_count") or 0),
        "successful_job_count": int(row.get("successful_job_count") or 0),
        "target_count": int(row.get("target_count") or 0),
        "asset_count": int(row.get("asset_count") or 0),
        "completed_count": int(row.get("completed_count") or 0),
        "failed_count": int(row.get("failed_count") or 0),
        "message": row.get("message"),
        "error": row.get("error"),
        "worker_id": row.get("worker_id"),
        "lease_until": row.get("lease_until"),
        "attempt_count": int(row.get("attempt_count") or 0),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


def decode_scan_postprocess_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row.get("id") or 0),
        "postprocess_run_id": row.get("postprocess_run_id"),
        "item_key": row.get("item_key"),
        "mp_job_id": row.get("mp_job_id"),
        "target": row.get("target"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "build_job_id": row.get("build_job_id"),
        "removal_operation_id": row.get("removal_operation_id"),
        "message": row.get("message"),
        "error": row.get("error"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


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


def copy_rows(
    cursor: psycopg.Cursor[Any],
    table: str,
    columns: tuple[str, ...],
    rows: list[tuple[Any, ...]],
) -> None:
    if not rows:
        return
    column_sql = ", ".join(columns)
    started = datetime.now(timezone.utc)
    with cursor.copy(f"COPY {table} ({column_sql}) FROM STDIN") as copy:
        for row in rows:
            copy.write_row(row)
    log_event(
        "database",
        "db.copy.completed",
        level=10,
        table=table,
        row_count=len(rows),
        duration_ms=round((datetime.now(timezone.utc) - started).total_seconds() * 1000, 2),
    )


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
    skipped = 0
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
    with connect() as conn:
        if values:
            with conn.cursor() as cursor:
                cursor.executemany(
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
                    values,
                )
        links_created = reconcile_asset_card_vulnerability_passport_links(conn, saved_ids, current)
    return {"saved": len(values), "skipped": skipped, "passport_links": links_created}


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
    vulnerability = raw_detail.get("vulnerability") if isinstance(raw_detail.get("vulnerability"), dict) else {}
    cvss = raw_detail.get("cvss") if isinstance(raw_detail.get("cvss"), dict) else {}
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
) -> int:
    values = [vulnerability_passport_detail_values(internal_id, raw_detail, current) for internal_id, raw_detail in details]
    if not values:
        return 0
    with conn.cursor() as cursor:
        cursor.executemany(VULNERABILITY_PASSPORT_DETAIL_UPSERT_SQL, values)
    reconcile_asset_card_vulnerability_passport_links(conn, [value[0] for value in values], current)
    return len(values)


def upsert_vulnerability_passport_detail(internal_id: str, raw_detail: dict[str, Any]) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            VULNERABILITY_PASSPORT_DETAIL_UPSERT_SQL + " RETURNING *",
            vulnerability_passport_detail_values(internal_id, raw_detail, current),
        ).fetchone()
        reconcile_asset_card_vulnerability_passport_links(conn, [internal_id], current)
    return decode_vulnerability_passport(dict(row)) if row else None


def upsert_vulnerability_passport_details(details: list[tuple[str, dict[str, Any]]]) -> int:
    init_db()
    current = now_utc()
    with connect() as conn:
        return _upsert_vulnerability_passport_details(conn, details, current)


def get_vulnerability_passport(internal_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerability_passports WHERE internal_id = %s",
            (internal_id,),
        ).fetchone()
    return decode_vulnerability_passport(dict(row)) if row else None


def delete_vulnerability_passport(internal_id: str) -> bool:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "DELETE FROM vulnerability_passports WHERE internal_id = %s RETURNING internal_id",
            (internal_id,),
        ).fetchone()
    return row is not None


def list_vulnerability_passports(
    *,
    q: str | None = None,
    severity: str | None = None,
    pdql_token: str | None = None,
    limit: int = 50,
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
                package_id ILIKE %s OR package_version ILIKE %s OR cves_json ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like, like])
    if severity:
        filters.append("LOWER(COALESCE(severity, '')) = LOWER(%s)")
        params.append(severity)
    if pdql_token:
        filters.append("pdql_token = %s")
        params.append(pdql_token)
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = min(200, max(1, limit))
    offset = max(0, offset)

    with connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM vulnerability_passports {where}", params).fetchone()
        rows = conn.execute(
            f"""
            SELECT
                id, internal_id, external_id, name, severity, score, issue_time,
                package_id, package_version, cves_json, metrics_json,
                first_seen, last_seen, detail_updated_at,
                (raw_detail_json IS NOT NULL) AS has_detail
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
        "rows": [decode_vulnerability_passport_summary(dict(row)) for row in rows],
        "limit": limit,
        "offset": offset,
    }


def vulnerability_passport_detail_refresh_candidates(
    internal_ids: list[Any],
    *,
    ttl_hours: int,
) -> dict[str, Any]:
    init_db()
    ordered_ids = list(dict.fromkeys(clean_value(value) for value in internal_ids if clean_value(value)))
    if not ordered_ids:
        return {"requested": [], "eligible": [], "skipped_fresh": []}
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT internal_id, detail_updated_at, (raw_detail_json IS NOT NULL) AS has_detail
            FROM vulnerability_passports
            WHERE internal_id = ANY(%s)
            """,
            (ordered_ids,),
        ).fetchall()
    by_id = {clean_value(row.get("internal_id")): dict(row) for row in rows}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max(0, ttl_hours))
    eligible: list[str] = []
    skipped_fresh: list[str] = []
    for internal_id in ordered_ids:
        row = by_id.get(internal_id)
        updated_at = _parse_timestamp(row.get("detail_updated_at")) if row else None
        if row and row.get("has_detail") and updated_at is not None and updated_at >= cutoff:
            skipped_fresh.append(internal_id)
        else:
            eligible.append(internal_id)
    return {"requested": ordered_ids, "eligible": eligible, "skipped_fresh": skipped_fresh}


def list_vulnerability_passport_internal_ids(limit: int = 50000) -> list[str]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT internal_id FROM vulnerability_passports ORDER BY internal_id LIMIT %s",
            (max(1, min(int(limit), 50000)),),
        ).fetchall()
    return [str(row["internal_id"]) for row in rows if row.get("internal_id")]


def create_vulnerability_passport_detail_job(
    job_id: str,
    *,
    requested_count: int,
    eligible_count: int,
    skipped_fresh_count: int,
    internal_ids: list[str] | None = None,
) -> dict[str, Any]:
    init_db()
    current = now_utc()
    status = "queued" if eligible_count else "completed"
    finished_at = None if eligible_count else current
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO vulnerability_passport_detail_jobs (
                job_id, status, requested_count, eligible_count, skipped_fresh_count,
                request_json, created_at, finished_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                job_id,
                status,
                requested_count,
                eligible_count,
                skipped_fresh_count,
                json.dumps({"internal_ids": internal_ids or []}, ensure_ascii=False),
                current,
                finished_at,
                current,
            ),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row))


def get_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM vulnerability_passport_detail_jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def get_active_vulnerability_passport_detail_job() -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM vulnerability_passport_detail_jobs
            WHERE status IN ('queued', 'running', 'cancelling')
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def interrupt_active_vulnerability_passport_detail_jobs() -> int:
    init_db()
    current = now_utc()
    with connect() as conn:
        result = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = 'interrupted',
                message = 'Application restarted before the detail sync finished.',
                finished_at = %s,
                updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current, current),
        )
    return int(result.rowcount or 0)


def requeue_active_vulnerability_passport_detail_jobs() -> int:
    init_db()
    current = now_utc()
    with connect() as conn:
        result = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = 'queued',
                message = 'Waiting for MP VM connection after application restart.',
                worker_id = NULL, lease_until = NULL,
                started_at = NULL, finished_at = NULL, updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current,),
        )
    return int(result.rowcount or 0)


def start_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'running' END,
                started_at = COALESCE(started_at, %s),
                worker_id = %s, lease_until = %s,
                attempt_count = attempt_count + 1, updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, job_id, lease_until_utc(), current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def request_vulnerability_passport_detail_job_cancel(job_id: str) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET cancel_requested = TRUE,
                status = 'cancelling',
                updated_at = %s
            WHERE job_id = %s AND status IN ('queued', 'running', 'cancelling')
            RETURNING *
            """,
            (current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def save_vulnerability_passport_detail_job_batch(
    job_id: str,
    *,
    details: list[tuple[str, dict[str, Any]]],
    errors: list[dict[str, str]],
) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            "SELECT errors_json FROM vulnerability_passport_detail_jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if not row:
            return None
        loaded_count = _upsert_vulnerability_passport_details(conn, details, current)
        saved_errors = json_loads(row.get("errors_json"), [])
        if not isinstance(saved_errors, list):
            saved_errors = []
        saved_errors = [*saved_errors, *errors][:100]
        updated = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET processed_count = processed_count + %s,
                loaded_count = loaded_count + %s,
                failed_count = failed_count + %s,
                errors_json = %s,
                updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                loaded_count + len(errors),
                loaded_count,
                len(errors),
                json.dumps(saved_errors, ensure_ascii=False),
                current,
                job_id,
            ),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(updated)) if updated else None


def finish_vulnerability_passport_detail_job(
    job_id: str,
    *,
    status: str,
    message: str | None = None,
) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = %s,
                message = %s,
                worker_id = NULL,
                lease_until = NULL,
                finished_at = %s,
                updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (status, message, current, current, job_id),
        ).fetchone()
    return decode_vulnerability_passport_detail_job(dict(row)) if row else None


def list_asset_card_links_for_vulnerability_passport(passport_id: str) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
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


def asset_card_exists(asset_id: str) -> bool:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT 1 FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
    return row is not None


def create_asset_card_build_job(
    job_id: str,
    *,
    trace_id: str | None,
    asset_id: str,
    operation: str,
    request: dict[str, Any],
) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO asset_card_build_jobs (
                job_id, trace_id, asset_id, operation, status, stage, request_json, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, 'queued', 'queued', %s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING *
            """,
            (job_id, trace_id, asset_id, operation, json.dumps(request, ensure_ascii=False), current, current),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def get_asset_card_build_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM asset_card_build_jobs WHERE job_id = %s", (job_id,)).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def get_active_asset_card_build_job() -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM asset_card_build_jobs
            WHERE status IN ('queued', 'running', 'cancelling')
            ORDER BY created_at DESC
            LIMIT 1
            """
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def interrupt_active_asset_card_build_jobs() -> int:
    init_db()
    current = now_utc()
    with connect() as conn:
        result = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = 'interrupted', stage = 'interrupted',
                message = 'Application restarted before the asset card build finished.',
                finished_at = %s, updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current, current),
        )
    return int(result.rowcount or 0)


def requeue_active_asset_card_build_jobs() -> int:
    init_db()
    current = now_utc()
    with connect() as conn:
        result = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = 'queued', stage = 'queued',
                message = 'Waiting for MP VM connection after application restart.',
                worker_id = NULL, lease_until = NULL,
                started_at = NULL, finished_at = NULL, updated_at = %s
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (current,),
        )
    return int(result.rowcount or 0)


def start_asset_card_build_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'running' END,
                stage = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'starting' END,
                progress_percent = GREATEST(progress_percent, 5),
                started_at = COALESCE(started_at, %s), worker_id = %s,
                lease_until = %s, attempt_count = attempt_count + 1, updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, job_id, lease_until_utc(), current, job_id),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def update_asset_card_build_job(
    job_id: str,
    *,
    stage: str,
    progress_percent: int,
    discovered_requests: int,
    completed_requests: int,
    node_count: int = 0,
    collection_count: int = 0,
    finding_count: int = 0,
    warning_count: int = 0,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET stage = %s,
                progress_percent = GREATEST(progress_percent, LEAST(100, GREATEST(0, %s))),
                discovered_requests = %s, completed_requests = %s,
                node_count = %s, collection_count = %s, finding_count = %s,
                warning_count = %s, stats_json = %s, updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                stage,
                progress_percent,
                discovered_requests,
                completed_requests,
                node_count,
                collection_count,
                finding_count,
                warning_count,
                json.dumps(stats or {}, ensure_ascii=False),
                current,
                job_id,
            ),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def request_asset_card_build_job_cancel(job_id: str) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET cancel_requested = TRUE, status = 'cancelling', stage = 'cancelling', updated_at = %s
            WHERE job_id = %s AND status IN ('queued', 'running', 'cancelling')
            RETURNING *
            """,
            (current, job_id),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def finish_asset_card_build_job(
    job_id: str,
    *,
    status: str,
    stage: str,
    message: str | None,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE asset_card_build_jobs
            SET status = %s, stage = %s, message = %s,
                progress_percent = CASE WHEN %s = 'completed' THEN 100 ELSE progress_percent END,
                stats_json = CASE WHEN %s::text IS NULL THEN stats_json ELSE %s END,
                worker_id = NULL, lease_until = NULL,
                finished_at = %s, updated_at = %s
            WHERE job_id = %s
            RETURNING *
            """,
            (
                status,
                stage,
                message,
                status,
                None if stats is None else "present",
                json.dumps(stats or {}, ensure_ascii=False),
                current,
                current,
                job_id,
            ),
        ).fetchone()
    return decode_asset_card_build_job(dict(row)) if row else None


def upsert_asset_card(card: dict[str, Any]) -> dict[str, Any] | None:
    init_db()
    write_started = datetime.now(timezone.utc)
    root = card.get("root") if isinstance(card.get("root"), dict) else {}
    data = root.get("data") if isinstance(root.get("data"), dict) else {}
    asset_id = clean_value(first_non_empty(card.get("asset_id"), root.get("objectId")))
    if not asset_id:
        return None

    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO asset_cards (
                asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp, asset_token,
                root_json, metadata_json, nodes_json, collections_json, table_rows_json,
                vulnerabilities_json, stats_json, raw_card_json, first_seen, last_seen
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(asset_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                asset_type = EXCLUDED.asset_type,
                fqdn = EXCLUDED.fqdn,
                hostname = EXCLUDED.hostname,
                ip_address = EXCLUDED.ip_address,
                os_name = EXCLUDED.os_name,
                os_version = EXCLUDED.os_version,
                vulnerability_level = EXCLUDED.vulnerability_level,
                token_timestamp = EXCLUDED.token_timestamp,
                asset_token = EXCLUDED.asset_token,
                root_json = EXCLUDED.root_json,
                metadata_json = EXCLUDED.metadata_json,
                nodes_json = EXCLUDED.nodes_json,
                collections_json = EXCLUDED.collections_json,
                table_rows_json = EXCLUDED.table_rows_json,
                vulnerabilities_json = EXCLUDED.vulnerabilities_json,
                stats_json = EXCLUDED.stats_json,
                raw_card_json = EXCLUDED.raw_card_json,
                last_seen = EXCLUDED.last_seen
            RETURNING
                id, asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp,
                stats_json, first_seen, last_seen
            """,
            (
                asset_id,
                clean_value(first_non_empty(card.get("display_name"), root.get("displayName"))),
                clean_value(first_non_empty(card.get("asset_type"), root.get("type"))),
                clean_value(data.get("fqdn")),
                clean_value(data.get("hostname")),
                clean_value(data.get("ipAddress")),
                clean_value(data.get("osName")),
                clean_value(data.get("osVersion")),
                clean_value(first_non_empty(card.get("vulnerability_level"), root.get("vulnerabilityLevel"))),
                card.get("timeline_timestamp"),
                clean_value(card.get("timeline_token")),
                json.dumps(root, ensure_ascii=False),
                json.dumps(card.get("metadata") or {}, ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("nodes") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("collections") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("table_rows") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("vulnerabilities") or {}), ensure_ascii=False),
                json.dumps(card.get("stats") or {}, ensure_ascii=False),
                "{}",
                current,
                current,
            ),
        ).fetchone()
        replace_asset_card_cache(conn, asset_id, card, current)
        save_duration_ms = round((datetime.now(timezone.utc) - write_started).total_seconds() * 1000, 2)
        stats = card.setdefault("stats", {})
        if isinstance(stats, dict):
            stats["save_duration_ms"] = save_duration_ms
            conn.execute(
                "UPDATE asset_cards SET stats_json = %s WHERE asset_id = %s",
                (json.dumps(stats, ensure_ascii=False), asset_id),
            )
    result = decode_asset_card_summary(dict(row)) if row else None
    log_event(
        "database",
        "db.write.completed",
        asset_id=asset_id,
        operation="upsert_asset_card",
        duration_ms=save_duration_ms,
        node_count=len(card.get("nodes") or []),
        collection_count=len(card.get("collections") or []),
        table_row_count=len(card.get("table_rows") or []),
    )
    return result


def replace_asset_card_cache(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    card: dict[str, Any],
    updated_at: str,
) -> None:
    conn.execute("DELETE FROM asset_card_table_rows WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_collection_items WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_collections WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_nodes WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_vulnerability_groups WHERE asset_id = %s", (asset_id,))

    nodes = [item for item in card.get("nodes") or [] if isinstance(item, dict)]
    collections = [item for item in card.get("collections") or [] if isinstance(item, dict)]
    table_rows = [item for item in card.get("table_rows") or [] if isinstance(item, dict)]

    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_nodes",
            (
                "asset_id", "path", "parent_path", "depth", "title", "display_name", "object_id", "object_type",
                "vulnerability_level", "data_json", "node_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(node.get("path")) or "",
                    asset_card_parent_path(node.get("path")),
                    asset_card_path_depth(node.get("path")),
                    clean_value(node.get("title")),
                    clean_value(node.get("display_name")),
                    clean_value(node.get("object_id")),
                    clean_value(node.get("type")),
                    clean_value(node.get("vulnerability_level")),
                    json.dumps(strip_asset_card_raw(node.get("data") or {}), ensure_ascii=False),
                    json.dumps(strip_asset_card_raw(node), ensure_ascii=False),
                    updated_at,
                )
                for node in nodes
                if clean_value(node.get("path"))
            ],
        )

        copy_rows(
            cur,
            "asset_card_collections",
            (
                "asset_id", "path", "parent_path", "depth", "name", "title", "value_type", "kind", "parent_type",
                "parent_object_id", "reported_count", "fetched_count", "truncated",
                "collection_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(collection.get("path")) or "",
                    asset_card_parent_path(collection.get("path")),
                    asset_card_path_depth(collection.get("path")),
                    clean_value(collection.get("name")),
                    clean_value(collection.get("title")),
                    clean_value(collection.get("type")),
                    clean_value(collection.get("kind")),
                    clean_value(collection.get("parent_type")),
                    clean_value(collection.get("parent_object_id")),
                    safe_int(collection.get("count")),
                    safe_int(collection.get("fetched_count")),
                    bool(collection.get("truncated")),
                    json.dumps(strip_asset_card_raw({k: v for k, v in collection.items() if k != "items"}), ensure_ascii=False),
                    updated_at,
                )
                for collection in collections
                if clean_value(collection.get("path"))
            ],
        )

        item_rows: list[tuple[Any, ...]] = []
        for collection in collections:
            collection_path = clean_value(collection.get("path"))
            if not collection_path:
                continue
            items = collection.get("items") if isinstance(collection.get("items"), list) else []
            for index, item in enumerate(items):
                item_doc = item if isinstance(item, dict) else {"path": f"{collection_path}[{index}]", "value": item}
                data = item_doc.get("data") if isinstance(item_doc.get("data"), dict) else {}
                item_rows.append(
                    (
                        asset_id,
                        collection_path,
                        index,
                        clean_value(item_doc.get("path")) or f"{collection_path}[{index}]",
                        clean_value(item_doc.get("display_name")),
                        clean_value(item_doc.get("object_id")),
                        clean_value(item_doc.get("type")),
                        clean_value(item_doc.get("vulnerability_level")),
                        json.dumps(strip_asset_card_raw(data), ensure_ascii=False),
                        json.dumps(strip_asset_card_raw(item_doc), ensure_ascii=False),
                        updated_at,
                    )
                )
        copy_rows(
            cur,
            "asset_card_collection_items",
            (
                "asset_id", "collection_path", "item_index", "item_path", "display_name",
                "object_id", "object_type", "vulnerability_level", "data_json", "item_json",
                "updated_at",
            ),
            item_rows,
        )

        copy_rows(
            cur,
            "asset_card_table_rows",
            (
                "asset_id", "row_order", "path", "name", "title", "value_text", "value_type",
                "kind", "parent_type", "parent_object_id", "row_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    index,
                    clean_value(row.get("path")) or "",
                    clean_value(row.get("name")),
                    clean_value(row.get("title")),
                    clean_value(row.get("value")),
                    clean_value(row.get("type")),
                    clean_value(row.get("kind")),
                    clean_value(row.get("parent_type")),
                    clean_value(row.get("parent_object_id")),
                    json.dumps(strip_asset_card_raw(row), ensure_ascii=False),
                    updated_at,
                )
                for index, row in enumerate(table_rows)
                if clean_value(row.get("path"))
            ],
        )

    vulnerability_groups = iter_asset_card_vulnerability_groups(card.get("vulnerabilities"))
    group_rows = [
        (
            asset_id,
            group["source"],
            group["collection_type"],
            group["collection_id"],
            clean_value(group.get("name")),
            clean_value(group.get("level")),
            safe_int(group.get("vulnerabilities_count")) or 0,
            safe_decimal(group.get("cvss_score")),
            safe_int(group.get("order")) or 0,
            bool(group.get("truncated")),
            json.dumps(strip_asset_card_raw({key: value for key, value in group.items() if key != "items"}), ensure_ascii=False),
            updated_at,
        )
        for group in vulnerability_groups
    ]
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_vulnerability_groups",
            (
                "asset_id", "source_type", "collection_type", "collection_id", "name", "severity",
                "vulnerability_count", "cvss_score", "group_order", "truncated", "group_json", "updated_at",
            ),
            group_rows,
        )

    stored_groups = conn.execute(
        """
        SELECT id, source_type, collection_type, collection_id
        FROM asset_card_vulnerability_groups
        WHERE asset_id = %s
        """,
        (asset_id,),
    ).fetchall()
    group_ids = {
        (row["source_type"], row["collection_type"], row["collection_id"]): int(row["id"])
        for row in stored_groups
    }
    finding_rows: list[tuple[Any, ...]] = []
    for group in vulnerability_groups:
        group_id = group_ids.get((group["source"], group["collection_type"], group["collection_id"]))
        if group_id is None:
            continue
        for finding in group.get("items") or []:
            if not isinstance(finding, dict):
                continue
            finding_rows.append(
                (
                    asset_id,
                    group_id,
                    clean_value(finding.get("vulnerability_instance_id")),
                    clean_value(finding.get("vulnerability_id")),
                    clean_value(finding.get("object_id")),
                    clean_value(finding.get("cve_name")),
                    clean_value(finding.get("name")),
                    clean_value(finding.get("level")),
                    safe_decimal(finding.get("cvss_score")),
                    clean_value(finding.get("description_key")),
                    json.dumps(strip_asset_card_raw(finding), ensure_ascii=False),
                    updated_at,
                )
            )
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_vulnerabilities",
            (
                "asset_id", "group_id", "vulnerability_instance_id", "vulnerability_id",
                "object_id", "cve_name", "name", "severity", "cvss_score", "description_key",
                "vulnerability_json", "updated_at",
            ),
            finding_rows,
        )

    reconcile_asset_card_vulnerability_passport_links(conn, None, updated_at, asset_id=asset_id)


def iter_asset_card_vulnerability_groups(vulnerabilities: Any) -> list[dict[str, Any]]:
    if not isinstance(vulnerabilities, dict):
        return []
    sources = vulnerabilities.get("sources")
    if not isinstance(sources, list):
        return []
    groups: list[dict[str, Any]] = []
    for source_doc in sources:
        if not isinstance(source_doc, dict):
            continue
        source_type = clean_value(source_doc.get("source"))
        collection_type = clean_value(source_doc.get("collection_type"))
        source_groups = source_doc.get("groups")
        if not source_type or not collection_type or not isinstance(source_groups, list):
            continue
        for group in source_groups:
            if not isinstance(group, dict):
                continue
            collection_id = clean_value(group.get("collection_id"))
            if not collection_id:
                continue
            groups.append({
                **group,
                "source": source_type,
                "collection_type": collection_type,
                "collection_id": collection_id,
            })
    return groups


def reconcile_asset_card_vulnerability_passport_links(
    conn: psycopg.Connection[dict[str, Any]],
    passport_ids: list[str] | None,
    linked_at: str,
    asset_id: str | None = None,
) -> int:
    """Link findings to passports with two set-based inserts."""

    direct = conn.execute(
        """
        INSERT INTO asset_card_vulnerability_passports (
            asset_vulnerability_id, passport_internal_id, match_method, linked_at
        )
        SELECT findings.id, passports.internal_id, 'vulner_id', %s
        FROM asset_card_vulnerabilities AS findings
        JOIN vulnerability_passports AS passports
          ON passports.internal_id = findings.vulnerability_id
        WHERE (%s::text IS NULL OR findings.asset_id = %s)
          AND (%s::text[] IS NULL OR passports.internal_id = ANY(%s))
        ON CONFLICT(asset_vulnerability_id, passport_internal_id) DO NOTHING
        """,
        (linked_at, asset_id, asset_id, passport_ids, passport_ids),
    )
    fallback = conn.execute(
        """
        WITH passport_cves AS (
            SELECT DISTINCT
                passports.internal_id,
                UPPER(COALESCE(
                    cve ->> 'display_name',
                    cve ->> 'displayName',
                    cve ->> 'cve',
                    cve ->> 'name',
                    cve ->> 'value',
                    CASE WHEN jsonb_typeof(cve) = 'string' THEN cve #>> '{}' END,
                    ''
                )) AS cve_name
            FROM vulnerability_passports AS passports
            CROSS JOIN LATERAL jsonb_array_elements(COALESCE(NULLIF(passports.cves_json, ''), '[]')::jsonb) AS cve
            WHERE (%s::text[] IS NULL OR passports.internal_id = ANY(%s))
        )
        INSERT INTO asset_card_vulnerability_passports (
            asset_vulnerability_id, passport_internal_id, match_method, linked_at
        )
        SELECT findings.id, passport_cves.internal_id, 'cve', %s
        FROM asset_card_vulnerabilities AS findings
        JOIN passport_cves
          ON passport_cves.cve_name = UPPER(COALESCE(findings.cve_name, ''))
        WHERE passport_cves.cve_name <> ''
          AND (%s::text IS NULL OR findings.asset_id = %s)
        ON CONFLICT(asset_vulnerability_id, passport_internal_id) DO NOTHING
        """,
        (passport_ids, passport_ids, linked_at, asset_id, asset_id),
    )
    return max(direct.rowcount or 0, 0) + max(fallback.rowcount or 0, 0)


def load_asset_card_vulnerabilities(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
) -> dict[str, Any]:
    stored_row = conn.execute(
        "SELECT vulnerabilities_json FROM asset_cards WHERE asset_id = %s",
        (asset_id,),
    ).fetchone()
    stored = json_loads(stored_row.get("vulnerabilities_json") if stored_row else None, {})
    result = strip_asset_card_raw(stored) if isinstance(stored, dict) else {}
    sources = result.get("sources") if isinstance(result.get("sources"), list) else []
    source_by_kind = {
        clean_value(source.get("source")): source
        for source in sources
        if isinstance(source, dict) and clean_value(source.get("source"))
    }
    for source in sources:
        if isinstance(source, dict):
            source["groups"] = []

    group_rows = conn.execute(
        """
        SELECT *
        FROM asset_card_vulnerability_groups
        WHERE asset_id = %s
        ORDER BY source_type, group_order, name NULLS LAST, collection_id
        """,
        (asset_id,),
    ).fetchall()
    for group_row in group_rows:
        group = json_loads(group_row.get("group_json"), {})
        if not isinstance(group, dict):
            group = {}
        group.update({
            "source": group_row.get("source_type"),
            "collection_type": group_row.get("collection_type"),
            "collection_id": group_row.get("collection_id"),
            "name": group_row.get("name"),
            "level": group_row.get("severity"),
            "vulnerabilities_count": int(group_row.get("vulnerability_count") or 0),
            "cvss_score": decimal_to_number(group_row.get("cvss_score")),
            "order": int(group_row.get("group_order") or 0),
            "truncated": bool(group_row.get("truncated")),
            "items": [],
        })
        source_type = clean_value(group_row.get("source_type")) or "unknown"
        source = source_by_kind.get(source_type)
        if source is None:
            source = {
                "source": source_type,
                "collection_type": group_row.get("collection_type"),
                "title": "Уязвимости ОС" if source_type == "os" else "Уязвимости программного обеспечения",
                "groups": [],
            }
            source_by_kind[source_type] = source
            sources.append(source)

        finding_rows = conn.execute(
            """
            SELECT
                vulnerability.*,
                COALESCE(
                    array_agg(link.passport_internal_id ORDER BY link.passport_internal_id)
                    FILTER (WHERE link.passport_internal_id IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS passport_ids,
                COALESCE(
                    jsonb_agg(
                        jsonb_build_object(
                            'internal_id', passports.internal_id,
                            'external_id', passports.external_id,
                            'name', passports.name,
                            'severity', passports.severity,
                            'has_detail', passports.raw_detail_json IS NOT NULL,
                            'match_method', link.match_method
                        )
                        ORDER BY COALESCE(passports.name, passports.external_id, passports.internal_id), passports.internal_id
                    ) FILTER (WHERE passports.internal_id IS NOT NULL),
                    '[]'::jsonb
                ) AS passports
            FROM asset_card_vulnerabilities AS vulnerability
            LEFT JOIN asset_card_vulnerability_passports AS link
                ON link.asset_vulnerability_id = vulnerability.id
            LEFT JOIN vulnerability_passports AS passports
                ON passports.internal_id = link.passport_internal_id
            WHERE vulnerability.group_id = %s
            GROUP BY vulnerability.id
            ORDER BY vulnerability.cve_name NULLS LAST, vulnerability.name NULLS LAST, vulnerability.id
            """,
            (group_row["id"],),
        ).fetchall()
        for finding_row in finding_rows:
            finding = json_loads(finding_row.get("vulnerability_json"), {})
            if not isinstance(finding, dict):
                finding = {}
            passports = json_loads(finding_row.get("passports"), [])
            finding.update({
                "level": finding_row.get("severity"),
                "name": finding_row.get("name"),
                "cve_name": finding_row.get("cve_name"),
                "description_key": finding_row.get("description_key"),
                "cvss_score": decimal_to_number(finding_row.get("cvss_score")),
                "object_id": finding_row.get("object_id"),
                "vulnerability_id": finding_row.get("vulnerability_id"),
                "vulnerability_instance_id": finding_row.get("vulnerability_instance_id"),
                "passport_ids": finding_row.get("passport_ids") or [],
                "passports": passports if isinstance(passports, list) else [],
            })
            group["items"].append(finding)
        source["groups"].append(group)

    result["sources"] = sources
    return result


def load_asset_card_cache(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
) -> dict[str, Any]:
    nodes = [
        json_loads(row.get("node_json"), {})
        for row in conn.execute(
            "SELECT node_json FROM asset_card_nodes WHERE asset_id = %s ORDER BY path",
            (asset_id,),
        ).fetchall()
    ]
    table_rows = [
        json_loads(row.get("row_json"), {})
        for row in conn.execute(
            "SELECT row_json FROM asset_card_table_rows WHERE asset_id = %s ORDER BY row_order, path",
            (asset_id,),
        ).fetchall()
    ]

    collection_docs: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        """
        SELECT path, collection_json
        FROM asset_card_collections
        WHERE asset_id = %s
        ORDER BY path
        """,
        (asset_id,),
    ).fetchall():
        path = clean_value(row.get("path")) or ""
        collection = json_loads(row.get("collection_json"), {})
        if isinstance(collection, dict):
            collection["items"] = []
            collection_docs[path] = collection

    for row in conn.execute(
        """
        SELECT collection_path, item_json
        FROM asset_card_collection_items
        WHERE asset_id = %s
        ORDER BY collection_path, item_index
        """,
        (asset_id,),
    ).fetchall():
        collection_path = clean_value(row.get("collection_path")) or ""
        collection = collection_docs.get(collection_path)
        item = json_loads(row.get("item_json"), {})
        if collection is not None and isinstance(item, dict):
            collection.setdefault("items", []).append(item)

    return {
        "nodes": [node for node in nodes if isinstance(node, dict)],
        "collections": list(collection_docs.values()),
        "table_rows": [row for row in table_rows if isinstance(row, dict)],
        "vulnerabilities": load_asset_card_vulnerabilities(conn, asset_id),
    }


def get_asset_card(asset_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
        cache = load_asset_card_cache(conn, asset_id) if row else None
        if row and is_asset_card_cache_empty(cache):
            legacy_card = decode_asset_card(dict(row))
            replace_asset_card_cache(conn, asset_id, legacy_card, now_utc())
            cache = load_asset_card_cache(conn, asset_id)
    return decode_asset_card(dict(row), cache=cache) if row else None


def delete_asset_card(asset_id: str) -> bool:
    init_db()
    with connect() as conn:
        row = conn.execute(
            "DELETE FROM asset_cards WHERE asset_id = %s RETURNING asset_id",
            (asset_id,),
        ).fetchone()
    return row is not None


def is_asset_card_cache_empty(cache: dict[str, Any] | None) -> bool:
    if not isinstance(cache, dict):
        return True
    return not any(cache.get(key) for key in ("nodes", "collections", "table_rows"))


def list_asset_cards(
    *,
    q: str | None = None,
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
                asset_id ILIKE %s OR display_name ILIKE %s OR asset_type ILIKE %s OR
                fqdn ILIKE %s OR hostname ILIKE %s OR ip_address ILIKE %s OR
                os_name ILIKE %s OR os_version ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like, like, like, like])
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = max(1, min(limit, 50000))
    offset = max(0, offset)

    with connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM asset_cards {where}", params).fetchone()
        rows = conn.execute(
            f"""
            SELECT
                id, asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp,
                stats_json, first_seen, last_seen
            FROM asset_cards
            {where}
            ORDER BY last_seen DESC, display_name NULLS LAST, asset_id
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    return {
        "total": int(total_row["count"] or 0),
        "rows": [decode_asset_card_summary(dict(row)) for row in rows],
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


def text_parameter(value: Any) -> str | None:
    """Return a psycopg-safe text value while preserving structured context."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_decimal(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def decimal_to_number(value: Any) -> int | float | None:
    number = safe_decimal(value)
    if number is None:
        return None
    return int(number) if number.is_integer() else number


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def decode_asset_card_summary(row: dict[str, Any]) -> dict[str, Any]:
    stats = json_loads(row.get("stats_json"), {})
    return {
        "id": row.get("id"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "asset_type": row.get("asset_type"),
        "fqdn": row.get("fqdn"),
        "hostname": row.get("hostname"),
        "ip_address": row.get("ip_address"),
        "os_name": row.get("os_name"),
        "os_version": row.get("os_version"),
        "vulnerability_level": row.get("vulnerability_level"),
        "token_timestamp": row.get("token_timestamp"),
        "stats": stats if isinstance(stats, dict) else {},
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def decode_asset_card_build_job(row: dict[str, Any]) -> dict[str, Any]:
    request = json_loads(row.get("request_json"), {})
    stats = json_loads(row.get("stats_json"), {})
    return {
        "job_id": row.get("job_id"),
        "trace_id": row.get("trace_id"),
        "asset_id": row.get("asset_id"),
        "operation": row.get("operation"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "progress_percent": max(0, min(100, int(row.get("progress_percent") or 0))),
        "request": request if isinstance(request, dict) else {},
        "stats": stats if isinstance(stats, dict) else {},
        "discovered_requests": int(row.get("discovered_requests") or 0),
        "completed_requests": int(row.get("completed_requests") or 0),
        "node_count": int(row.get("node_count") or 0),
        "collection_count": int(row.get("collection_count") or 0),
        "finding_count": int(row.get("finding_count") or 0),
        "warning_count": int(row.get("warning_count") or 0),
        "cancel_requested": bool(row.get("cancel_requested")),
        "worker_id": row.get("worker_id"),
        "lease_until": row.get("lease_until"),
        "attempt_count": int(row.get("attempt_count") or 0),
        "message": row.get("message"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


def decode_asset_card(row: dict[str, Any], cache: dict[str, Any] | None = None) -> dict[str, Any]:
    root = json_loads(row.get("root_json"), {})
    metadata = json_loads(row.get("metadata_json"), {})
    cached_nodes = cache.get("nodes") if isinstance(cache, dict) else None
    cached_collections = cache.get("collections") if isinstance(cache, dict) else None
    cached_table_rows = cache.get("table_rows") if isinstance(cache, dict) else None
    cached_vulnerabilities = cache.get("vulnerabilities") if isinstance(cache, dict) else None
    nodes = cached_nodes if cached_nodes else json_loads(row.get("nodes_json"), [])
    collections = cached_collections if cached_collections else json_loads(row.get("collections_json"), [])
    table_rows = cached_table_rows if cached_table_rows else json_loads(row.get("table_rows_json"), [])
    vulnerabilities = cached_vulnerabilities if isinstance(cached_vulnerabilities, dict) else json_loads(row.get("vulnerabilities_json"), {})
    stats = json_loads(row.get("stats_json"), {})
    return {
        "id": row.get("id"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "asset_type": row.get("asset_type"),
        "fqdn": row.get("fqdn"),
        "hostname": row.get("hostname"),
        "ip_address": row.get("ip_address"),
        "os_name": row.get("os_name"),
        "os_version": row.get("os_version"),
        "vulnerability_level": row.get("vulnerability_level"),
        "token_timestamp": row.get("token_timestamp"),
        "root": root if isinstance(root, dict) else {},
        "metadata": metadata if isinstance(metadata, dict) else {},
        "nodes": strip_asset_card_raw(nodes) if isinstance(nodes, list) else [],
        "collections": strip_asset_card_raw(collections) if isinstance(collections, list) else [],
        "table_rows": strip_asset_card_raw(table_rows) if isinstance(table_rows, list) else [],
        "vulnerabilities": strip_asset_card_raw(vulnerabilities) if isinstance(vulnerabilities, dict) else {},
        "stats": stats if isinstance(stats, dict) else {},
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def strip_asset_card_raw(value: Any) -> Any:
    raw_keys = {"raw", "raw_card", "raw_record", "raw_detail", "raw_value"}
    if isinstance(value, list):
        return [strip_asset_card_raw(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_asset_card_raw(item)
            for key, item in value.items()
            if key not in raw_keys
        }
    return value


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
        "has_detail": isinstance(raw_detail, dict),
        "source_pdql": row.get("source_pdql"),
        "pdql_token": row.get("pdql_token"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "detail_updated_at": row.get("detail_updated_at"),
    }


def decode_vulnerability_passport_summary(row: dict[str, Any]) -> dict[str, Any]:
    cves = json_loads(row.get("cves_json"), [])
    metrics = json_loads(row.get("metrics_json"), {})
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
        "has_detail": bool(row.get("has_detail")),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "detail_updated_at": row.get("detail_updated_at"),
    }


def decode_vulnerability_passport_detail_job(row: dict[str, Any]) -> dict[str, Any]:
    errors = json_loads(row.get("errors_json"), [])
    request = json_loads(row.get("request_json"), {})
    return {
        "job_id": row.get("job_id"),
        "status": row.get("status"),
        "requested_count": int(row.get("requested_count") or 0),
        "eligible_count": int(row.get("eligible_count") or 0),
        "processed_count": int(row.get("processed_count") or 0),
        "loaded_count": int(row.get("loaded_count") or 0),
        "failed_count": int(row.get("failed_count") or 0),
        "skipped_fresh_count": int(row.get("skipped_fresh_count") or 0),
        "cancel_requested": bool(row.get("cancel_requested")),
        "errors": errors if isinstance(errors, list) else [],
        "request": request if isinstance(request, dict) else {},
        "worker_id": row.get("worker_id"),
        "lease_until": row.get("lease_until"),
        "attempt_count": int(row.get("attempt_count") or 0),
        "message": row.get("message"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
