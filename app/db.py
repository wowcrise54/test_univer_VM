from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
from contextlib import nullcontext
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
        CREATE TABLE IF NOT EXISTS operations (
            operation_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            progress_percent INTEGER NOT NULL DEFAULT 0,
            subject_type TEXT,
            subject_id TEXT,
            subject_label TEXT,
            message TEXT,
            error_json TEXT NOT NULL DEFAULT '{}',
            request_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            trace_id TEXT,
            retry_of TEXT REFERENCES operations(operation_id) ON DELETE SET NULL,
            idempotency_key TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE(kind, source_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS operation_events (
            id BIGSERIAL PRIMARY KEY,
            operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            message TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS saved_views (
            id BIGSERIAL PRIMARY KEY,
            route TEXT NOT NULL,
            name TEXT NOT NULL,
            filters_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(route, name)
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
        """
        CREATE TABLE IF NOT EXISTS asset_card_search_fields (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            entity_path TEXT NOT NULL,
            field_path TEXT NOT NULL,
            field_name TEXT NOT NULL,
            value_type TEXT NOT NULL,
            value_text TEXT,
            value_text_normalized TEXT,
            value_number NUMERIC,
            value_boolean BOOLEAN,
            updated_at TEXT NOT NULL
        )
        """,
        "ALTER TABLE asset_cards ADD COLUMN IF NOT EXISTS vulnerabilities_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE asset_card_build_jobs ADD COLUMN IF NOT EXISTS trace_id TEXT",
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
        "CREATE INDEX IF NOT EXISTS idx_operations_status_created ON operations(status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_operations_kind_created ON operations(kind, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_operations_updated ON operations(updated_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_operations_idempotency ON operations(idempotency_key) WHERE idempotency_key IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_operation_events_operation_created ON operation_events(operation_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_saved_views_route_name ON saved_views(route, name)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_runs_task_created ON scan_postprocess_runs(mp_task_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_runs_status ON scan_postprocess_runs(status, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_items_run_status ON scan_postprocess_items(postprocess_run_id, status, id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_postprocess_items_asset ON scan_postprocess_items(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_display_name_lower ON asset_cards((LOWER(display_name)))",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_fqdn_lower ON asset_cards((LOWER(fqdn)))",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_ip ON asset_cards(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_type ON asset_cards(asset_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_nodes_asset_path ON asset_card_nodes(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_nodes_type ON asset_card_nodes(object_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collections_asset_path ON asset_card_collections(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collections_name ON asset_card_collections(name)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collection_items_asset_collection ON asset_card_collection_items(asset_id, collection_path, item_index)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_collection_items_type ON asset_card_collection_items(object_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_table_rows_asset_path ON asset_card_table_rows(asset_id, path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_table_rows_kind ON asset_card_table_rows(kind)",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_asset ON asset_card_search_fields(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_text ON asset_card_search_fields(field_path, value_text_normalized, asset_id) WHERE value_type = 'text'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_number ON asset_card_search_fields(field_path, value_number, asset_id) WHERE value_type = 'number'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_boolean ON asset_card_search_fields(field_path, value_boolean, asset_id) WHERE value_type = 'boolean'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_entity ON asset_card_search_fields(asset_id, entity_path, field_path)",
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


ACTIVE_OPERATION_STATUSES = {"queued", "running", "cancelling", "recovering"}
RETRYABLE_OPERATION_KINDS = {"asset_card_build", "passport_detail_sync"}


def validated_sort_sql(sort_by: str | None, sort_dir: str | None, allowed: dict[str, str], *, default: str) -> tuple[str, str]:
    key = sort_by or default
    expression = allowed.get(key)
    if not expression:
        raise ValueError(f"Unsupported sort column: {key}")
    return expression, "DESC" if str(sort_dir or "").lower() == "desc" else "ASC"


def register_operation(
    operation_id: str,
    *,
    kind: str,
    source_id: str,
    status: str = "queued",
    stage: str = "queued",
    progress_percent: int = 0,
    subject_type: str | None = None,
    subject_id: str | None = None,
    subject_label: str | None = None,
    message: str | None = None,
    error: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    trace_id: str | None = None,
    retry_of: str | None = None,
    idempotency_key: str | None = None,
    created_at: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    updated_at: str | None = None,
    _conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    """Create or refresh the normalized operation registry without replacing richer request data."""
    if _conn is None:
        init_db()
    current = updated_at or now_utc()
    created = created_at or current
    clean_key = clean_value(idempotency_key)
    with (nullcontext(_conn) if _conn is not None else connect()) as conn:
        row = conn.execute(
            """
            INSERT INTO operations (
                operation_id, kind, source_id, status, stage, progress_percent,
                subject_type, subject_id, subject_label, message, error_json,
                request_json, result_json, trace_id, retry_of, idempotency_key,
                created_at, started_at, finished_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(kind, source_id) DO UPDATE SET
                status = EXCLUDED.status,
                stage = EXCLUDED.stage,
                progress_percent = GREATEST(operations.progress_percent, EXCLUDED.progress_percent),
                subject_type = COALESCE(EXCLUDED.subject_type, operations.subject_type),
                subject_id = COALESCE(EXCLUDED.subject_id, operations.subject_id),
                subject_label = COALESCE(EXCLUDED.subject_label, operations.subject_label),
                message = COALESCE(EXCLUDED.message, operations.message),
                error_json = CASE WHEN EXCLUDED.error_json = '{}' THEN operations.error_json ELSE EXCLUDED.error_json END,
                request_json = CASE WHEN EXCLUDED.request_json = '{}' THEN operations.request_json ELSE EXCLUDED.request_json END,
                result_json = CASE WHEN EXCLUDED.result_json = '{}' THEN operations.result_json ELSE EXCLUDED.result_json END,
                trace_id = COALESCE(EXCLUDED.trace_id, operations.trace_id),
                retry_of = COALESCE(EXCLUDED.retry_of, operations.retry_of),
                idempotency_key = COALESCE(EXCLUDED.idempotency_key, operations.idempotency_key),
                started_at = COALESCE(EXCLUDED.started_at, operations.started_at),
                finished_at = COALESCE(EXCLUDED.finished_at, operations.finished_at),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (
                operation_id,
                kind,
                source_id,
                status,
                stage,
                max(0, min(100, int(progress_percent or 0))),
                subject_type,
                subject_id,
                subject_label,
                message,
                json.dumps(error or {}, ensure_ascii=False),
                json.dumps(request or {}, ensure_ascii=False),
                json.dumps(result or {}, ensure_ascii=False),
                trace_id,
                retry_of,
                clean_key,
                created,
                started_at,
                finished_at,
                current,
            ),
        ).fetchone()
        _append_operation_event(conn, dict(row))
    return decode_operation(dict(row))


def _append_operation_event(conn: psycopg.Connection, row: dict[str, Any]) -> None:
    previous = conn.execute(
        """
        SELECT status, stage, message
        FROM operation_events
        WHERE operation_id = %s
        ORDER BY id DESC
        LIMIT 1
        """,
        (row["operation_id"],),
    ).fetchone()
    if previous and all(previous.get(key) == row.get(key) for key in ("status", "stage", "message")):
        return
    conn.execute(
        """
        INSERT INTO operation_events (operation_id, status, stage, message, details_json, created_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            row["operation_id"],
            row["status"],
            row["stage"],
            row.get("message"),
            json.dumps({"progress_percent": row.get("progress_percent", 0)}, ensure_ascii=False),
            row.get("updated_at") or now_utc(),
        ),
    )


def sync_operations_from_sources() -> None:
    """Refresh the registry from legacy job tables so old endpoints remain authoritative."""
    init_db()
    with connect() as conn:
        asset_jobs = conn.execute(
            """SELECT source.* FROM asset_card_build_jobs source
               LEFT JOIN operations op ON op.kind = 'asset_card_build' AND op.source_id = source.job_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        passport_jobs = conn.execute(
            """SELECT source.* FROM vulnerability_passport_detail_jobs source
               LEFT JOIN operations op ON op.kind = 'passport_detail_sync' AND op.source_id = source.job_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        postprocess_runs = conn.execute(
            """SELECT source.* FROM scan_postprocess_runs source
               LEFT JOIN operations op ON op.kind = 'scan_postprocess' AND op.source_id = source.run_id
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
        import_runs = conn.execute(
            """SELECT source.* FROM import_runs source
               LEFT JOIN operations op ON op.kind = 'pdql_export' AND op.source_id = source.id::text
               WHERE op.operation_id IS NULL OR COALESCE(source.finished_at, source.started_at) > op.updated_at"""
        ).fetchall()
        removal_runs = conn.execute(
            """SELECT source.* FROM asset_removal_operations source
               LEFT JOIN operations op ON op.kind = 'asset_removal' AND op.source_id = source.id::text
               WHERE op.operation_id IS NULL OR source.updated_at > op.updated_at"""
        ).fetchall()
    for raw in asset_jobs:
        row = dict(raw)
        register_operation(
            row["job_id"], kind="asset_card_build", source_id=row["job_id"],
            status=row["status"], stage=row.get("stage") or row["status"],
            progress_percent=row.get("progress_percent") or 0,
            subject_type="asset", subject_id=row.get("asset_id"), subject_label=row.get("asset_id"),
            message=row.get("message"), request=json_loads(row.get("request_json"), {}),
            result=json_loads(row.get("stats_json"), {}), trace_id=row.get("trace_id"),
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in passport_jobs:
        row = dict(raw)
        eligible = int(row.get("eligible_count") or 0)
        processed = int(row.get("processed_count") or 0)
        progress = 100 if not eligible else round(processed * 100 / eligible)
        register_operation(
            row["job_id"], kind="passport_detail_sync", source_id=row["job_id"],
            status=row["status"], stage=row["status"], progress_percent=progress,
            subject_type="vulnerability_passports", subject_label="Vulnerability passports",
            message=row.get("message"), error={"items": json_loads(row.get("errors_json"), [])},
            result={
                "requested_count": row.get("requested_count"), "eligible_count": eligible,
                "processed_count": processed, "loaded_count": row.get("loaded_count"),
                "failed_count": row.get("failed_count"), "skipped_fresh_count": row.get("skipped_fresh_count"),
            },
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in postprocess_runs:
        row = dict(raw)
        options = json_loads(row.get("options_json"), {})
        refresh_asset_id = options.get("refresh_asset_id") if isinstance(options, dict) else None
        refresh_label = options.get("refresh_asset_label") if isinstance(options, dict) else None
        total = max(int(row.get("target_count") or 0), int(row.get("total_job_count") or 0), 1)
        done = int(row.get("completed_count") or 0) + int(row.get("failed_count") or 0)
        progress = min(100, round(done * 100 / total))
        register_operation(
            row["run_id"], kind="scan_postprocess", source_id=row["run_id"],
            status=row["status"], stage=row.get("stage") or row["status"], progress_percent=progress,
            subject_type="asset_card" if refresh_asset_id else "scanner_task",
            subject_id=refresh_asset_id or row.get("mp_task_id"),
            subject_label=refresh_label or refresh_asset_id or row.get("mp_task_id"),
            message=row.get("message"), error={"message": row.get("error")} if row.get("error") else {},
            request=options,
            result={"mp_run_id": row.get("mp_run_id"), "completed_count": row.get("completed_count"), "failed_count": row.get("failed_count")},
            created_at=row.get("created_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("updated_at"),
        )
    for raw in import_runs:
        row = dict(raw)
        operation_id = f"import:{row['id']}"
        register_operation(
            operation_id, kind="pdql_export", source_id=str(row["id"]),
            status=row.get("status") or "completed", stage=row.get("status") or "completed",
            progress_percent=100 if row.get("finished_at") else 25,
            subject_type="export", subject_id=str(row["id"]), subject_label=row.get("csv_filename") or row.get("source"),
            message=row.get("error") or f"Imported {int(row.get('row_count') or 0)} rows",
            error={"message": row.get("error")} if row.get("error") else {},
            request={"pdql": row.get("pdql"), "delete_after_export": row.get("delete_after_export")},
            result={"row_count": row.get("row_count"), "asset_count": row.get("asset_count"), "finding_count": row.get("finding_count")},
            created_at=row.get("started_at"), started_at=row.get("started_at"),
            finished_at=row.get("finished_at"), updated_at=row.get("finished_at") or row.get("started_at"),
        )
    for raw in removal_runs:
        row = dict(raw)
        operation_id = f"removal:{row['id']}"
        status = row.get("status") or "queued"
        register_operation(
            operation_id, kind="asset_removal", source_id=str(row["id"]),
            status=status, stage=status, progress_percent=100 if status in {"completed", "success", "failed"} else 25,
            subject_type="assets", subject_id=row.get("operation_id"), subject_label="MP VM assets",
            message=row.get("message"), request={"asset_ids": json_loads(row.get("asset_ids_json"), [])},
            result=json_loads(row.get("raw_response_json"), {}),
            created_at=row.get("created_at"), started_at=row.get("created_at"),
            finished_at=row.get("updated_at") if status not in ACTIVE_OPERATION_STATUSES else None,
            updated_at=row.get("updated_at"),
        )


def list_operations(
    *,
    status: str | None = None,
    kind: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str | None = None,
) -> dict[str, Any]:
    sync_operations_from_sources()
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status = %s")
        params.append(status)
    if kind:
        clauses.append("kind = %s")
        params.append(kind)
    if q:
        clauses.append("(LOWER(COALESCE(subject_label, '')) LIKE %s OR LOWER(COALESCE(subject_id, '')) LIKE %s OR LOWER(COALESCE(message, '')) LIKE %s)")
        needle = f"%{q.strip().lower()}%"
        params.extend([needle, needle, needle])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    limit = max(1, min(200, int(limit)))
    offset = max(0, int(offset))
    sort_expression, direction = validated_sort_sql(
        sort_by,
        sort_dir,
        {"created_at": "created_at", "updated_at": "updated_at", "status": "LOWER(status)", "kind": "LOWER(kind)", "subject": "LOWER(subject_label)", "progress": "progress_percent"},
        default="created_at",
    )
    if sort_by is None:
        direction = "DESC"
    with connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS count FROM operations {where}", params).fetchone()["count"]
        rows = conn.execute(
            f"SELECT * FROM operations {where} ORDER BY {sort_expression} {direction} NULLS LAST, operation_id ASC LIMIT %s OFFSET %s",
            [*params, limit, offset],
        ).fetchall()
    return {"total": int(total), "rows": [decode_operation(dict(row)) for row in rows], "limit": limit, "offset": offset}


def get_operation(operation_id: str, *, include_events: bool = True) -> dict[str, Any] | None:
    sync_operations_from_sources()
    with connect() as conn:
        row = conn.execute("SELECT * FROM operations WHERE operation_id = %s", (operation_id,)).fetchone()
        if not row:
            return None
        events = conn.execute(
            "SELECT * FROM operation_events WHERE operation_id = %s ORDER BY id DESC LIMIT 100",
            (operation_id,),
        ).fetchall() if include_events else []
    result = decode_operation(dict(row))
    if include_events:
        result["events"] = [decode_operation_event(dict(item)) for item in reversed(events)]
    return result


def get_operation_by_idempotency_key(idempotency_key: str | None) -> dict[str, Any] | None:
    clean_key = clean_value(idempotency_key)
    if not clean_key:
        return None
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM operations WHERE idempotency_key = %s", (clean_key,)).fetchone()
    return decode_operation(dict(row)) if row else None


def set_operation_retry(operation_id: str, retry_of: str, idempotency_key: str | None = None) -> dict[str, Any] | None:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            "UPDATE operations SET retry_of = %s, idempotency_key = COALESCE(%s, idempotency_key), updated_at = %s WHERE operation_id = %s RETURNING *",
            (retry_of, clean_value(idempotency_key), current, operation_id),
        ).fetchone()
    return decode_operation(dict(row)) if row else None


def list_saved_views(route: str) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute("SELECT * FROM saved_views WHERE route = %s ORDER BY name", (route,)).fetchall()
    return [decode_saved_view(dict(row)) for row in rows]


def save_view(route: str, name: str, filters: dict[str, Any]) -> dict[str, Any]:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            INSERT INTO saved_views (route, name, filters_json, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT(route, name) DO UPDATE SET filters_json = EXCLUDED.filters_json, updated_at = EXCLUDED.updated_at
            RETURNING *
            """,
            (route, name, json.dumps(filters, ensure_ascii=False), current, current),
        ).fetchone()
    return decode_saved_view(dict(row))


def delete_saved_view(view_id: int) -> bool:
    init_db()
    with connect() as conn:
        result = conn.execute("DELETE FROM saved_views WHERE id = %s", (view_id,))
    return bool(result.rowcount)


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


def get_asset_card_refresh_template(asset_id: str, template_task_id: str | None = None) -> dict[str, Any] | None:
    """Return an explicit task, the task that produced the card, or the latest usable local task."""
    with connect() as conn:
        if template_task_id:
            row = conn.execute(
                "SELECT * FROM scan_tasks WHERE mp_task_id = %s AND deleted_at IS NULL",
                (template_task_id,),
            ).fetchone()
            return _decode_scan_task(dict(row)) if row else None

        row = conn.execute(
            """
            SELECT task.*
            FROM scan_postprocess_items item
            JOIN scan_postprocess_runs run ON run.run_id = item.postprocess_run_id
            JOIN scan_tasks task ON task.mp_task_id = run.mp_task_id
            WHERE item.asset_id = %s
              AND task.deleted_at IS NULL
            ORDER BY item.updated_at DESC, task.updated_at DESC
            LIMIT 1
            """,
            (asset_id,),
        ).fetchone()
        if not row:
            row = conn.execute(
                """
                SELECT * FROM scan_tasks
                WHERE deleted_at IS NULL
                ORDER BY updated_at DESC, id DESC
                LIMIT 1
                """
            ).fetchone()
    return _decode_scan_task(dict(row)) if row else None


def get_active_asset_card_refresh(asset_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM scan_postprocess_runs
            WHERE status IN ('monitoring', 'resolving', 'processing', 'waiting')
              AND options_json::jsonb ->> 'refresh_asset_id' = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (asset_id,),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


SCAN_POSTPROCESS_ACTIVE_STATUSES = {"monitoring", "resolving", "processing", "waiting"}
SCAN_POSTPROCESS_FAILED_ITEM_STATUSES = {"resolution_failed", "build_failed", "removal_failed"}


def create_scan_postprocess_run(
    run_id: str,
    *,
    mp_task_id: str,
    started_from: str,
    options: dict[str, Any],
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    current = now_utc()
    refresh_asset_id = options.get("refresh_asset_id")
    refresh_label = options.get("refresh_asset_label")
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
        register_operation(
            run_id,
            kind="scan_postprocess",
            source_id=run_id,
            status="monitoring",
            stage="waiting_for_run",
            subject_type="asset_card" if refresh_asset_id else "scanner_task",
            subject_id=refresh_asset_id or mp_task_id,
            subject_label=refresh_label or refresh_asset_id or mp_task_id,
            request=options,
            idempotency_key=idempotency_key,
            created_at=current,
            updated_at=current,
            _conn=conn,
        )
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


def list_pending_asset_refresh_task_cleanups() -> list[dict[str, Any]]:
    """Terminal refresh runs keep their local task row until remote task deletion succeeds."""
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT ON (run.mp_task_id) run.*
            FROM scan_postprocess_runs run
            JOIN scan_tasks task ON task.mp_task_id = run.mp_task_id
            WHERE run.status NOT IN ('monitoring', 'resolving', 'processing', 'waiting')
              AND run.options_json::jsonb ->> 'auto_created_refresh_task' = 'true'
            ORDER BY run.mp_task_id, run.updated_at DESC
            """
        ).fetchall()
    return [decode_scan_postprocess_run(dict(row)) for row in rows]


def claim_scan_postprocess_run(run_id: str, worker_id: str) -> dict[str, Any] | None:
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = %s, started_at = COALESCE(started_at, %s), updated_at = %s
            WHERE run_id = %s
              AND worker_id IS NULL
              AND status IN ('monitoring', 'resolving', 'processing', 'waiting')
            RETURNING *
            """,
            (worker_id, current, current, run_id),
        ).fetchone()
    return decode_scan_postprocess_run(dict(row)) if row else None


def release_scan_postprocess_leases() -> None:
    current = now_utc()
    with connect() as conn:
        conn.execute(
            """
            UPDATE scan_postprocess_runs
            SET worker_id = NULL, updated_at = %s
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
                worker_id = NULL, finished_at = %s, updated_at = %s
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
            ORDER BY {order_sql}
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
    sort_by: str | None = None,
    sort_dir: str | None = None,
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
            ORDER BY {order_sql}
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


def create_vulnerability_passport_detail_job(
    job_id: str,
    *,
    requested_count: int,
    eligible_count: int,
    skipped_fresh_count: int,
    request: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
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
                created_at, finished_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                job_id,
                status,
                requested_count,
                eligible_count,
                skipped_fresh_count,
                current,
                finished_at,
                current,
            ),
        ).fetchone()
        register_operation(
            job_id,
            kind="passport_detail_sync",
            source_id=job_id,
            status=status,
            stage=status,
            progress_percent=100 if not eligible_count else 0,
            subject_type="vulnerability_passports",
            subject_label="Vulnerability passports",
            request=request,
            result={"requested_count": requested_count, "eligible_count": eligible_count, "skipped_fresh_count": skipped_fresh_count},
            idempotency_key=idempotency_key,
            created_at=current,
            finished_at=finished_at,
            updated_at=current,
            _conn=conn,
        )
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


def start_vulnerability_passport_detail_job(job_id: str) -> dict[str, Any] | None:
    init_db()
    current = now_utc()
    with connect() as conn:
        row = conn.execute(
            """
            UPDATE vulnerability_passport_detail_jobs
            SET status = CASE WHEN cancel_requested THEN 'cancelling' ELSE 'running' END,
                started_at = COALESCE(started_at, %s),
                updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, current, job_id),
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
    idempotency_key: str | None = None,
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
        if row:
            register_operation(
                job_id,
                kind="asset_card_build",
                source_id=job_id,
                status="queued",
                stage="queued",
                subject_type="asset",
                subject_id=asset_id,
                subject_label=asset_id,
                request=request,
                trace_id=trace_id,
                idempotency_key=idempotency_key,
                created_at=current,
                updated_at=current,
                _conn=conn,
            )
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
                started_at = COALESCE(started_at, %s), updated_at = %s
            WHERE job_id = %s AND status = 'queued'
            RETURNING *
            """,
            (current, current, job_id),
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
        replace_asset_card_search_index(conn, asset_id, card, current)
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
                "asset_id", "path", "title", "display_name", "object_id", "object_type",
                "vulnerability_level", "data_json", "node_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(node.get("path")) or "",
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
                "asset_id", "path", "name", "title", "value_type", "kind", "parent_type",
                "parent_object_id", "reported_count", "fetched_count", "truncated",
                "collection_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(collection.get("path")) or "",
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


ASSET_SEARCH_HIDDEN_KEYS = {
    "raw", "rawcard", "rawrecord", "rawdetail", "rawvalue", "objectid", "type",
}


def is_hidden_asset_search_key(key: Any) -> bool:
    normalized = re.sub(r"[_-]", "", str(key or "")).lower()
    return normalized in ASSET_SEARCH_HIDDEN_KEYS or normalized.startswith("raw")


def asset_search_leaf_rows(
    value: Any,
    *,
    entity_path: str,
    field_path: str,
    field_name: str,
    depth: int = 0,
) -> list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]]:
    if depth > 8 or value is None:
        return []
    if isinstance(value, dict):
        if "hasItems" in value and isinstance(value.get("hasItems"), bool):
            value = value["hasItems"]
        else:
            rows: list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]] = []
            nested = value.get("data") if isinstance(value.get("data"), dict) else value
            for key, child in nested.items():
                if is_hidden_asset_search_key(key):
                    continue
                child_path = f"{field_path}.{key}" if field_path else str(key)
                rows.extend(asset_search_leaf_rows(
                    child,
                    entity_path=entity_path,
                    field_path=child_path,
                    field_name=str(key),
                    depth=depth + 1,
                ))
            return rows
    if isinstance(value, list):
        rows = []
        for item in value:
            rows.extend(asset_search_leaf_rows(
                item,
                entity_path=entity_path,
                field_path=field_path,
                field_name=field_name,
                depth=depth + 1,
            ))
        return rows
    if isinstance(value, bool):
        return [(entity_path, field_path, field_name, "boolean", "true" if value else "false", "true" if value else "false", None, value)]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [(entity_path, field_path, field_name, "number", str(value), str(value), value, None)]
    text = clean_value(value)
    if text is None:
        return []
    return [(entity_path, field_path, field_name, "text", text, text.lower(), None, None)]


def build_asset_card_search_rows(card: dict[str, Any]) -> list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]]:
    root = card.get("root") if isinstance(card.get("root"), dict) else {}
    root_data = root.get("data") if isinstance(root.get("data"), dict) else {}
    rows: list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]] = []
    summary = {
        "assetId": clean_value(card.get("asset_id")),
        "displayName": first_non_empty(card.get("display_name"), root.get("displayName")),
        "assetType": first_non_empty(card.get("asset_type"), root.get("type")),
        "fqdn": first_non_empty(card.get("fqdn"), root_data.get("fqdn")),
        "hostname": first_non_empty(card.get("hostname"), root_data.get("hostname")),
        "ipAddress": first_non_empty(card.get("ip_address"), root_data.get("ipAddress")),
        "osName": first_non_empty(card.get("os_name"), root_data.get("osName")),
        "osVersion": first_non_empty(card.get("os_version"), root_data.get("osVersion")),
        "vulnerabilityLevel": first_non_empty(card.get("vulnerability_level"), root.get("vulnerabilityLevel")),
    }
    rows.extend(asset_search_leaf_rows(summary, entity_path="asset", field_path="asset", field_name="asset"))
    rows.extend(asset_search_leaf_rows(root_data, entity_path="asset", field_path="asset", field_name="asset"))
    for node in card.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        path = clean_value(node.get("path"))
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        if path:
            rows.extend(asset_search_leaf_rows(data, entity_path=path, field_path=path, field_name=asset_path_leaf(path)))
    for collection in card.get("collections") or []:
        if not isinstance(collection, dict):
            continue
        collection_path = clean_value(collection.get("path"))
        if not collection_path:
            continue
        for index, item in enumerate(collection.get("items") or []):
            item_doc = item if isinstance(item, dict) else {"value": item}
            entity_path = clean_value(item_doc.get("path")) or f"{collection_path}[{index}]"
            if isinstance(item_doc.get("data"), dict):
                value = item_doc["data"]
                field_path = collection_path
            elif "value" in item_doc:
                value = item_doc.get("value")
                field_path = collection_path
            else:
                value = {key: val for key, val in item_doc.items() if key not in {"path", "node"}}
                field_path = collection_path
            rows.extend(asset_search_leaf_rows(
                value,
                entity_path=entity_path,
                field_path=field_path,
                field_name=clean_value(collection.get("name")) or asset_path_leaf(collection_path),
            ))
    deduped = list(dict.fromkeys(rows))
    return deduped


def asset_path_leaf(path: str) -> str:
    return re.split(r"[.\[]", str(path))[-1].rstrip("]") or str(path)


def replace_asset_card_search_index(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    card: dict[str, Any],
    updated_at: str,
) -> int:
    conn.execute("DELETE FROM asset_card_search_fields WHERE asset_id = %s", (asset_id,))
    rows = build_asset_card_search_rows(card)
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_search_fields",
            (
                "asset_id", "entity_path", "field_path", "field_name", "value_type",
                "value_text", "value_text_normalized", "value_number", "value_boolean", "updated_at",
            ),
            [(asset_id, *row, updated_at) for row in rows],
        )
    return len(rows)


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
    sort_by: str | None = None,
    sort_dir: str | None = None,
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
    sort_expression, direction = validated_sort_sql(
        sort_by,
        sort_dir,
        {"display_name": "LOWER(display_name)", "ip_address": "LOWER(ip_address)", "fqdn": "LOWER(fqdn)", "os_name": "LOWER(os_name)", "asset_type": "LOWER(asset_type)", "vulnerability_level": "LOWER(vulnerability_level)", "last_seen": "last_seen"},
        default="last_seen",
    )
    if sort_by is None:
        direction = "DESC"

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
            ORDER BY {sort_expression} {direction} NULLS LAST, asset_id ASC
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


ASSET_QUERY_TEXT_OPERATORS = {"equals", "not_equals", "contains", "starts_with", "in"}
ASSET_QUERY_NUMBER_OPERATORS = {"equals", "not_equals", "gt", "gte", "lt", "lte"}
ASSET_QUERY_BOOLEAN_OPERATORS = {"is_true", "is_false"}
ASSET_QUERY_COMMON_OPERATORS = {"exists", "not_exists"}


def asset_card_search_index_coverage() -> dict[str, int]:
    init_db()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM asset_cards) AS total_cards,
                (SELECT COUNT(DISTINCT asset_id) FROM asset_card_search_fields) AS indexed_cards
            """
        ).fetchone()
    return {"total_cards": int(row["total_cards"] or 0), "indexed_cards": int(row["indexed_cards"] or 0)}


def backfill_asset_card_search_index_batch(limit: int = 20) -> dict[str, int]:
    init_db()
    limit = max(1, min(100, int(limit)))
    with connect() as conn:
        missing = conn.execute(
            """
            SELECT card.asset_id
            FROM asset_cards card
            WHERE NOT EXISTS (
                SELECT 1 FROM asset_card_search_fields field WHERE field.asset_id = card.asset_id
            )
            ORDER BY card.last_seen DESC, card.asset_id
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    processed = 0
    indexed_fields = 0
    for row in missing:
        asset_id = str(row["asset_id"])
        card = get_asset_card(asset_id)
        if not card:
            continue
        current = now_utc()
        with connect() as conn:
            indexed_fields += replace_asset_card_search_index(conn, asset_id, card, current)
        processed += 1
    coverage = asset_card_search_index_coverage()
    return {**coverage, "processed": processed, "indexed_fields": indexed_fields}


def list_asset_card_search_fields(q: str | None = None, limit: int = 100) -> dict[str, Any]:
    init_db()
    limit = max(1, min(500, int(limit)))
    params: list[Any] = []
    where = ""
    if q:
        needle = f"%{q.strip().lower()}%"
        where = "WHERE LOWER(field_path) LIKE %s OR LOWER(field_name) LIKE %s"
        params.extend([needle, needle])
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                field_path,
                MIN(field_name) AS field_name,
                value_type,
                COUNT(DISTINCT asset_id) AS asset_count,
                MIN(value_text) FILTER (WHERE value_text IS NOT NULL) AS sample_value
            FROM asset_card_search_fields
            {where}
            GROUP BY field_path, value_type
            ORDER BY field_path, value_type
            LIMIT %s
            """,
            [*params, limit],
        ).fetchall()
    return {"rows": rows_to_dicts(rows), **asset_card_search_index_coverage()}


def collect_asset_query_rules(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    if node.get("field_path"):
        return [node]
    result: list[dict[str, Any]] = []
    for child in node.get("rules") or []:
        result.extend(collect_asset_query_rules(child))
    return result


def validate_asset_query_tree(node: Any, *, depth: int = 0, parent_scope: str | None = None) -> int:
    if not isinstance(node, dict):
        raise ValueError("Query node must be an object.")
    if depth > 3:
        raise ValueError("Query groups may not be nested deeper than 3 levels.")
    if node.get("field_path"):
        if not str(node.get("operator") or ""):
            raise ValueError("Every field rule requires an operator.")
        return 1
    combinator = str(node.get("combinator") or "and").lower()
    scope = str(node.get("match_scope") or "host").lower()
    if combinator not in {"and", "or"} or scope not in {"host", "same_entity"}:
        raise ValueError("Unsupported query group combinator or match_scope.")
    if parent_scope == "same_entity" and scope == "host":
        raise ValueError("A host-scoped group cannot be nested inside same_entity.")
    rules = node.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Every query group must contain at least one rule.")
    count = sum(validate_asset_query_tree(child, depth=depth + 1, parent_scope=scope) for child in rules)
    if count > 20:
        raise ValueError("A query may contain at most 20 field rules.")
    if scope == "same_entity" and any(
        str(rule.get("operator") or "") == "not_exists" for rule in collect_asset_query_rules(node)
    ):
        raise ValueError("not_exists is only supported for host-scoped groups.")
    return count


def compile_asset_query_rule(rule: dict[str, Any]) -> tuple[str, list[Any], str]:
    field_path = str(rule.get("field_path") or "").strip()
    operator = str(rule.get("operator") or "").lower()
    value = rule.get("value")
    if not field_path:
        raise ValueError("field_path is required.")
    if operator == "not_exists":
        return (
            "SELECT card.asset_id, NULL::text AS entity_path FROM asset_cards card "
            "WHERE NOT EXISTS (SELECT 1 FROM asset_card_search_fields field WHERE field.asset_id = card.asset_id AND field.field_path = %s)",
            [field_path],
            "host",
        )
    base = "SELECT asset_id, entity_path FROM asset_card_search_fields WHERE field_path = %s"
    params: list[Any] = [field_path]
    if operator == "exists":
        return base, params, "entity"
    if operator in ASSET_QUERY_TEXT_OPERATORS:
        if operator == "in":
            values = value if isinstance(value, list) else [item.strip() for item in str(value or "").split(",") if item.strip()]
            if not values:
                raise ValueError("in requires at least one value.")
            placeholders = ", ".join(["%s"] * len(values))
            return f"{base} AND value_text_normalized IN ({placeholders})", [*params, *[str(item).lower() for item in values]], "entity"
        normalized = str(value or "").lower()
        expression = {
            "equals": "value_text_normalized = %s",
            "not_equals": "value_text_normalized <> %s",
            "contains": "value_text_normalized LIKE %s",
            "starts_with": "value_text_normalized LIKE %s",
        }[operator]
        if operator == "contains":
            normalized = f"%{normalized}%"
        elif operator == "starts_with":
            normalized = f"{normalized}%"
        return f"{base} AND {expression}", [*params, normalized], "entity"
    if operator in ASSET_QUERY_NUMBER_OPERATORS:
        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{operator} requires a numeric value.") from exc
        expression = {"equals": "=", "not_equals": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[operator]
        return f"{base} AND value_number {expression} %s", [*params, numeric], "entity"
    if operator in ASSET_QUERY_BOOLEAN_OPERATORS:
        return f"{base} AND value_boolean = %s", [*params, operator == "is_true"], "entity"
    raise ValueError(f"Unsupported asset query operator: {operator}")


def compile_asset_query_node(node: dict[str, Any]) -> tuple[str, list[Any], str]:
    if node.get("field_path"):
        return compile_asset_query_rule(node)
    scope = str(node.get("match_scope") or "host").lower()
    combinator = str(node.get("combinator") or "and").lower()
    child_parts: list[str] = []
    params: list[Any] = []
    for child in node.get("rules") or []:
        child_sql, child_params, child_scope = compile_asset_query_node(child)
        if scope == "host":
            child_sql = f"SELECT DISTINCT asset_id, NULL::text AS entity_path FROM ({child_sql}) child"
        elif child_scope == "host":
            raise ValueError("Host-scoped rules cannot be correlated inside same_entity.")
        child_parts.append(f"SELECT asset_id, entity_path FROM ({child_sql}) grouped_child")
        params.extend(child_params)
    joiner = " INTERSECT " if combinator == "and" else " UNION "
    return joiner.join(child_parts), params, scope


ASSET_QUERY_SORT_COLUMNS = {
    "display_name": "LOWER(card.display_name)",
    "ip_address": "LOWER(card.ip_address)",
    "fqdn": "LOWER(card.fqdn)",
    "os_name": "LOWER(card.os_name)",
    "asset_type": "LOWER(card.asset_type)",
    "last_seen": "card.last_seen",
    "vulnerability_level": "LOWER(card.vulnerability_level)",
}


def query_asset_cards_by_fields(
    query: dict[str, Any],
    *,
    sort_by: str = "display_name",
    sort_dir: str = "asc",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    validate_asset_query_tree(query)
    matched_sql, params, _scope = compile_asset_query_node(query)
    sort_expression = ASSET_QUERY_SORT_COLUMNS.get(sort_by)
    if not sort_expression:
        raise ValueError(f"Unsupported asset query sort column: {sort_by}")
    direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    limit = max(1, min(50000, int(limit)))
    offset = max(0, int(offset))
    matched_cte = f"WITH matched_pairs AS ({matched_sql}), matched AS (SELECT DISTINCT asset_id FROM matched_pairs)"
    with connect() as conn:
        total = conn.execute(f"{matched_cte} SELECT COUNT(*) AS count FROM matched", params).fetchone()["count"]
        cards = conn.execute(
            f"""
            {matched_cte}
            SELECT card.id, card.asset_id, card.display_name, card.asset_type, card.fqdn,
                   card.hostname, card.ip_address, card.os_name, card.os_version,
                   card.vulnerability_level, card.token_timestamp, card.stats_json,
                   card.first_seen, card.last_seen
            FROM matched JOIN asset_cards card ON card.asset_id = matched.asset_id
            ORDER BY {sort_expression} {direction} NULLS LAST, card.asset_id ASC
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
        asset_ids = [row["asset_id"] for row in cards]
        rules = collect_asset_query_rules(query)
        field_paths = list(dict.fromkeys(str(rule.get("field_path")) for rule in rules if rule.get("field_path") and rule.get("operator") != "not_exists"))
        evidence_rows = []
        if asset_ids and field_paths:
            evidence_rows = conn.execute(
                """
                SELECT asset_id, entity_path, field_path, field_name, value_type,
                       value_text, value_number, value_boolean
                FROM asset_card_search_fields
                WHERE asset_id = ANY(%s) AND field_path = ANY(%s)
                ORDER BY asset_id, entity_path, field_path, id
                """,
                (asset_ids, field_paths),
            ).fetchall()
    evidence_by_asset: dict[str, list[dict[str, Any]]] = {asset_id: [] for asset_id in asset_ids}
    for raw in evidence_rows:
        item = dict(raw)
        matching_rules = [rule for rule in rules if rule.get("field_path") == item["field_path"]]
        if not any(asset_query_evidence_matches(item, rule) for rule in matching_rules):
            continue
        item["value"] = first_non_empty(item.get("value_text"), item.get("value_number"), item.get("value_boolean"))
        evidence_by_asset[item["asset_id"]].append(item)
    decoded = []
    for card in cards:
        summary = decode_asset_card_summary(dict(card))
        summary["matches"] = evidence_by_asset.get(card["asset_id"], [])[:50]
        decoded.append(summary)
    return {"total": int(total or 0), "rows": decoded, "limit": limit, "offset": offset, **asset_card_search_index_coverage()}


def asset_query_evidence_matches(field: dict[str, Any], rule: dict[str, Any]) -> bool:
    operator = str(rule.get("operator") or "").lower()
    if operator in {"exists", "not_exists"}:
        return operator == "exists"
    value = rule.get("value")
    if operator in ASSET_QUERY_BOOLEAN_OPERATORS:
        return bool(field.get("value_boolean")) is (operator == "is_true")
    if operator in ASSET_QUERY_NUMBER_OPERATORS:
        try:
            left, right = float(field.get("value_number")), float(value)
        except (TypeError, ValueError):
            return False
        return {"equals": left == right, "not_equals": left != right, "gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[operator]
    left = str(field.get("value_text_normalized") or field.get("value_text") or "").lower()
    if operator == "in":
        values = value if isinstance(value, list) else [item.strip() for item in str(value or "").split(",")]
        return left in {str(item).lower() for item in values}
    right = str(value or "").lower()
    return {"equals": left == right, "not_equals": left != right, "contains": right in left, "starts_with": left.startswith(right)}.get(operator, False)


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


def decode_operation(row: dict[str, Any]) -> dict[str, Any]:
    status = str(row.get("status") or "unknown")
    kind = str(row.get("kind") or "unknown")
    return {
        "operation_id": row.get("operation_id"),
        "kind": kind,
        "source_id": row.get("source_id"),
        "status": status,
        "stage": row.get("stage"),
        "progress_percent": max(0, min(100, int(row.get("progress_percent") or 0))),
        "subject": {
            "type": row.get("subject_type"),
            "id": row.get("subject_id"),
            "label": row.get("subject_label"),
        },
        "message": row.get("message"),
        "error": json_loads(row.get("error_json"), {}),
        "request": json_loads(row.get("request_json"), {}),
        "result": json_loads(row.get("result_json"), {}),
        "trace_id": row.get("trace_id"),
        "retry_of": row.get("retry_of"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
        "can_cancel": status in ACTIVE_OPERATION_STATUSES and kind in {"asset_card_build", "passport_detail_sync"},
        "can_retry": status not in ACTIVE_OPERATION_STATUSES and kind in RETRYABLE_OPERATION_KINDS,
    }


def decode_operation_event(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "message": row.get("message"),
        "details": json_loads(row.get("details_json"), {}),
        "created_at": row.get("created_at"),
    }


def decode_saved_view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "route": row.get("route"),
        "name": row.get("name"),
        "filters": json_loads(row.get("filters_json"), {}),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
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
