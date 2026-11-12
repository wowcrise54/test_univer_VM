"""Idempotent baseline schema and application-level ``init_db``.

The baseline DDL is shared with Alembic (the baseline migration imports
:func:`schema_statements` from the ``app.db`` facade), so its content must
not change when it moves."""

from __future__ import annotations

import threading
from pathlib import Path

import psycopg

from .circuit_breaker import _close_database_circuit, _open_database_circuit, _raise_if_database_circuit_open
from .passport_cve_schema import SCHEMA_SQL as PASSPORT_CVE_SQL
from .risk_evidence_schema import EVIDENCE_COLUMNS_SQL, FUNCTIONS_SQL

_DB_INITIALIZED = False

_DB_INIT_LOCK = threading.Lock()

def init_db() -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    _raise_if_database_circuit_open()
    with _DB_INIT_LOCK:
        if _DB_INITIALIZED:
            return
        _raise_if_database_circuit_open()
        try:
            _initialize_schema()
        except Exception as exc:
            _open_database_circuit(exc)
            raise psycopg.OperationalError(str(exc)) from exc
        _close_database_circuit()
        _DB_INITIALIZED = True

def schema_statements() -> list[str]:
    """Return the idempotent baseline schema used by Alembic and legacy startup."""

    return [
        *FUNCTIONS_SQL,
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
            detail_updated_at TEXT,
            """ + EVIDENCE_COLUMNS_SQL + """
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS vulnerability_passport_trends (
            passport_internal_id TEXT PRIMARY KEY
                REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
            description TEXT,
            is_trend_since TEXT,
            vendors_json TEXT NOT NULL DEFAULT '[]',
            affected_components_json TEXT NOT NULL DEFAULT '[]',
            source_pdql TEXT NOT NULL,
            pdql_token TEXT,
            synced_at TEXT NOT NULL
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
            cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
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
        CREATE TABLE IF NOT EXISTS asset_card_history (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            captured_at TEXT NOT NULL,
            quality_json TEXT NOT NULL DEFAULT '{}',
            changes_json TEXT NOT NULL DEFAULT '[]',
            summary_json TEXT NOT NULL DEFAULT '{}'
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
        CREATE TABLE IF NOT EXISTS asset_groups (
            group_id UUID PRIMARY KEY,
            parent_id UUID REFERENCES asset_groups(group_id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            query_json TEXT NOT NULL,
            definition_version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'stale',
            member_count INTEGER NOT NULL DEFAULT 0,
            indexed_cards INTEGER NOT NULL DEFAULT 0,
            total_cards INTEGER NOT NULL DEFAULT 0,
            last_evaluated_at TIMESTAMPTZ,
            last_error TEXT,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_group_evaluations (
            evaluation_id UUID PRIMARY KEY,
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            definition_version INTEGER NOT NULL,
            status TEXT NOT NULL,
            matched_count INTEGER NOT NULL DEFAULT 0,
            indexed_cards INTEGER NOT NULL DEFAULT 0,
            total_cards INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_scan_evidence (
            asset_id TEXT PRIMARY KEY REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            postprocess_run_id TEXT NOT NULL,
            mp_task_id TEXT NOT NULL,
            scanned_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_auth_sessions (
            id UUID PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_permissions (
            permission_key TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            action TEXT NOT NULL,
            description TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_roles (
            id BIGSERIAL PRIMARY KEY,
            role_key TEXT UNIQUE,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            is_system BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_role_permissions (
            role_id BIGINT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
            permission_key TEXT NOT NULL REFERENCES app_permissions(permission_key) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_key)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_user_roles (
            user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            role_id BIGINT NOT NULL REFERENCES app_roles(id) ON DELETE RESTRICT,
            PRIMARY KEY (user_id, role_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_auth_identities (
            id BIGSERIAL PRIMARY KEY,
            provider TEXT NOT NULL,
            subject TEXT NOT NULL,
            user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            UNIQUE (provider, subject)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_auth_audit_events (
            id BIGSERIAL PRIMARY KEY,
            actor_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
            actor_username TEXT,
            event_type TEXT NOT NULL,
            permission_key TEXT,
            decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
            target_type TEXT,
            target_id TEXT,
            ip_address TEXT,
            user_agent TEXT,
            trace_id TEXT,
            request_id TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
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
        *PASSPORT_CVE_SQL,
        """
        CREATE TABLE IF NOT EXISTS asset_card_search_field_catalog (
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            field_path TEXT NOT NULL,
            value_type TEXT NOT NULL,
            field_name TEXT NOT NULL,
            sample_value TEXT,
            PRIMARY KEY (asset_id, field_path, value_type)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_card_software_inventory (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            entity_path TEXT NOT NULL,
            soft_name TEXT NOT NULL,
            soft_name_normalized TEXT NOT NULL,
            soft_version TEXT NOT NULL DEFAULT '',
            soft_version_normalized TEXT NOT NULL DEFAULT '',
            vendor TEXT,
            architecture TEXT,
            install_path TEXT,
            is_windows BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, entity_path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_group_members (
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            evaluation_id UUID NOT NULL REFERENCES asset_group_evaluations(evaluation_id) ON DELETE CASCADE,
            membership_source TEXT NOT NULL DEFAULT 'rule',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (group_id, asset_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS asset_group_overrides (
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            action TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (group_id, asset_id)
        )
        """,
        "ALTER TABLE asset_cards ADD COLUMN IF NOT EXISTS vulnerabilities_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE asset_cards ADD COLUMN IF NOT EXISTS software_inventory_updated_at TEXT",
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
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passport_trends_since ON vulnerability_passport_trends(is_trend_since DESC, passport_internal_id)",
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_passport_detail_jobs_created ON vulnerability_passport_detail_jobs(created_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerability_passport_detail_jobs_single_active ON vulnerability_passport_detail_jobs ((1)) WHERE status IN ('queued', 'running', 'cancelling')",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_build_jobs_created ON asset_card_build_jobs(created_at DESC)",
        "DROP INDEX IF EXISTS idx_asset_card_build_jobs_single_active",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_build_jobs_active ON asset_card_build_jobs(status, asset_id) WHERE status IN ('queued', 'running', 'cancelling')",
        "CREATE INDEX IF NOT EXISTS idx_operations_status_created ON operations(status, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_operations_kind_created ON operations(kind, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_operations_updated ON operations(updated_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_operations_idempotency ON operations(idempotency_key) WHERE idempotency_key IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_operation_events_operation_created ON operation_events(operation_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_app_auth_sessions_user ON app_auth_sessions(user_id, expires_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_app_auth_sessions_token ON app_auth_sessions(token_hash) WHERE revoked_at IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_app_auth_audit_created ON app_auth_audit_events(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_app_auth_audit_actor ON app_auth_audit_events(actor_user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_saved_views_route_name ON saved_views(route, name)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_groups_parent_name ON asset_groups(COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), LOWER(name)) WHERE archived_at IS NULL",
        "CREATE INDEX IF NOT EXISTS idx_asset_group_members_asset ON asset_group_members(asset_id, group_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_group_evaluations_group_started ON asset_group_evaluations(group_id, started_at DESC)",
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
        # Text values may be several kilobytes long and cannot safely be stored
        # as B-tree keys.  Keep the full value in the table for collision-safe
        # comparisons and index its fixed-size digest for equality lookups.
        "DROP INDEX IF EXISTS idx_asset_search_path_text",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_text_hash ON asset_card_search_fields(field_path, md5(value_text_normalized), asset_id) WHERE value_type = 'text'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_number ON asset_card_search_fields(field_path, value_number, asset_id) WHERE value_type = 'number'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_path_boolean ON asset_card_search_fields(field_path, value_boolean, asset_id) WHERE value_type = 'boolean'",
        "CREATE INDEX IF NOT EXISTS idx_asset_search_entity ON asset_card_search_fields(asset_id, entity_path, field_path)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_software_name_version ON asset_card_software_inventory(is_windows, soft_name_normalized, soft_version_normalized, asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_software_name ON asset_card_software_inventory(soft_name_normalized, asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_software_name_version_prefix ON asset_card_software_inventory(is_windows, soft_name_normalized, soft_version_normalized text_pattern_ops, asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_software_asset ON asset_card_software_inventory(asset_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_groups_asset_source ON asset_card_vulnerability_groups(asset_id, source_type, group_order)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_asset_cve ON asset_card_vulnerabilities(asset_id, cve_name)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_group_order ON asset_card_vulnerabilities(group_id, cve_name, name, id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_vulnerability_id ON asset_card_vulnerabilities(vulnerability_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_asset_vulnerability_id ON asset_card_vulnerabilities(asset_id, vulnerability_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_cve_upper ON asset_card_vulnerabilities((UPPER(TRIM(cve_name))))",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_severity_lower ON asset_card_vulnerabilities((CASE WHEN LOWER(TRIM(COALESCE(severity, ''))) IN ('critical', 'high', 'medium', 'low') THEN LOWER(TRIM(severity)) ELSE 'unknown' END))",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_groups_source ON asset_card_vulnerability_groups(source_type)",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_last_seen ON asset_cards(last_seen DESC)",
        "CREATE INDEX IF NOT EXISTS idx_asset_scan_evidence_scanned_at ON asset_scan_evidence(scanned_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_passports_passport ON asset_card_vulnerability_passports(passport_internal_id)",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_passports_finding ON asset_card_vulnerability_passports(asset_vulnerability_id, passport_internal_id)",
    ]

def _initialize_schema() -> None:
    from alembic import command
    from alembic.config import Config

    root_dir = Path(__file__).resolve().parents[2]
    config = Config(str(root_dir / "alembic.ini"))
    config.set_main_option("script_location", str(root_dir / "migrations"))
    command.upgrade(config, "head")
