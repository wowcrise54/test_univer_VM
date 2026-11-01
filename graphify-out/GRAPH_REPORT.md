# Graph Report - main-wt  (2026-10-31)

## Corpus Check
- 300 files · ~281,554 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 38 file(s) not represented in the graph (top: .css 14, .toml 10, (none) 8)

## Summary
- 4722 nodes · 13577 edges · 187 communities (135 shown, 52 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 1098 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `61568463`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- FakeSession
- mp10_export_VM_info.py
- panels.jsx
- DomainError
- Any
- VulnerabilitiesDashboard.jsx
- build_docker_vulnerability_source
- FakeRepository
- app/auth.py
- test_security_administration_db.py
- init_db
- VmWorkflowService
- audit_event
- api
- StepEditor.jsx
- api/risk.py
- AttentionRepository
- AutomationRepository
- environment
- mpvm_client.py
- mpvm-rest-client
- MpVmClient
- connect
- e2e
- test_automation_boundaries.py
- refresh_asset_card_by_scan
- TaskWorkspace.jsx
- RepositoryBundle
- test_task_presets_db.py
- api/remediation.py
- AutomationService
- App.jsx
- .capture_snapshot
- run_scan_postprocess
- AssetQueryPage.jsx
- query_asset_cards_by_fields
- AssetCardBatchJobApiTests
- schemas.py
- DatabaseRecovery
- Any
- test_vulnerability_reports.py
- AssetCardDatabaseTests
- ScriptedConnection
- repositories/vulnerabilities.py
- test_mpvm_transport.py
- VmWorkflowRepository
- test_risk_management_db.py
- datetime
- vulnerability_hosts
- log_event
- VmManagementPage.jsx
- useTaskForm.js
- FakeConnection
- build_asset_card
- VulnerabilityAnalyticsRepository
- authorization.py
- db.py
- VulnerabilityAnalyticsService
- MP VM REST API Client
- test_asset_card_jobs.py
- RemediationRepository
- test_diagnostic_transactions_db.py
- AssetCardRequestExecutor
- export_vulnerability_xlsx
- ScanPostprocessClientTests
- build_template_draft
- register_operation
- MpVmApiError
- quality
- startup
- OperationsPage.jsx
- vulnerability_passport_detail_refresh_candidates
- scripts
- OperationRunner
- reports/compliance.py
- shell.spec.js
- test_security_administration_db.py
- monitor_successful_scan_jobs
- test_directory_boundaries.py
- test_task_presets.py
- Python Runtime Dependencies
- package.json
- VulnerabilityReportTests
- test_http_service_contracts.py
- VulnerabilityApiContractTests
- MP VM REST Client Container
- Settings
- test_team_tasks.py
- AssetGroupService
- ConnectionTokenTests
- Settings
- test_vm_workflows.py
- schema_statements
- api/compliance.py
- test_auth.py
- TeamTasksPage.jsx
- ContractTests
- app/__init__.py
- Архитектура MP VM Client
- AssetGroupsPage.jsx
- resolve_scanned_target_once
- api/team_tasks.py
- is_finished
- Основные потоки
- test_vulnerability_asset_selection_db.py
- test_search_user_copies_entries_before_unbind
- api/task_presets.py
- ComplianceReportRequest
- VmPreflightBlocked
- env.py
- workflow_service
- json
- test_auth_ldap_db.py
- test_vm_workflow_idempotency_db.py
- DatabaseRecovery
- VulnerabilityTrendApiTests
- api/asset_groups.py
- AssetCardSearchIndexTests
- diagnostics.py
- psycopg
- test_vm_workflow_boundaries.py
- test_auth_ldap.py
- ScannerTaskFolderRepository
- TaskPresetRepository
- План развития MP VM Client до MVP
- test_api_contracts_db.py
- Архитектура системы MP VM Client
- sync_trending_vulnerability_passports
- Руководство оператора MP VM Client
- test_rbac_matrix_db.py
- services/team_tasks.py
- vm.py
- http_services
- routers.py
- test_start_failure_does_not_overwrite_concurrent_terminal_cancellation
- ARCHITECTURE.md
- Дашборды и отчеты по критическим уязвимостям
- Переработка вкладки задач
- Пресеты задач для инженеров
- Разработка и развёртывание
- PassportDetailWorkerTests
- MP VM Client — инструкции агенту
- test_attention_compliance_db.py
- Исправления корректности — 2026-10-01
- Q: Почему MpVmClient соединяет 13 функциональных сообществ проекта?
- Q: Собери информацию обо всех трассах MpVmClient
- Q: При клике на задачу увидеть её результаты: для precheck успешные и неуспешные проверки, для обычной задачи успешность сканирования, всё в отдельном окне.
- Q: Уточнение UI результатов задач по примерам MP VM jobs для обычного скана и precheck.
- Q: Можно ли удалить вкладку Активы и использовать Уязвимости, Карточки активов и Группы активов?
- Q: Удалить вкладку Активы, оставить Уязвимости, Карточки активов и Группы активов, перенаправлять /assets.
- FakeResult
- collect-container-logs.sh
- routers.py
- test_catalog_cancellation_never_submits_queued_detail_work
- _fake_connect
- Этап 2. Данные и восстановление

## God Nodes (most connected - your core abstractions)
1. `connect()` - 299 edges
2. `MpVmClient` - 127 edges
3. `now_utc()` - 116 edges
4. `MpVmApiError` - 105 edges
5. `api()` - 91 edges
6. `init_db()` - 78 edges
7. `Button()` - 71 edges
8. `VmWorkflowService` - 65 edges
9. `AutomationRepository` - 56 edges
10. `AutomationService` - 49 edges

## Surprising Connections (you probably didn't know these)
- `Правила расширения` --references--> `OperationRunner`  [INFERRED]
  docs/ARCHITECTURE.md → app/core/runtime.py
- `Фоновые задачи и долговечность` --references--> `OperationRunner`  [INFERRED]
  docs/system-architecture.md → app/core/runtime.py
- `PostgreSQL` --references--> `init_db()`  [INFERRED]
  docs/system-architecture.md → app/db.py
- `3. Построение карточки актива` --references--> `AssetCardRequestExecutor`  [INFERRED]
  docs/system-architecture.md → app/main.py
- `MP VM недоступна или сессия отсутствует` --references--> `require_mpvm()`  [INFERRED]
  docs/system-architecture.md → app/main.py

## Import Cycles
- 3-file cycle: `app/services/__init__.py -> app/services/bundle.py -> app/services/task_presets.py -> app/services/__init__.py`
- 4-file cycle: `app/services/__init__.py -> app/services/bundle.py -> app/services/team_tasks.py -> app/services/task_presets.py -> app/services/__init__.py`

## Hyperedges (group relationships)
- **Quality-Verified Layered Architecture** — github_workflows_quality_quality_gate, docs_architecture_application_architecture, requirements_dev_development_dependencies [INFERRED 0.85]
- **Persistent VM Workflow System** — readme_vm_workflow_orchestration, readme_remediation_lifecycle, readme_operations_center, docs_architecture_vm_workflow_vertical_slice [INFERRED 0.95]

## Communities (187 total, 52 thin omitted)

### Community 0 - "FakeSession"
Cohesion: 0.04
Nodes (9): __init__(), __init__(), __init__(), __init__(), __init__(), FakeSession, __init__(), StartScannerTaskApiTests (+1 more)

### Community 1 - "mp10_export_VM_info.py"
Cohesion: 0.07
Nodes (60): as_dict_list(), asset_id_from_csv_row(), AuthConfig, build_default_token_url(), build_disabled_daily_trigger(), build_export_output_path(), build_filtered_pdql(), build_scanner_task() (+52 more)

### Community 2 - "panels.jsx"
Cohesion: 0.04
Nodes (131): AssetCardsPage(), AssetsPage(), PassportsPage(), ACTIVE_ASSET_CARD_JOB_STATUSES, ACTIVE_BULK_REFRESH_STATUSES, ACTIVE_PASSPORT_JOB_STATUSES, ACTIVE_SCAN_POSTPROCESS_STATUSES, ASSET_DEFAULT_FILTERS (+123 more)

### Community 3 - "DomainError"
Cohesion: 0.15
Nodes (5): DomainError, _Slot, TeamTasksService, test_domain_error_preserves_human_message_and_independent_contexts(), test_foreign_task_is_not_found_for_every_action()

### Community 4 - "Any"
Cohesion: 0.04
Nodes (139): AssetCardPresetQueryRequest, AutomationRunbookRequest, AutomationScheduleRequest, DeleteScannerTaskRequest, VulnerabilityPassportQueryRequest, active_asset_card_build_job(), active_vulnerability_passport_detail_job(), asset_card_build_job() (+131 more)

### Community 5 - "VulnerabilitiesDashboard.jsx"
Cohesion: 0.09
Nodes (71): barWidth(), cardLabel(), DashboardContext(), DEFAULT_HOST_SORT, DEFAULT_VULNERABILITY_SORT, EMPTY_FILTERS, EmptyState(), filterSeverity() (+63 more)

### Community 6 - "build_docker_vulnerability_source"
Cohesion: 0.06
Nodes (48): remote_call(), timed_vulnerabilities(), build_asset_vulnerability_snapshot(), load_group(), build_docker_vulnerability_source(), clean_text(), _docker_container_key(), _docker_container_label() (+40 more)

### Community 7 - "FakeRepository"
Cohesion: 0.07
Nodes (7): test_invalid_cron_expression_returns_actionable_error(), DefinitionTests, handler(), FakeRepository, SchedulerTests, service(), WebhookTests

### Community 8 - "app/auth.py"
Cohesion: 0.14
Nodes (23): cleanup_audit_events(), create_session(), ensure_bootstrap_admin(), get_session_user(), hash_password(), _iso(), _ldap_default_role_row(), list_audit_events() (+15 more)

### Community 9 - "test_security_administration_db.py"
Cohesion: 0.20
Nodes (24): authenticate(), delete_user(), list_users(), update_user(), UserUpdateRequest, auth_update_user(), create(), error_code() (+16 more)

### Community 10 - "init_db"
Cohesion: 0.08
Nodes (34): create_vulnerability_passport_detail_job(), _credential_id_from_payload(), _decode_scan_task(), decode_vulnerability_passport(), decode_vulnerability_passport_detail_job(), finish_vulnerability_passport_detail_job(), get_active_vulnerability_passport_detail_job(), get_asset_card_refresh_template() (+26 more)

### Community 11 - "VmWorkflowService"
Cohesion: 0.15
Nodes (9): VmWorkflowService, test_campaign_finalization_uses_operation_subject_and_start_error_asset_ids(), test_group_scan_reconcile_step_is_skipped_after_postprocess(), test_monitor_reports_child_progress_then_reconciles_terminal_operations(), test_reconciliation_error_is_isolated_and_workflow_completes_with_errors(), test_resume_monitors_workflow_with_persisted_child_operation_ids(), test_retry_group_verification_does_not_require_campaign_id(), test_retry_reconciliation_reuses_child_results_and_only_reschedules_monitor() (+1 more)

### Community 13 - "audit_event"
Cohesion: 0.14
Nodes (15): audit_event(), delete_role(), login(), LoginLimiter, LoginRequest, logout(), application_auth_middleware(), auth_delete_role() (+7 more)

### Community 14 - "api"
Cohesion: 0.04
Nodes (78): @tanstack/react-query, @testing-library/react, vitest, ACCESS_CHANGE_CODES, ACCESS_CHANGED_EVENT, notifyAccessChangedIfNeeded(), api(), downloadApiFile() (+70 more)

### Community 15 - "StepEditor.jsx"
Cohesion: 0.14
Nodes (26): AssetQueryStepConfig(), AutomationStepEditor(), automationStepFromApi(), automationStepToApi(), clone(), collectQueryRules(), compactConfig(), CONDITION_OPERATORS (+18 more)

### Community 16 - "api/risk.py"
Cohesion: 0.09
Nodes (32): actor(), CampaignCreate, CampaignUpdate, ContextCsvImport, ContextUpdate, ContextValues, create_campaign(), get_campaign() (+24 more)

### Community 17 - "AttentionRepository"
Cohesion: 0.17
Nodes (12): AttentionRepository, decode_cursor(), encode_cursor(), _iso(), AttentionService, test_attention_owner_and_filters_are_applied_before_pagination(), test_search_paginated_order_and_explicit_kind(), test_attention_filters_before_pagination() (+4 more)

### Community 18 - "AutomationRepository"
Cohesion: 0.14
Nodes (19): AutomationRepository, _dump(), _load(), _rows(), _definition(), _published_runbook(), test_automation_replay_key_cannot_silently_reuse_a_different_request(), test_deleting_a_runbook_cascades_versions_schedules_runs_steps_and_audit() (+11 more)

### Community 19 - "environment"
Cohesion: 0.05
Nodes (42): postgres, path, required, MPVM_ASSET_CARD_REFRESH_WORKERS, MPVM_ASSET_CARD_REQUEST_WORKERS, MPVM_BACKGROUND_REQUEST_LIMIT, MPVM_DATABASE_URL, MPVM_DOCKER_DYNAMIC_GROUP_ITERATIONS (+34 more)

### Community 20 - "mpvm_client.py"
Cohesion: 0.10
Nodes (33): chunks(), remove_assets_after_export(), resolve_asset_ids_by_ips(), asset_id_from_csv_row(), build_asset_id_pdql_for_ips(), build_asset_resolution_pdql(), build_credential_overrides(), build_disabled_daily_trigger() (+25 more)

### Community 21 - "mpvm-rest-client"
Cohesion: 0.05
Nodes (40): postgres, path, required, MPVM_API_URL, MPVM_CLIENT_ID, MPVM_DATABASE_URL, MPVM_EXPORTS_DIR, MPVM_INSECURE (+32 more)

### Community 22 - "MpVmClient"
Cohesion: 0.12
Nodes (12): build_precheck_task_name(), prepare_docker_dynamic_group_for_scan(), remove_docker_dynamic_group(), run_false_targets_precheck(), run_precheck_for_scanner_task(), start_scanner_task_impl(), is_scanner_task_not_found(), is_scanner_task_not_found_response() (+4 more)

### Community 23 - "connect"
Cohesion: 0.05
Nodes (62): archive_local_asset_group(), asset_card_exists(), _AssetCardBuildAdmissionConflict, _close_database_circuit(), connect(), create_asset_card_build_jobs(), create_scan_postprocess_run(), database_circuit_status() (+54 more)

### Community 24 - "e2e"
Cohesion: 0.06
Nodes (38): context, dockerfile, target, test-postgres, build, environment, network_mode, profiles (+30 more)

### Community 25 - "test_automation_boundaries.py"
Cohesion: 0.13
Nodes (9): automation(), test_asset_card_batch_parallelism_rejects_out_of_range_values(), test_conditions_compare_nested_saved_step_outputs(), test_invalid_definitions_are_rejected_before_persistence(), test_missed_schedule_advances_without_recreating_a_recorded_skip(), test_persisted_step_decoding_handles_legacy_native_json_and_damaged_payloads(), test_resume_keeps_completed_outputs_and_evaluates_following_conditions(), test_runbook_updates_audit_only_existing_records() (+1 more)

### Community 26 - "refresh_asset_card_by_scan"
Cohesion: 0.07
Nodes (28): StartScannerTaskRequest, AutomationStepCancelled, get_operation_by_idempotency_key(), build_asset_refresh_task_payload(), docker_scan_group_name(), execute_automation_step(), normalize_remote_scanner_task_template(), refresh_asset_card_batch() (+20 more)

### Community 27 - "TaskWorkspace.jsx"
Cohesion: 0.09
Nodes (30): connectionChecks(), displayTargets(), displayText(), FolderButton(), formatCheckErrors(), formatDate(), formatDuration(), objectRecords() (+22 more)

### Community 28 - "RepositoryBundle"
Cohesion: 0.12
Nodes (7): RepositoryBundle, AssetCardsService, AssetQueryService, AssetsService, OperationsService, PassportsService, TasksService

### Community 29 - "test_task_presets_db.py"
Cohesion: 0.25
Nodes (7): _engineer(), _role_id(), test_engineer_roles_are_seeded_with_team_permissions(), test_ip_and_fqdn_targets_round_trip(), test_preset_crud_versioning_and_role_scoping(), test_team_tasks_are_scoped_by_preset_roles(), _values()

### Community 30 - "api/remediation.py"
Cohesion: 0.16
Nodes (18): bulk_update(), BulkCaseUpdate, CaseUpdate, coverage_assets(), coverage_summary(), get_case(), list_cases(), policy() (+10 more)

### Community 31 - "AutomationService"
Cohesion: 0.16
Nodes (3): AutomationService, test_conditions_can_compare_the_entire_saved_output(), test_valid_definition_normalizes_nonobject_config_condition_and_batch_parallelism()

### Community 32 - "App.jsx"
Cohesion: 0.06
Nodes (53): react, ActivePage(), App(), AppShell(), AuthenticatedApp(), canAccessRoute(), AppDataContext, AppDataProvider() (+45 more)

### Community 33 - ".capture_snapshot"
Cohesion: 0.15
Nodes (4): database_snapshot_rows(), FakeConnection, FakeResult, SnapshotRepositoryTests

### Community 34 - "run_scan_postprocess"
Cohesion: 0.09
Nodes (32): claim_scan_postprocess_run(), decode_scan_postprocess_run(), delete_scan_task(), finish_scan_postprocess_run(), get_active_asset_card_refresh(), get_latest_scan_postprocess_run(), get_scan_postprocess_run(), list_pending_asset_refresh_task_cleanups() (+24 more)

### Community 35 - "AssetQueryPage.jsx"
Cohesion: 0.15
Nodes (27): AssetQueryPage(), contentDispositionFilename(), countRules(), DEFAULT_SORT, EMPTY_GROUP(), EMPTY_RULE(), formatDate(), friendlyFieldName() (+19 more)

### Community 36 - "query_asset_cards_by_fields"
Cohesion: 0.07
Nodes (25): asset_query_evidence_matches(), collect_asset_query_rules(), create_local_asset_group(), decode_asset_card_summary(), decode_asset_group(), evaluate_local_asset_group(), get_asset_group(), get_summary() (+17 more)

### Community 38 - "schemas.py"
Cohesion: 0.10
Nodes (26): AssetCardAssetQueryRequest, AssetCardBuildBatchJobRequest, AssetCardBuildJobRequest, AssetCardBuildRequest, AssetCardBulkRefreshRequest, AssetCardFieldQueryRequest, AssetCardRefreshScanRequest, AssetCardUpdateRequest (+18 more)

### Community 40 - "Any"
Cohesion: 0.17
Nodes (9): as_dict_list(), build_default_token_url(), compact_json_summary(), ensure_items(), ensure_list(), MpVmApiError, test_credentials_in_the_api_url_are_rejected_and_compact_details_redact_secrets(), test_timeline_token_and_invalid_json_contract() (+1 more)

### Community 41 - "test_vulnerability_reports.py"
Cohesion: 0.23
Nodes (5): csv_dict_reader(), _common(), render_vulnerability_xlsx(), _safe_cell(), _write_sheet()

### Community 42 - "AssetCardDatabaseTests"
Cohesion: 0.12
Nodes (6): canonical_asset_card_id(), create_asset_card_build_job(), _direct_child_filter_sql(), get_asset_card_section(), get_asset_card_summary(), AssetCardDatabaseTests

### Community 43 - "ScriptedConnection"
Cohesion: 0.11
Nodes (3): OperationsApiTests, QueryResult, ScriptedConnection

### Community 44 - "repositories/vulnerabilities.py"
Cohesion: 0.23
Nodes (13): _attach_fix_text(), _decode_host(), _decode_snapshot_rows(), _decode_trending_passport(), _decode_vulnerability(), _fix_rollup_cte(), _fix_text_query(), _has_fix_exists_sql() (+5 more)

### Community 45 - "test_mpvm_transport.py"
Cohesion: 0.13
Nodes (12): build_retry_adapter(), build_session(), Исходное состояние, Матрица проверки, Незавершённая верификация, Первый этап: тесты и безопасность backend, Подтверждённые находки и изменения, test_plain_text_remote_error_redacts_bearer_token() (+4 more)

### Community 46 - "VmWorkflowRepository"
Cohesion: 0.12
Nodes (11): _decode(), _iso(), VmWorkflowRepository, create_scan(), test_cancelled_before_start_persists_all_steps_and_skips_remote_start(), test_failed_scan_start_is_persisted_and_never_restarted(), test_started_scan_persists_child_operation_before_monitoring(), create() (+3 more)

### Community 47 - "test_risk_management_db.py"
Cohesion: 0.08
Nodes (28): _risk_sql(), RiskRepository, RiskService, risk_data(), test_asset_context_upsert_deduplicates_targets_preserves_fields_and_records_audit(), test_campaign_creation_deduplicates_cases_and_audits_assignments(), test_campaign_empty_patch_checks_supplied_snapshot(), test_campaign_invalid_case_rolls_back_campaign_and_audit() (+20 more)

### Community 48 - "datetime"
Cohesion: 0.10
Nodes (19): classify_asset_type(), evaluate_freshness(), freshness_cutoff(), FreshnessResult, is_internet_asset(), _asset_row(), build_compliance_dataset(), ComplianceRepository (+11 more)

### Community 49 - "vulnerability_hosts"
Cohesion: 0.23
Nodes (6): _service(), trending_vulnerabilities(), vulnerabilities(), vulnerability_hosts(), vulnerability_summary(), vulnerability_trends()

### Community 50 - "log_event"
Cohesion: 0.08
Nodes (33): current_context(), current_trace_id(), describe_sql(), diagnostic_context(), DiagnosticConnection, DiagnosticCursor, log_event(), log_exception() (+25 more)

### Community 51 - "VmManagementPage.jsx"
Cohesion: 0.16
Nodes (26): createIdempotencyKey(), ACTIVE, AttentionQueue(), campaignDraft(), CampaignDrawer(), campaignLabel(), date(), inputDate() (+18 more)

### Community 52 - "useTaskForm.js"
Cohesion: 0.33
Nodes (7): initialForm(), localDateTime(), readEditDrafts(), readNewDraft(), taskForm(), useTaskForm(), storageDescriptor

### Community 54 - "build_asset_card"
Cohesion: 0.12
Nodes (28): build_asset_card(), add_embedded_data_rows(), add_embedded_value_rows(), add_table_row(), add_value_rows(), fetch_collection_specs(), fetch_node_specs(), metadata_for_types() (+20 more)

### Community 55 - "VulnerabilityAnalyticsRepository"
Cohesion: 0.14
Nodes (4): _filtered_findings_cte(), VulnerabilityAnalyticsRepository, FakeConnection, VulnerabilityQueryContractTests

### Community 57 - "db.py"
Cohesion: 0.07
Nodes (68): _append_operation_event(), asset_card_quality(), asset_collection_columns(), _asset_collection_detail_row(), asset_collection_meta(), asset_path_key(), asset_path_label(), asset_path_leaf() (+60 more)

### Community 58 - "VulnerabilityAnalyticsService"
Cohesion: 0.17
Nodes (8): _as_utc(), _bucket_floor(), _iso_utc(), _next_bucket(), VulnerabilityAnalyticsService, FakeTrendRepository, service_snapshot(), VulnerabilityTrendServiceTests

### Community 59 - "MP VM REST API Client"
Cohesion: 0.08
Nodes (26): MP VM Client Architecture, Layered Request Flow, VM Workflow Vertical Slice, Vite Development Application Shell, Application Authorization, Asset Card Query, Automation Runbooks, Docker (+18 more)

### Community 61 - "test_asset_card_jobs.py"
Cohesion: 0.09
Nodes (6): FakeSession, FixtureAssetClient, ParallelTreeAssetClient, PartialFailureAssetClient, SlowClient, WindowsFilteredAssetClient

### Community 62 - "RemediationRepository"
Cohesion: 0.05
Nodes (29): _case(), CoverageRepository, _iso(), RemediationRepository, CoverageService, RemediationService, _asset_with_finding(), _start() (+21 more)

### Community 63 - "test_diagnostic_transactions_db.py"
Cohesion: 0.47
Nodes (6): connect(), read_events(), test_batch_commit_preserves_data_and_omits_parameter_values(), test_batch_failure_can_be_rolled_back_and_connection_reused(), test_deferred_commit_failure_is_not_reported_as_success(), test_invalid_sql_rolls_back_and_records_failure()

### Community 64 - "AssetCardRequestExecutor"
Cohesion: 0.16
Nodes (6): AssetCardBuildCancelled, AssetCardRequestExecutor, mark_completed(), delete_local_asset_card(), AssetCardExecutorTests, semantic_card()

### Community 65 - "export_vulnerability_xlsx"
Cohesion: 0.32
Nodes (4): iter_docker_vulnerability_report_rows(), iter_vulnerability_report_rows(), export_vulnerability_report(), export_vulnerability_xlsx()

### Community 66 - "ScanPostprocessClientTests"
Cohesion: 0.14
Nodes (3): AuthConfig, PagingClient, ScanPostprocessClientTests

### Community 67 - "build_template_draft"
Cohesion: 0.32
Nodes (5): build_template_draft(), find_profile(), find_template(), template_catalogue(), test_template_draft_reports_what_the_admin_must_pick()

### Community 68 - "register_operation"
Cohesion: 0.15
Nodes (18): decode_operation(), get_operation(), get_operations_summary(), list_operations(), register_operation(), sync_operations_from_sources(), OperationsRepository, create() (+10 more)

### Community 69 - "MpVmApiError"
Cohesion: 0.08
Nodes (50): client(), green_connection_job(), response(), test_asset_removal_pending_and_invalid_results(), test_asset_removal_understands_terminal_states_without_count_fields(), test_asset_resolution_queries_normalize_addresses_and_quote_host_names(), test_card_and_passport_reads_validate_dictionary_payload(), test_clean_scan_job_selection_excludes_connection_checks_discovery_and_jobs_with_errors() (+42 more)

### Community 70 - "quality"
Cohesion: 0.08
Nodes (25): MPVM_DATABASE_URL, POSTGRES_DB, POSTGRES_PASSWORD, POSTGRES_USER, jobs, quality, name, on (+17 more)

### Community 71 - "startup"
Cohesion: 0.33
Nodes (5): app_lifespan(), configure_session_from_env(), shutdown(), startup(), test_startup_recovers_bootstrap_and_scheduler_after_database_returns()

### Community 72 - "OperationsPage.jsx"
Cohesion: 0.15
Nodes (17): CaseEditor(), flattenGroups(), formatDate(), Metric(), PolicyEditor(), RemediationPage(), RiskWorkspace(), statusLabels (+9 more)

### Community 73 - "vulnerability_passport_detail_refresh_candidates"
Cohesion: 0.33
Nodes (3): _parse_timestamp(), vulnerability_passport_detail_refresh_candidates(), DatabaseInitializationTests

### Community 74 - "scripts"
Cohesion: 0.18
Nodes (11): scripts, build, coverage:check, dev, format:check, lint, preview, quality (+3 more)

### Community 75 - "OperationRunner"
Cohesion: 0.07
Nodes (15): AppContainer, RuntimeSession, CancellationRegistry, OperationRunner, ReadinessRepository, ServiceBundle, Границы приложения, Backend (+7 more)

### Community 76 - "reports/compliance.py"
Cohesion: 0.14
Nodes (10): _paragraph(), _pdf_font(), render_compliance_pdf(), render_compliance_xlsx(), _safe_cell(), _write_sheet(), ComplianceDataset, _dataset() (+2 more)

### Community 77 - "shell.spec.js"
Cohesion: 0.14
Nodes (9): defaultApiResponse(), EMPTY_TRENDS, ENGINEER_PRESET, installApiMock(), OPERATION, POPULATED_TRENDS, PRESET_TEMPLATES, presetAdminApiOverrides() (+1 more)

### Community 78 - "test_security_administration_db.py"
Cohesion: 0.19
Nodes (17): clone_role(), create_user(), list_permissions(), list_roles(), RoleCloneRequest, RoleUpdateRequest, update_role(), UserCreateRequest (+9 more)

### Community 79 - "monitor_successful_scan_jobs"
Cohesion: 0.10
Nodes (17): monitor_successful_scan_jobs(), drain_asset_batch(), resolution_client(), resolve_target(), submit_asset(), process_scanned_asset_item(), process_scanned_asset_item_with_progress(), raise_if_scan_postprocess_cancelled() (+9 more)

### Community 80 - "test_directory_boundaries.py"
Cohesion: 0.08
Nodes (32): _build_connection(), _escape_filter_value(), _filter_for(), _in_admin_group(), _is_in_required_ou(), LdapError, _password_ok(), resolve_ldap_identity() (+24 more)

### Community 81 - "test_task_presets.py"
Cohesion: 0.07
Nodes (29): flatten_asset_groups(), walk(), _ids(), TaskPresetService, user_role_ids(), test_template_draft_resolves_the_team_role_by_key(), http(), repository() (+21 more)

### Community 82 - "Python Runtime Dependencies"
Cohesion: 0.33
Nodes (6): PostgreSQL CI Service, CI Quality Gate, Python Development Dependencies, FastAPI Backend Stack, PostgreSQL Persistence Stack, Python Runtime Dependencies

### Community 83 - "package.json"
Cohesion: 0.07
Nodes (39): dependencies, react@^19.2.7, react-dom@^19.2.7, @tanstack/react-query@^5.90.5, vite@^8.1.3, @vitejs/plugin-react@^6.0.3, devDependencies, eslint@^9.39.1 (+31 more)

### Community 84 - "VulnerabilityReportTests"
Cohesion: 0.18
Nodes (4): VulnerabilityReportRequest, stream_vulnerability_report_csv(), VulnerabilityReportTests, report_rows()

### Community 85 - "test_http_service_contracts.py"
Cohesion: 0.09
Nodes (21): test_attention_and_search_reject_invalid_cursors(), test_attention_feature_flag_prevents_queries(), test_attention_filters_and_owner_use_authenticated_identity(), test_campaign_verification_requires_every_permission_before_starting(), test_compliance_export_normalizes_selection_and_records_audit(), test_compliance_pagination_rejects_domain_query_errors(), test_compliance_summary_date_and_scope(), test_group_domain_errors_preserve_http_contract() (+13 more)

### Community 87 - "MP VM REST Client Container"
Cohesion: 0.47
Nodes (6): Corporate Network Deployment, MP VM REST Client Container, Corporate PostgreSQL Service, Local Container Deployment, MP VM Client Service, Local PostgreSQL Service

### Community 89 - "test_team_tasks.py"
Cohesion: 0.09
Nodes (28): http(), _preset(), repository(), service(), _task(), test_archived_preset_blocks_create_and_start(), test_create_accepts_any_well_formed_target(), test_create_accepts_targets_without_groups() (+20 more)

### Community 90 - "AssetGroupService"
Cohesion: 0.07
Nodes (28): AssetGroupBulkActionRequest, AssetGroupRepository, AssetGroupService, create(), test_bulk_archival_deduplicates_groups_and_reports_missing_groups(), test_duplicate_group_name_rolls_back_and_leaves_existing_members(), test_empty_group_recalculation_and_archival_hide_it_from_active_tree(), test_failed_evaluation_persists_error_and_can_be_retried() (+20 more)

### Community 91 - "ConnectionTokenTests"
Cohesion: 0.14
Nodes (7): _configure_session_from_env_unlocked(), connect_session(), env_connect_error_message(), resume_connected_workflows(), normalize_url(), ConnectionTokenTests, test_grid_token_keeps_asset_and_group_selection_and_reports_missing_token()

### Community 92 - "Settings"
Cohesion: 0.16
Nodes (12): get_settings(), resolve_access_token(), auth_config(), test_bootstrap_password_strength_and_secret_repr(), test_empty_token_and_missing_credentials_fail_before_network_access(), test_missing_oauth_token_is_rejected(), test_optional_delays_and_cache_ttls_accept_zero_but_reject_negative(), test_password_grant_uses_configured_timeout_and_returns_token() (+4 more)

### Community 93 - "test_vm_workflows.py"
Cohesion: 0.15
Nodes (15): FakeCancellations, FakeRepository, FakeRunner, ImmediateFuture, test_asset_group_replay_is_validated_against_the_persisted_request(), __init__(), test_asset_group_scan_uses_verification_steps_without_reconcile(), test_asset_group_verification_keeps_reconcile_enabled() (+7 more)

### Community 94 - "schema_statements"
Cohesion: 0.27
Nodes (3): schema_statements(), upgrade(), upgrade()

### Community 95 - "api/compliance.py"
Cohesion: 0.29
Nodes (7): _assessment_date(), compliance_findings(), compliance_report(), compliance_stale_assets(), compliance_summary(), _page(), _service()

### Community 96 - "test_auth.py"
Cohesion: 0.06
Nodes (11): effective_permissions(), create_app(), test_compatibility_permission_resolver_is_explicit(), test_cors_is_disabled_by_default_and_rejects_wildcard(), test_effective_permissions_uses_assigned_roles_then_legacy_role(), test_empty_permission_assignment_never_falls_back_to_role_name(), test_hidden_static_route_does_not_inherit_dynamic_route_permission(), test_new_registered_read_route_requires_its_own_permission_policy() (+3 more)

### Community 97 - "TeamTasksPage.jsx"
Cohesion: 0.06
Nodes (77): react-dom, SystemBanner(), permissionUnion(), pluralRoles(), RoleAssignmentDialog(), RoleChips(), RolePicker(), AuditTab() (+69 more)

### Community 99 - "app/__init__.py"
Cohesion: 0.06
Nodes (16): FakePassportClient, VulnerabilityPassportSummaryTests, SystemStatusTests, test_precheck_persists_requested_successful_and_false_targets(), test_retry_false_precheck_only_requests_previous_false_targets(), test_scanner_task_results_returns_all_jobs_and_detects_precheck(), test_scanner_task_results_returns_empty_when_task_has_no_runs(), client() (+8 more)

### Community 100 - "Архитектура MP VM Client"
Cohesion: 0.40
Nodes (5): VM workflow orchestration, Архитектура MP VM Client, Переходные фасады, Правила расширения, Проверки

### Community 102 - "AssetGroupsPage.jsx"
Cohesion: 0.22
Nodes (16): AssetGroupsPage(), defaultOperator(), EMPTY_QUERY(), EMPTY_RULE(), filterTree(), flattenGroups(), formatDate(), GroupDetails() (+8 more)

### Community 113 - "resolve_scanned_target_once"
Cohesion: 0.20
Nodes (4): _ip_equals(), _ip_in_network(), scanned_asset_record_matches(), ScanAssetResolutionTests

### Community 114 - "api/team_tasks.py"
Cohesion: 0.09
Nodes (24): scanner_task_run_jobs(), scanner_task_runs(), _task_runtime(), _audit(), create_team_task(), delete_team_task(), _groups(), list_team_tasks() (+16 more)

### Community 115 - "is_finished"
Cohesion: 0.15
Nodes (6): extract_successful_connection_targets(), is_finished(), is_successful_connection_check_job(), ConnectionCheckJobSuccessTests, IsFinishedTests, WaitForConnectionCheckTargetsTests

### Community 116 - "Основные потоки"
Cohesion: 0.40
Nodes (5): 2. Обработка одного просканированного актива, 3. Построение карточки актива, 4. Уязвимости и паспорта, 5. Remediation и подтверждение результата, Основные потоки

### Community 119 - "api/task_presets.py"
Cohesion: 0.17
Nodes (20): archive_task_preset(), AssetGroupRef, _audit(), _can_manage(), create_task_preset(), get_task_preset(), list_task_presets(), _raise_domain_error() (+12 more)

### Community 125 - "json"
Cohesion: 0.13
Nodes (17): compare(), main(), percentile(), run_benchmark(), main(), percentage(), branch_pct(), main() (+9 more)

### Community 126 - "test_auth_ldap_db.py"
Cohesion: 0.13
Nodes (19): _identity(), _LdapPatch, _make_user(), patch_ldap(), patch_ldap_error(), _permissions(), test_audit_events_record_login_decisions(), test_expired_and_unknown_sessions_are_rejected() (+11 more)

### Community 127 - "test_vm_workflow_idempotency_db.py"
Cohesion: 0.13
Nodes (14): FakeCancellations, FakeRunner, ImmediateFuture, _service(), test_asset_group_replay_rejects_different_group_or_assets(), test_campaign_verification_finalizes_all_cases_with_one_version_change(), test_identical_replay_returns_existing_workflow_without_restarting(), test_parallel_identical_requests_create_exactly_one_workflow() (+6 more)

### Community 128 - "DatabaseRecovery"
Cohesion: 0.14
Nodes (12): database_startup_steps(), coordinator(), test_concurrent_readiness_checks_do_not_duplicate_initialization(), test_database_loss_during_final_probe_is_not_reported_connected(), test_database_returns_after_outage_without_duplicate_jobs(), test_health_probes_are_public_and_sanitized(), test_late_database_recovery_runs_initialization_once(), probe() (+4 more)

### Community 130 - "api/asset_groups.py"
Cohesion: 0.12
Nodes (26): _actor(), archive_group(), bulk_action(), create_group(), create_group_from_vulnerability(), delete_override(), evaluate_group(), get_group() (+18 more)

### Community 131 - "AssetCardSearchIndexTests"
Cohesion: 0.07
Nodes (21): asset_card_search_index_coverage(), asset_card_software_inventory_coverage(), backfill_asset_card_search_index_batch(), backfill_asset_card_software_inventory_batch(), compile_asset_query_node(), compile_asset_query_rule(), copy_rows(), get_asset_card() (+13 more)

### Community 132 - "diagnostics.py"
Cohesion: 0.04
Nodes (48): build_diagnostic_archive(), capture_debug_payload(), ChannelFilter, _cleanup_old_logs(), configure_diagnostics(), ConsoleFilter, DiagnosticsConfig, DiagnosticSession (+40 more)

### Community 134 - "psycopg"
Cohesion: 0.06
Nodes (31): _actor(), assign_tasks_to_folder(), _audit(), create_task_folder(), delete_task_folder(), list_task_folders(), _raise_domain_error(), rename_task_folder() (+23 more)

### Community 135 - "test_vm_workflow_boundaries.py"
Cohesion: 0.11
Nodes (11): test_campaign_start_handles_missing_empty_active_and_replayed_targets(), test_empty_asset_group_finishes_without_child_operations(), test_monitor_cancels_after_waiting_for_an_unknown_child(), test_recovery_without_any_saved_child_persists_failure_without_reconciliation(), test_retry_rejects_missing_or_nonretryable_workflows(), test_retry_reuses_the_request_and_does_not_schedule_a_replayed_attempt(), test_scan_replay_cannot_reuse_other_workflow_or_retry_key(), test_tracking_existing_scan_persists_child_before_monitoring() (+3 more)

### Community 136 - "test_auth_ldap.py"
Cohesion: 0.14
Nodes (11): _fake_now_utc(), _QueryResult, _RoleLookupConn, test_existing_local_user_wins_over_ldap(), test_ldap_default_role_can_resolve_custom_role_by_name_when_key_is_null(), test_ldap_default_role_falls_back_to_viewer_when_configured_role_is_missing(), test_ldap_login_maps_admin_group_to_admin_role(), test_ldap_login_mode_uses_ldap_without_local_password_check() (+3 more)

### Community 137 - "ScannerTaskFolderRepository"
Cohesion: 0.22
Nodes (4): ScannerTaskFolderRepository, ScannerTaskFolderService, test_folder_names_are_trimmed_and_blank_names_rejected(), test_shared_folder_assignments_are_unique_audited_and_unassigned_on_delete()

### Community 138 - "TaskPresetRepository"
Cohesion: 0.23
Nodes (3): _json_param(), _serialize(), TaskPresetRepository

### Community 139 - "План развития MP VM Client до MVP"
Cohesion: 0.09
Nodes (21): 0.1. Восстановить frontend quality gate — P0, S, 0.2. Ввести единый release quality gate — P0, M, 1.1. Fail-closed RBAC и реальные тесты сессий — P0, S/M, 1.2. Production-профиль конфигурации — P0, S/M, 1.3. Разделить liveness и readiness — P0, S, 3.1. Единая очередь «Требует действия» — P1, M, 3.2. Глобальный поиск расследования — P1, M, 4.1. Телеметрия очередей и зависших операций — P2, S/M (+13 more)

### Community 140 - "test_api_contracts_db.py"
Cohesion: 0.18
Nodes (16): _detail_code(), _login(), _make_user(), _seed_case(), test_case_get_returns_404_with_code(), test_case_update_optimistic_lock_conflict_returns_409(), test_case_update_rejects_missing_expected_version(), test_create_user_rejects_short_password_and_bad_username() (+8 more)

### Community 141 - "Архитектура системы MP VM Client"
Cohesion: 0.13
Nodes (15): Frontend, HTTP API, MP VM недоступна или сессия отсутствует, PostgreSQL, PostgreSQL недоступен, Архитектура системы MP VM Client, Аутентификация и трассировка, Внешняя MP VM (+7 more)

### Community 142 - "sync_trending_vulnerability_passports"
Cohesion: 0.20
Nodes (3): merge_trending_vulnerability_records(), sync_trending_vulnerability_passports(), PassportQueryTests

### Community 143 - "Руководство оператора MP VM Client"
Cohesion: 0.10
Nodes (19): Автоматизация, Быстрый рабочий цикл, Выборки по карточкам, Группы активов, Карточки активов, Карточки активов и локальные выборки, Навигация и маршруты, Назначение (+11 more)

### Community 144 - "test_rbac_matrix_db.py"
Cohesion: 0.10
Nodes (15): ensure_rbac_catalog(), required_permission(), _create_user(), _login(), rbac_matrix(), _role_permissions(), _seed_sla_policy(), test_rbac_matrix_differentiates_roles() (+7 more)

### Community 145 - "services/team_tasks.py"
Cohesion: 0.26
Nodes (6): _ip_or_none(), normalize_scan_target(), normalize_scan_targets(), test_duplicates_collapse_after_normalization(), test_invalid_targets_are_rejected(), test_valid_targets_are_normalized()

### Community 147 - "vm.py"
Cohesion: 0.26
Nodes (11): _actor(), cancel_workflow(), get_workflow(), list_workflows(), overview(), _require(), retry_workflow(), scan_preflight() (+3 more)

### Community 149 - "routers.py"
Cohesion: 0.35
Nodes (3): attention(), _permissions(), search()

### Community 154 - "ARCHITECTURE.md"
Cohesion: 0.21
Nodes (7): Документация MP VM REST API Client, Основные документы, Правило актуальности, Python quality gate и пороги покрытия, Полный прогон, Тестирование в Docker, Что проверяют расширенные наборы

### Community 156 - "Дашборды и отчеты по критическим уязвимостям"
Cohesion: 0.15
Nodes (12): Backend API, Аудит, доступ и хранение, Дашборды и отчеты по критическим уязвимостям, Критерии приемки, Модель данных и вычисления, Обработка ошибок, Пользовательский интерфейс, Принятые решения (+4 more)

### Community 158 - "Переработка вкладки задач"
Cohesion: 0.17
Nodes (11): API истории и совместимость, Критерии приемки, Локальное хранение папок и API, Ошибки и безопасность, Переработка вкладки задач, Подробности задачи, Принятые решения, Проверки (+3 more)

### Community 159 - "Пресеты задач для инженеров"
Cohesion: 0.17
Nodes (11): API, Инженер Linux, Инженер Windows, Ограничения, Подготовка узлов, Почему так, Пресеты задач для инженеров, Роли и права (+3 more)

### Community 164 - "Разработка и развёртывание"
Cohesion: 0.18
Nodes (11): Frontend, PostgreSQL и backend, База данных и миграции, Контейнерный запуск, Конфигурация, Локальный запуск, Подтверждённые проблемы и диагностика, Разработка и развёртывание (+3 more)

### Community 172 - "MP VM Client — инструкции агенту"
Cohesion: 0.25
Nodes (7): Graphify, MP VM Client — инструкции агенту, Главный принцип, Завершение задачи, Критичные правила, Проверки — только Docker, Проект

### Community 173 - "test_attention_compliance_db.py"
Cohesion: 0.10
Nodes (21): ComplianceService, Critical Vulnerability Compliance Reports Implementation Plan, File Structure, Final Acceptance Checklist, Global Constraints, Task 4: Compliance Service and Dashboard API, Task 5: PDF/XLSX Rendering and Audited Downloads, Task 6: Compliance Query Hook and Dashboard Component (+13 more)

### Community 177 - "Исправления корректности — 2026-10-01"
Cohesion: 0.29
Nodes (6): Версии контекста и кампаний, Готовность и восстановление, Исправления корректности — 2026-10-01, Каталог разрешений, Проверки и применение, Свидетельства эксплуатации

### Community 184 - "Q: Почему MpVmClient соединяет 13 функциональных сообществ проекта?"
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: Почему MpVmClient соединяет 13 функциональных сообществ проекта?, Source Nodes

### Community 185 - "Q: Собери информацию обо всех трассах MpVmClient"
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: Собери информацию обо всех трассах MpVmClient, Source Nodes

### Community 186 - "Q: При клике на задачу увидеть её результаты: для precheck успешные и неуспешные проверки, для обычной задачи успешность сканирования, всё в отдельном окне."
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: При клике на задачу увидеть её результаты: для precheck успешные и неуспешные проверки, для обычной задачи успешность сканирования, всё в отдельном окне., Source Nodes

### Community 187 - "Q: Уточнение UI результатов задач по примерам MP VM jobs для обычного скана и precheck."
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: Уточнение UI результатов задач по примерам MP VM jobs для обычного скана и precheck., Source Nodes

### Community 188 - "Q: Можно ли удалить вкладку Активы и использовать Уязвимости, Карточки активов и Группы активов?"
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: Можно ли удалить вкладку Активы и использовать Уязвимости, Карточки активов и Группы активов?, Source Nodes

### Community 189 - "Q: Удалить вкладку Активы, оставить Уязвимости, Карточки активов и Группы активов, перенаправлять /assets."
Cohesion: 0.40
Nodes (4): Answer, Outcome, Q: Удалить вкладку Активы, оставить Уязвимости, Карточки активов и Группы активов, перенаправлять /assets., Source Nodes

### Community 234 - "test_catalog_cancellation_never_submits_queued_detail_work"
Cohesion: 0.20
Nodes (8): RefreshCancelled, run(), progress(), test_catalog_cancellation_never_submits_queued_detail_work(), test_catalog_failures_are_persisted_with_bounded_error_messages(), test_catalog_refresh_preserves_result_and_submits_detail_arguments(), query(), test_naive_scan_dates_are_interpreted_as_utc_at_the_freshness_boundary()

### Community 327 - "Этап 2. Данные и восстановление"
Cohesion: 0.40
Nodes (5): 2.1. Восстановление после возврата PostgreSQL без рестарта — P0, M, 2.2. Проверяемые миграции, backup и restore — P0, M, 2.3. Безопасные retry изменяющих MP VM-запросов — P0, M, 2.4. Долговечные leases критичных jobs — P0/P1, L, Этап 2. Данные и восстановление

## Knowledge Gaps
- **9 isolated node(s):** `Layered Request Flow`, `Application Authorization`, `Asset Card Query`, `Automation Runbooks`, `Operations Center` (+4 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1081 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **52 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Work-memory lessons

**Preferred sources** — corroborated by past sessions; start here.
- `MpVmClient` (3× useful, score=2.734681956) _(code changed — re-verify)_
- `navigationGroups` (2× useful, score=1.916821645) _(code changed — re-verify)_
- `AssetCardRequestExecutor` (2× useful, score=1.777067251) _(code changed — re-verify)_

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `File Structure` connect `test_attention_compliance_db.py` to `datetime`, `run_scan_postprocess`?**
  _High betweenness centrality (0.265) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `connect()` (e.g. with `DiagnosticConnection` and `DiagnosticCursor`) actually correct?**
  _`connect()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Layered Request Flow`, `Application Authorization`, `Asset Card Query` to the rest of the system?**
  _9 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `FakeSession` be split into smaller, more focused modules?**
  _Cohesion score 0.044444444444444446 - nodes in this community are weakly interconnected._
- **Why does `Task 7: Direct Browser Downloads and Responsive Styling` connect `test_attention_compliance_db.py` to `api`?**
  _High betweenness centrality (0.196) - this node is a cross-community bridge._
- **Are the 36 inferred relationships involving `MpVmClient` (e.g. with `RuntimeSession` and `AssetCardRequestExecutor`) actually correct?**
  _`MpVmClient` has 36 INFERRED edges - model-reasoned connections that need verification._
- **Should `mp10_export_VM_info.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06985062066063538 - nodes in this community are weakly interconnected._