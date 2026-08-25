# Graph Report - MP VM test  (2026-08-25)

## Corpus Check
- 146 files · ~369,564 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2775 nodes · 8691 edges · 125 communities (97 shown, 28 thin omitted)
- Extraction: 93% EXTRACTED · 7% INFERRED · 0% AMBIGUOUS · INFERRED: 633 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Bundled Frontend Runtime
- MP10 API Client
- Asset Card Interface
- ai Components
- Automation API Schemas
- Dashboard UI Components
- Vulnerability Snapshot Processing
- Runtime Configuration
- Authentication Schemas
- Diagnostic Logging
- Database Bootstrap
- VM Workflow Service
- add Components
- aa Components
- Frontend API Client
- Automation Step Editor
- Risk Campaign Schemas
- ac Components
- Automation Repository
- Remediation Repositories
- Scanner Payload Tests
- ScanPostprocessCancelled Components
- MP VM Transport
- Scan Postprocessing
- Database Integration Tests
- an Components
- Asset API Schemas
- Application Pages
- Service Repository Bundle
- ad Components
- Remediation Policy Schemas
- Automation Service
- Application Shell
- FakeConnection Components
- Asset Data Utilities
- Asset Query Interface
- Asset Repositories
- Asset Search Logic
- Asset Job Schemas
- Scanner Task API
- API Error Handling
- Vulnerability Report Tests
- Asset Database Tests
- Operations API Tests
- Vulnerability Row Decoders
- Diagnostic Sessions
- VM Workflow Repository
- Risk Repository
- Asset Configuration UI
- Vulnerability API Routes
- Authorization Middleware
- Risk Campaign UI
- Ae Components
- bl Components
- API Route Composition
- Vulnerability Analytics Repository
- Asset Refresh Tests
- Asset Collection Mapping
- Vulnerability Analytics Service
- Architecture And Integration
- Frontend Development Dependencies
- Asset Executor Tests
- Remediation Service Tests
- Remediation Service
- Asset Request Executor
- Snapshot Trigger Tests
- Scan Postprocess Client Tests
- Vulnerability Passport API
- Operation Event Mapping
- Asset Import Processing
- Risk Management Service
- Ao Components
- Application Data Provider
- Frontend Runtime Dependencies
- Package Build Scripts
- Cancellation Registry
- Dashboard Component Tests
- Browser Workflow Tests
- Docker Deduplication Tests
- Docker Cleanup Tests
- Scanner Start API Tests
- Parallel Asset Tests
- Backend Persistence Stack
- Node Runtime Configuration
- Asset Search Index Tests
- Scan Monitoring Tests
- Vulnerability API Contracts
- Container Deployment Stack
- Logging Benchmark
- Asset Job API Tests
- Slow Client Tests
- Connection Token Tests
- Scan Processing Order
- Asset Resolution Tests
- Baseline Database Migration
- Domain Error Model
- FastAPI Application Factory
- Network Asset Matching
- Architecture Contract Tests
- Thread Pool Utilities
- Automation Database Migration
- Vulnerability Trends Migration
- Coverage Ratchet Script
- API Composition Package
- React ESLint Plugin
- React Refresh Plugin
- Global Definitions Package
- Vitest Test Runner
- Vitest Coverage Package

## God Nodes (most connected - your core abstractions)
1. `connect()` - 111 edges
2. `i()` - 100 edges
3. `MpVmClient` - 97 edges
4. `n()` - 92 edges
5. `t()` - 86 edges
6. `r()` - 71 edges
7. `a()` - 67 edges
8. `now_utc()` - 61 edges
9. `MpVmApiError` - 56 edges
10. `init_db()` - 54 edges

## Surprising Connections (you probably didn't know these)
- `MP VM REST API Client` --conceptually_related_to--> `MaxPatrol SIEM Integration`  [AMBIGUOUS]
  README.md → ptmpsiem27.6_devguide_ru.pdf
- `VM Workflow Vertical Slice` --semantically_similar_to--> `VM Workflow Orchestration`  [INFERRED] [semantically similar]
  docs/ARCHITECTURE.md → README.md
- `Production React Application Shell` --semantically_similar_to--> `Vite Development Application Shell`  [INFERRED] [semantically similar]
  app/static/index.html → index.html
- `MP VM Client Service` --semantically_similar_to--> `MP VM REST Client Container`  [INFERRED] [semantically similar]
  docker-compose.yml → docker-compose.corpnet.example.yml
- `DefinitionTests` --uses--> `AutomationStepCancelled`  [INFERRED]
  tests/test_automations.py → app/automations/service.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **MP VM Application Delivery Stack** — readme_mp_vm_rest_api_client, app_static_index_production_shell, index_development_shell, docker_compose_local_deployment, requirements_runtime_dependencies [INFERRED 0.85]
- **Persistent VM Workflow System** — readme_vm_workflow_orchestration, readme_remediation_lifecycle, readme_operations_center, docs_architecture_vm_workflow_vertical_slice [INFERRED 0.95]
- **Quality-Verified Layered Architecture** — github_workflows_quality_quality_gate, docs_architecture_application_architecture, requirements_dev_development_dependencies [INFERRED 0.85]

## Communities (125 total, 28 thin omitted)

### Community 0 - "Bundled Frontend Runtime"
Cohesion: 0.03
Nodes (123): a(), addObserver(), al(), Br(), build(), cancel(), cancelQueries(), cd() (+115 more)

### Community 1 - "MP10 API Client"
Cohesion: 0.07
Nodes (68): IPv4Network, as_dict_list(), asset_id_from_csv_row(), AuthConfig, build_default_token_url(), build_disabled_daily_trigger(), build_export_output_path(), build_filtered_pdql() (+60 more)

### Community 2 - "Asset Card Interface"
Cohesion: 0.05
Nodes (71): ACTIVE_ASSET_CARD_JOB_STATUSES, ACTIVE_BULK_REFRESH_STATUSES, ACTIVE_PASSPORT_JOB_STATUSES, ACTIVE_SCAN_POSTPROCESS_STATUSES, ASSET_DEFAULT_FILTERS, ASSET_DEFAULT_SORT, ASSET_SORT_OPTIONS, AssetCard() (+63 more)

### Community 3 - "ai Components"
Cohesion: 0.16
Nodes (77): ai(), Ba(), bi(), bn(), C(), ca(), canRun(), Ci() (+69 more)

### Community 4 - "Automation API Schemas"
Cohesion: 0.06
Nodes (70): AutomationScheduleRequest, active_asset_card_build_job(), active_vulnerability_passport_detail_job(), app_lifespan(), asset_card_build_job(), asset_card_query_fields(), assets(), assets_summary() (+62 more)

### Community 5 - "Dashboard UI Components"
Cohesion: 0.06
Nodes (60): barWidth(), DashboardContext(), DEFAULT_HOST_SORT, DEFAULT_VULNERABILITY_SORT, EMPTY_FILTERS, filterSeverity(), formatCalendarDate(), formatDate() (+52 more)

### Community 6 - "Vulnerability Snapshot Processing"
Cohesion: 0.07
Nodes (69): asset_card_refresh_templates(), asset_value_to_text(), build_asset_vulnerability_snapshot(), build_docker_vulnerability_source(), clean_text(), dedupe_asset_candidates(), dedupe_vulnerability_passports(), _docker_container_key() (+61 more)

### Community 7 - "Runtime Configuration"
Cohesion: 0.06
Nodes (17): get_settings(), field_validator, Validated process configuration loaded from ``MPVM_*`` variables., Settings, AppContainer, Explicit owner of mutable process-scoped application state., RuntimeSession, Application-wide configuration and runtime primitives. (+9 more)

### Community 8 - "Authentication Schemas"
Cohesion: 0.07
Nodes (44): audit_event(), authenticate(), cleanup_audit_events(), clone_role(), create_session(), create_user(), get_session_user(), hash_password() (+36 more)

### Community 9 - "Diagnostic Logging"
Cohesion: 0.08
Nodes (40): build_diagnostic_archive(), capture_debug_payload(), ChannelFilter, _cleanup_old_logs(), configure_diagnostics(), ConsoleFilter, current_context(), describe_sql() (+32 more)

### Community 10 - "Database Bootstrap"
Cohesion: 0.09
Nodes (55): ensure_bootstrap_admin(), ensure_rbac_catalog(), Seed immutable templates and migrate the former app_users.role values once., asset_card_exists(), asset_card_search_index_coverage(), backfill_asset_card_search_index_batch(), _close_database_circuit(), connect() (+47 more)

### Community 11 - "VM Workflow Service"
Cohesion: 0.08
Nodes (20): Any, Event, RuntimeError, Reuse persisted child results when only the final reconciliation failed., Durable orchestration over the existing operation and scan-postprocess engines., VmPreflightBlocked, VmWorkflowService, OperationAction (+12 more)

### Community 12 - "add Components"
Cohesion: 0.09
Nodes (55): add(), At(), bs(), bt(), ct(), df(), dl(), dt() (+47 more)

### Community 13 - "aa Components"
Cohesion: 0.07
Nodes (51): aa(), ap(), as(), b(), ce(), Co(), cp(), dp() (+43 more)

### Community 14 - "Frontend API Client"
Cohesion: 0.08
Nodes (34): api(), downloadApiFile(), normalizeApiError(), App(), AppProviders(), createRequestId(), flushFrontendDiagnostics(), installGlobalDiagnostics() (+26 more)

### Community 15 - "Automation Step Editor"
Cohesion: 0.09
Nodes (38): AssetQueryStepConfig(), AutomationStepEditor(), automationStepFromApi(), automationStepToApi(), clone(), collectQueryRules(), compactConfig(), CONDITION_OPERATORS (+30 more)

### Community 16 - "Risk Campaign Schemas"
Cohesion: 0.10
Nodes (43): actor(), CampaignCreate, CampaignUpdate, ContextCsvImport, ContextUpdate, ContextValues, create_campaign(), get_campaign() (+35 more)

### Community 17 - "ac Components"
Cohesion: 0.08
Nodes (46): ac(), af(), bc(), Bd(), cc(), cf(), da(), ec() (+38 more)

### Community 18 - "Automation Repository"
Cohesion: 0.13
Nodes (5): AutomationRepository, _dump(), _load(), Any, _rows()

### Community 19 - "Remediation Repositories"
Cohesion: 0.11
Nodes (10): _case(), CoverageRepository, _iso(), Any, datetime, RemediationRepository, FakeConnection, FakeResult (+2 more)

### Community 20 - "Scanner Payload Tests"
Cohesion: 0.11
Nodes (29): asset_id_from_csv_row(), build_asset_resolution_pdql(), build_credential_overrides(), build_disabled_daily_trigger(), build_scanner_task_payload(), build_windows_credential_overrides(), csv_dict_reader(), dedupe_keep_order() (+21 more)

### Community 21 - "ScanPostprocessCancelled Components"
Cohesion: 0.14
Nodes (36): build_scanned_asset_card(), cleanup_auto_created_refresh_task(), configure_session_from_env(), confirm_docker_scan_terminal_for_cleanup(), connect_session(), docker_dynamic_group_from_options(), docker_group_cleanup_after(), finish_provisional_scan_start_failure() (+28 more)

### Community 22 - "MP VM Transport"
Cohesion: 0.17
Nodes (5): is_scanner_task_not_found(), MpVmClient, Event, Path, Response

### Community 23 - "Scan Postprocessing"
Cohesion: 0.10
Nodes (35): claim_scan_postprocess_run(), create_scan_postprocess_run(), _credential_id_from_payload(), database_circuit_status(), decode_scan_postprocess_item(), decode_scan_postprocess_run(), _decode_scan_task(), finish_scan_postprocess_run() (+27 more)

### Community 24 - "Database Integration Tests"
Cohesion: 0.06
Nodes (7): run_migrations_online(), DatabaseInitializationTests, FakePassportClient, PassportDetailWorkerTests, PassportQueryTests, VulnerabilityPassportSummaryTests, VulnerabilityPassportWriteLockTests

### Community 25 - "an Components"
Cohesion: 0.10
Nodes (35): an(), bindMethods(), cn(), constructor(), cs(), dn(), fn(), Fo() (+27 more)

### Community 26 - "Asset API Schemas"
Cohesion: 0.10
Nodes (34): AssetCardFieldQueryRequest, AssetCardRefreshScanRequest, StartScannerTaskRequest, AutomationStepCancelled, RuntimeError, asset_card_query(), build_asset_refresh_task_payload(), build_precheck_task_name() (+26 more)

### Community 27 - "Application Pages"
Cohesion: 0.08
Nodes (25): AssetCardsPage(), ExportPage(), PassportsPage(), TasksPage(), assetCardJobStageLabel(), assetCardJobStatusLabel(), AssetCardsPanel(), clampNumber() (+17 more)

### Community 28 - "Service Repository Bundle"
Cohesion: 0.11
Nodes (10): RepositoryBundle, AssetCardsService, AssetQueryService, AssetsService, OperationsService, PassportsService, Any, ServiceBundle (+2 more)

### Community 29 - "ad Components"
Cohesion: 0.12
Nodes (33): ad(), Au(), bu(), Cu(), Eu(), fu(), Gd(), gu() (+25 more)

### Community 30 - "Remediation Policy Schemas"
Cohesion: 0.17
Nodes (29): bulk_update(), BulkCaseUpdate, CaseUpdate, coverage_assets(), coverage_summary(), get_case(), list_cases(), policy() (+21 more)

### Community 31 - "Automation Service"
Cohesion: 0.15
Nodes (4): AutomationService, Any, datetime, SchedulerTests

### Community 32 - "Application Shell"
Cohesion: 0.14
Nodes (22): AppShell(), AuthenticatedApp(), useAppDataContext(), AlertStack(), routeNextActions, shouldHandleLinkClick(), Sidebar(), SystemBanner() (+14 more)

### Community 33 - "FakeConnection Components"
Cohesion: 0.12
Nodes (9): database_snapshot_rows(), FakeConnection, FakeResult, FakeTrendRepository, datetime, service_snapshot(), SnapshotRepositoryTests, VulnerabilityTrendApiTests (+1 more)

### Community 34 - "Asset Data Utilities"
Cohesion: 0.14
Nodes (29): _asset_vulnerability_group(), chunked(), clean_value(), decimal_to_number(), decode_asset_card(), _decode_asset_vulnerability_finding(), deduplicate_asset_card_vulnerability_findings(), delete_findings_for_assets() (+21 more)

### Community 35 - "Asset Query Interface"
Cohesion: 0.15
Nodes (23): AssetQueryPage(), contentDispositionFilename(), countRules(), DEFAULT_SORT, EMPTY_GROUP(), EMPTY_RULE(), formatDate(), friendlyFieldName() (+15 more)

### Community 36 - "Asset Repositories"
Cohesion: 0.13
Nodes (9): AssetCardsRepository, AssetQueryRepository, AssetsRepository, ImportsRepository, OperationsRepository, PassportsRepository, Any, TasksRepository (+1 more)

### Community 37 - "Asset Search Logic"
Cohesion: 0.14
Nodes (26): asset_path_leaf(), asset_query_evidence_matches(), asset_search_leaf_rows(), build_asset_card_search_rows(), collect_asset_query_rules(), compile_asset_query_node(), compile_asset_query_rule(), copy_rows() (+18 more)

### Community 38 - "Asset Job Schemas"
Cohesion: 0.15
Nodes (24): AssetCardAssetQueryRequest, AssetCardBuildJobRequest, AssetCardBuildRequest, AssetCardBulkRefreshRequest, AssetCardUpdateRequest, AutomationPublishRequest, AutomationRunbookRequest, AutomationRunRequest (+16 more)

### Community 39 - "Scanner Task API"
Cohesion: 0.14
Nodes (25): ScannerTaskRequest, build_asset_card(), build_asset_card_endpoint(), capture_vulnerability_snapshot(), create_scanner_task(), export_pdql(), http_error(), mpvm_lookups() (+17 more)

### Community 40 - "API Error Handling"
Cohesion: 0.23
Nodes (8): as_dict_list(), compact_json_summary(), ensure_items(), ensure_list(), MpVmApiError, Any, RuntimeError, Raised when MP VM returns an unexpected API response.

### Community 41 - "Vulnerability Report Tests"
Cohesion: 0.12
Nodes (6): Any, field_validator, VulnerabilityReportRequest, FakeConnection, FakeCursor, VulnerabilityReportTests

### Community 43 - "Operations API Tests"
Cohesion: 0.10
Nodes (4): OperationsApiTests, QueryResult, ScriptedConnection, SystemStatusTests

### Community 44 - "Vulnerability Row Decoders"
Cohesion: 0.21
Nodes (12): _decode_host(), _decode_snapshot_rows(), _decode_trending_passport(), _decode_vulnerability(), _filtered_findings_cte(), _normalized_severity(), _page_bounds(), Any (+4 more)

### Community 45 - "Diagnostic Sessions"
Cohesion: 0.11
Nodes (13): DiagnosticSession, Requests session that records sanitized MP VM request lifecycle events., Any, Response, RuntimeError, Resolve a supplied bearer token or perform the OAuth password grant., resolve_access_token(), HTTPAdapter (+5 more)

### Community 46 - "VM Workflow Repository"
Cohesion: 0.20
Nodes (5): MP VM REST client application., _decode(), _iso(), Any, VmWorkflowRepository

### Community 47 - "Risk Repository"
Cohesion: 0.20
Nodes (5): Any, _risk_sql(), RiskRepository, test_context_rejects_unknown_classification_before_database_access(), test_risk_model_is_versioned_and_bounded()

### Community 48 - "Asset Configuration UI"
Cohesion: 0.16
Nodes (18): AssetsPage(), AssetConfigTable(), AssetConfigTablePaged(), AssetPropertyList(), AssetRowsTable(), AssetsPanel(), formatAssetCell(), postprocessCardLabel() (+10 more)

### Community 49 - "Vulnerability API Routes"
Cohesion: 0.24
Nodes (20): alias, datetime, ge, get, le, max_length, Query, Request (+12 more)

### Community 50 - "Authorization Middleware"
Cohesion: 0.14
Nodes (21): delete_role(), current_trace_id(), application_auth_middleware(), auth_delete_role(), auth_error(), auth_login(), auth_logout(), auth_update_role() (+13 more)

### Community 51 - "Risk Campaign UI"
Cohesion: 0.16
Nodes (14): createIdempotencyKey(), ACTIVE, CampaignDrawer(), campaignLabel(), date(), inputDate(), queryValue(), readPreferences() (+6 more)

### Community 52 - "Ae Components"
Cohesion: 0.17
Nodes (20): Ae(), Be(), clearInterval(), de(), fe(), G(), gt(), He() (+12 more)

### Community 53 - "bl Components"
Cohesion: 0.18
Nodes (20): bl(), cl(), ea(), gl(), jc(), l(), ol(), Pa() (+12 more)

### Community 54 - "API Route Composition"
Cohesion: 0.13
Nodes (19): auth_clone_role(), auth_create_user(), cancel_asset_card_build_job(), cancel_automation_run(), cancel_operation(), cancel_scan_postprocess_run(), cancel_vulnerability_passport_detail_job(), decode_csv_bytes() (+11 more)

### Community 55 - "Vulnerability Analytics Repository"
Cohesion: 0.18
Nodes (5): Analytics over the latest asset cards and their retained aggregates., VulnerabilityAnalyticsRepository, FakeConnection, FakeResult, VulnerabilityQueryContractTests

### Community 57 - "Asset Collection Mapping"
Cohesion: 0.20
Nodes (18): asset_collection_columns(), _asset_collection_detail_row(), asset_collection_meta(), asset_path_key(), asset_path_label(), asset_tree_depth(), asset_tree_parent_path(), _asset_tree_paths_with_children() (+10 more)

### Community 58 - "Vulnerability Analytics Service"
Cohesion: 0.24
Nodes (8): _as_utc(), _bucket_floor(), _iso_utc(), _next_bucket(), Any, datetime, TrendBucket, VulnerabilityAnalyticsService

### Community 59 - "Architecture And Integration"
Cohesion: 0.15
Nodes (17): Production React Application Shell, AppContainer Process Resource Ownership, MP VM Client Architecture, Layered Request Flow, Backward-Compatible Transition Facades, VM Workflow Vertical Slice, Vite Development Application Shell, MaxPatrol SIEM 27.6 Developer Guide (+9 more)

### Community 60 - "Frontend Development Dependencies"
Cohesion: 0.12
Nodes (17): eslint, @eslint/js, eslint-plugin-react-hooks, jsdom, devDependencies, eslint, @eslint/js, eslint-plugin-react-hooks (+9 more)

### Community 61 - "Asset Executor Tests"
Cohesion: 0.14
Nodes (4): AssetCardExecutorTests, FixtureAssetClient, PartialFailureAssetClient, semantic_card()

### Community 63 - "Remediation Service"
Cohesion: 0.21
Nodes (3): Any, datetime, RemediationService

### Community 64 - "Asset Request Executor"
Cohesion: 0.24
Nodes (4): AssetCardBuildCancelled, AssetCardRequestExecutor, Exception, Future

### Community 65 - "Snapshot Trigger Tests"
Cohesion: 0.19
Nodes (5): AssetCardSnapshotTriggerTests, _built_card(), FakeSession, ScanPostprocessSnapshotTriggerTests, SnapshotSafetyTests

### Community 67 - "Vulnerability Passport API"
Cohesion: 0.21
Nodes (13): decode_vulnerability_passport(), delete_vulnerability_passport(), get_vulnerability_passport(), _lock_vulnerability_passport_writes(), Atomically replace the current trend snapshot without degrading passport data., Choose one best passport per finding using vulnerability and host OS context., reconcile_asset_card_vulnerability_passport_links(), replace_vulnerability_passport_trends() (+5 more)

### Community 68 - "Operation Event Mapping"
Cohesion: 0.18
Nodes (12): _append_operation_event(), decode_operation(), decode_operation_event(), get_operation(), get_operation_by_idempotency_key(), get_operations_summary(), Return unfiltered operation counters for navigation and overview widgets., Create or refresh the normalized operation registry without replacing richer… (+4 more)

### Community 69 - "Asset Import Processing"
Cohesion: 0.21
Nodes (12): cleanup_orphans(), collect_asset_identity(), create_import_run(), empty_asset_identity_set(), finish_import_run(), first_value(), import_csv_text(), make_csv_reader() (+4 more)

### Community 71 - "Ao Components"
Cohesion: 0.33
Nodes (12): Ao(), bo(), Gi(), go(), ko(), lc(), qo(), s() (+4 more)

### Community 72 - "Application Data Provider"
Cohesion: 0.24
Nodes (10): AppDataContext, AppDataProvider(), ACTIVE_OPERATION_STATUSES, assetsQuery(), DEFAULT_OPERATION_QUERY, EMPTY_CONNECTION_DRAFT, EMPTY_LOOKUPS, operationsQuery() (+2 more)

### Community 73 - "Frontend Runtime Dependencies"
Cohesion: 0.18
Nodes (11): dependencies, react, react-dom, @tanstack/react-query, vite, @vitejs/plugin-react, react, react-dom (+3 more)

### Community 74 - "Package Build Scripts"
Cohesion: 0.18
Nodes (11): scripts, build, coverage:check, dev, format:check, lint, preview, quality (+3 more)

### Community 75 - "Cancellation Registry"
Cohesion: 0.24
Nodes (3): CancellationRegistry, Event, Thread-safe registry for cancellation tokens owned by active jobs.

### Community 76 - "Dashboard Component Tests"
Cohesion: 0.22
Nodes (6): HOST, RESOLUTION_STATS, SUMMARY, TRENDING_VULNERABILITIES, TRENDS, VULNERABILITY

### Community 77 - "Browser Workflow Tests"
Cohesion: 0.25
Nodes (6): defaultApiResponse(), EMPTY_TRENDS, installApiMock(), OPERATION, POPULATED_TRENDS, ROUTES

### Community 82 - "Backend Persistence Stack"
Cohesion: 0.29
Nodes (7): PostgreSQL CI Service, CI Quality Gate, MP VM Database Table Inventory, Python Development Dependencies, FastAPI Backend Stack, PostgreSQL Persistence Stack, Python Runtime Dependencies

### Community 83 - "Node Runtime Configuration"
Cohesion: 0.29
Nodes (6): engines, node, name, private, type, version

### Community 87 - "Container Deployment Stack"
Cohesion: 0.47
Nodes (6): Corporate Network Deployment, MP VM REST Client Container, Corporate PostgreSQL Service, Local Container Deployment, MP VM Client Service, Local PostgreSQL Service

### Community 88 - "Logging Benchmark"
Cohesion: 0.60
Nodes (5): compare(), main(), percentile(), Any, run_benchmark()

### Community 94 - "Baseline Database Migration"
Cohesion: 0.50
Nodes (3): Return the idempotent baseline schema used by Alembic and legacy startup., schema_statements(), upgrade()

### Community 96 - "FastAPI Application Factory"
Cohesion: 0.50
Nodes (4): create_app(), FastAPI, Path, Lifespan

### Community 97 - "Network Asset Matching"
Cohesion: 0.40
Nodes (5): _ip_equals(), _ip_in_network(), scanned_asset_record_matches(), _BaseAddress, _BaseNetwork

### Community 102 - "Coverage Ratchet Script"
Cohesion: 0.83
Nodes (3): main(), percentage(), Path

## Ambiguous Edges - Review These
- `MP VM REST API Client` → `MaxPatrol SIEM Integration`  [AMBIGUOUS]
  README.md · relation: conceptually_related_to
- `MaxPatrol SIEM 27.6 Developer Guide` → `MaxPatrol SIEM Integration`  [AMBIGUOUS]
  ptmpsiem27.6_devguide_ru.pdf · relation: implements

## Knowledge Gaps
- **92 isolated node(s):** `name`, `version`, `private`, `type`, `node` (+87 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `MP VM REST API Client` and `MaxPatrol SIEM Integration`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **What is the exact relationship between `MaxPatrol SIEM 27.6 Developer Guide` and `MaxPatrol SIEM Integration`?**
  _Edge tagged AMBIGUOUS (relation: implements) - confidence is low._
- **Why does `MpVmClient` connect `MP VM Transport` to `Asset Request Executor`, `Snapshot Trigger Tests`, `Automation API Schemas`, `Vulnerability Snapshot Processing`, `Scanner Task API`, `Runtime Configuration`, `API Error Handling`, `Database Bootstrap`, `Diagnostic Sessions`, `Scanner Payload Tests`, `ScanPostprocessCancelled Components`, `Asset API Schemas`, `Connection Token Tests`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Why does `AutomationService` connect `Automation Service` to `Automation Repository`, `Automation API Schemas`, `Runtime Configuration`?**
  _High betweenness centrality (0.020) - this node is a cross-community bridge._
- **Why does `OperationRunner` connect `Runtime Configuration` to `Thread Pool Utilities`, `VM Workflow Service`, `Cancellation Registry`, `VM Workflow Repository`, `Service Repository Bundle`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `connect()` (e.g. with `DiagnosticConnection` and `DiagnosticCursor`) actually correct?**
  _`connect()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 27 inferred relationships involving `i()` (e.g. with `b()` and `Ci()`) actually correct?**
  _`i()` has 27 INFERRED edges - model-reasoned connections that need verification._