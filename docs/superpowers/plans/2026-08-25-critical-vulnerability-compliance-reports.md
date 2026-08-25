# Critical Vulnerability Compliance Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build auditable dashboards and direct-download PDF/XLSX reports for fresh critical vulnerabilities in the `10.255.0.0/16` internet scope and organization user-device/server scope.

**Architecture:** Add a focused compliance domain module, persist per-asset scan evidence during existing scan postprocessing, and expose a repository/service pair through dedicated compliance routers. Reuse one immutable report dataset for dashboard totals, PDF, and XLSX so all formats describe the same assessment snapshot; generate binaries in memory and never persist them server-side.

**Tech Stack:** Python 3.12+, FastAPI 0.139, PostgreSQL/psycopg 3, Alembic, Pydantic 2, ReportLab, openpyxl, React 19, TanStack Query 5, Vitest, pytest/unittest.

## Global Constraints

- Internet scope is exactly `10.255.0.0/16`.
- Freshness window is exactly 30 calendar days; the cutoff date is inclusive.
- Primary scan date is completed scan evidence; `asset_cards.last_seen` is a labeled fallback.
- Missing or stale scan dates appear only in the stale section and never in compliant totals.
- Only normalized severity `critical` is included in finding totals and report details.
- Organization classification uses `asset_type` only; no hostname or OS inference.
- Report formats are exactly PDF and XLSX.
- Generated binaries are returned directly to the requesting user and are never stored server-side.
- Report access uses `imports_exports.read`; metadata-only audit records contain no vulnerability rows or binary content.
- Existing user changes in `.codex/config.toml` and `graphify-out/` must remain untouched.

---

## File Structure

- Create `app/domain/compliance.py`: pure CIDR, asset-type, date-source, and freshness rules.
- Create `app/repositories/compliance.py`: PostgreSQL queries and immutable assessment dataset assembly.
- Create `app/services/compliance.py`: dashboard pagination and report dataset orchestration.
- Create `app/reports/compliance.py`: PDF/XLSX renderers and safe worksheet-cell handling.
- Create `app/reports/fonts/DejaVuSans.ttf`: bundled Cyrillic regular font.
- Create `app/reports/fonts/DejaVuSans-Bold.ttf`: bundled Cyrillic bold font.
- Create `app/reports/fonts/LICENSE`: DejaVu font license text.
- Create `app/api/compliance.py`: dashboard and report HTTP contracts, downloads, and audit calls.
- Create `migrations/versions/20260825_0016_asset_scan_evidence.py`: durable asset-to-scan completion evidence.
- Create `src/features/vulnerabilities/ComplianceDashboard.jsx`: compliance tabs, KPIs, tables, and downloads.
- Create `src/features/vulnerabilities/useComplianceDashboard.js`: TanStack Query contracts and URL construction.
- Create `tests/test_vulnerability_compliance.py`: domain, repository, service, and API behavior.
- Create `tests/test_compliance_reports.py`: PDF/XLSX content and audit behavior.
- Create `src/test/vulnerability-compliance-dashboard.test.jsx`: frontend interaction and download coverage.
- Modify `app/db.py`: development-schema compatibility and scan-evidence upsert helper.
- Modify `app/main.py`: record scan evidence after a completed card build.
- Modify `app/repositories/bundle.py`: expose `ComplianceRepository`.
- Modify `app/services/bundle.py`: expose `ComplianceService`.
- Modify `app/api/routers.py`: register compliance routers.
- Modify `requirements.txt`: pin ReportLab and openpyxl.
- Modify `src/features/vulnerabilities/VulnerabilitiesDashboard.jsx`: add compliance workspace.
- Modify `src/features/vulnerabilities/index.jsx`: export the new component where needed.
- Modify `src/api/client.js`: use existing file-download helper for binary reports without changing its public contract.
- Modify `src/styles/vulnerabilities.css`: responsive compliance layout and print-neutral status styling.
- Modify `README.md`: document endpoints, scope, freshness, and direct-download behavior.

---

### Task 1: Pure Compliance Rules

**Files:**
- Create: `app/domain/compliance.py`
- Test: `tests/test_vulnerability_compliance.py`

**Interfaces:**
- Produces: `ComplianceScope = Literal["internet", "organization"]`.
- Produces: `AssetCategory = Literal["user_device", "server", "unclassified"]`.
- Produces: `freshness_cutoff(assessment_date: date) -> date`.
- Produces: `evaluate_freshness(scan_at: datetime | str | None, assessment_date: date) -> FreshnessResult`.
- Produces: `is_internet_asset(ip_address: str | None) -> bool`.
- Produces: `classify_asset_type(asset_type: str | None) -> AssetCategory`.

- [ ] **Step 1: Write failing boundary and classification tests**

```python
from datetime import date

from app.domain.compliance import (
    classify_asset_type,
    evaluate_freshness,
    is_internet_asset,
)


def test_internet_scope_is_exact_10_255_slash_16():
    assert is_internet_asset("10.255.0.0") is True
    assert is_internet_asset("10.255.255.255") is True
    assert is_internet_asset("10.254.255.255") is False
    assert is_internet_asset("10.256.0.1") is False
    assert is_internet_asset(None) is False


def test_freshness_includes_exact_thirty_day_boundary():
    assessment = date(2026, 8, 25)
    assert evaluate_freshness("2026-07-26T00:00:00Z", assessment).is_fresh is True
    assert evaluate_freshness("2026-07-25T23:59:59Z", assessment).is_fresh is False
    assert evaluate_freshness(None, assessment).reason == "missing_scan_date"


def test_asset_type_is_not_inferred_from_hostname_or_os():
    assert classify_asset_type("Server") == "server"
    assert classify_asset_type("Workstation") == "user_device"
    assert classify_asset_type("Windows Server 2025") == "unclassified"
    assert classify_asset_type(None) == "unclassified"
```

- [ ] **Step 2: Run the focused tests and confirm the module is missing**

Run: `pytest tests/test_vulnerability_compliance.py -v`

Expected: FAIL with `ModuleNotFoundError: app.domain.compliance`.

- [ ] **Step 3: Implement explicit pure rules and immutable result type**

```python
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from ipaddress import ip_address, ip_network
from typing import Literal

ComplianceScope = Literal["internet", "organization"]
AssetCategory = Literal["user_device", "server", "unclassified"]
INTERNET_NETWORK = ip_network("10.255.0.0/16")
FRESHNESS_DAYS = 30
SERVER_TYPES = {"server", "virtual server", "physical server"}
USER_DEVICE_TYPES = {"workstation", "desktop", "laptop", "user device"}


@dataclass(frozen=True)
class FreshnessResult:
    scan_at: datetime | None
    cutoff_at: datetime
    is_fresh: bool
    age_days: int | None
    reason: Literal["fresh", "stale", "missing_scan_date"]


def is_internet_asset(value: str | None) -> bool:
    try:
        return ip_address(str(value).strip()) in INTERNET_NETWORK
    except ValueError:
        return False


def classify_asset_type(value: str | None) -> AssetCategory:
    normalized = " ".join(str(value or "").strip().lower().split())
    if normalized in SERVER_TYPES:
        return "server"
    if normalized in USER_DEVICE_TYPES:
        return "user_device"
    return "unclassified"
```

Implement `evaluate_freshness` by parsing ISO strings into UTC, creating the inclusive cutoff at `00:00:00 UTC` on `assessment_date - 30 days`, and returning `FreshnessResult` without consulting the database.

- [ ] **Step 4: Run domain tests**

Run: `pytest tests/test_vulnerability_compliance.py -v`

Expected: PASS for CIDR, boundary, missing-date, and exact `asset_type` classification tests.

- [ ] **Step 5: Commit the domain rules**

```bash
git add app/domain/compliance.py tests/test_vulnerability_compliance.py
git commit -m "feat: add vulnerability compliance rules"
```

---

### Task 2: Persist Completed Scan Evidence

**Files:**
- Create: `migrations/versions/20260825_0016_asset_scan_evidence.py`
- Modify: `app/db.py`
- Modify: `app/main.py`
- Test: `tests/test_scan_postprocess.py`
- Test: `tests/test_vulnerability_compliance.py`

**Interfaces:**
- Consumes: `asset_id`, `postprocess_run_id`, `mp_task_id`, and `scan_finished_at` already available in scan postprocessing.
- Produces: `db.record_completed_scan_evidence(postprocess_run_id: str, *, mp_task_id: str, scanned_at: str) -> int`.
- Produces table: `asset_scan_evidence(asset_id PRIMARY KEY, postprocess_run_id, mp_task_id, scanned_at, updated_at)`.

- [ ] **Step 1: Write failing persistence tests**

```python
def test_completed_scan_evidence_upsert_keeps_latest_completion(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(db, "connect", lambda: connection)
    db.record_completed_scan_evidence(
        "run-2",
        mp_task_id="task-1",
        scanned_at="2026-08-25T10:00:00+00:00",
    )
    sql, params = connection.execute_calls[-1]
    assert "FROM scan_postprocess_items" in sql
    assert "status = 'completed'" in sql
    assert "ON CONFLICT (asset_id) DO UPDATE" in sql
    assert "EXCLUDED.scanned_at >= asset_scan_evidence.scanned_at" in sql
    assert params == ("run-2", "task-1", "2026-08-25T10:00:00+00:00", "run-2")


def test_completed_postprocess_records_evidence_for_completed_items():
    auth = SimpleNamespace()
    with (
        patch.object(main.db, "claim_scan_postprocess_run", return_value={
            "run_id": "postprocess-1",
            "mp_task_id": "task-1",
            "started_from": "manual",
            "options": {},
            "cancel_requested": False,
        }),
        patch.object(main, "MpVmClient", return_value=MagicMock()),
        patch.object(main, "monitor_successful_scan_jobs", return_value={
            "successful_job_count": 1,
            "total_job_count": 1,
            "scan_finished_at": "2026-08-25T09:00:00+00:00",
        }),
        patch.object(main.db, "refresh_scan_postprocess_counts", return_value={
            "completed_count": 1,
            "failed_count": 0,
        }),
        patch.object(main.db, "record_completed_scan_evidence") as evidence,
        patch.object(main.db, "update_scan_task_status"),
        patch.object(main.db, "finish_scan_postprocess_run"),
        patch.object(main, "capture_vulnerability_snapshot"),
        patch.object(main, "schedule_scan_docker_group_cleanup"),
    ):
        main.run_scan_postprocess(run_id="postprocess-1", auth=auth, token="token")
    evidence.assert_called_once_with(
        "postprocess-1",
        mp_task_id="task-1",
        scanned_at="2026-08-25T09:00:00+00:00",
    )
```

Use the existing successful asset-processing fixture in `tests/test_scan_postprocess.py`; pass its concrete arguments instead of introducing a second fake workflow.

- [ ] **Step 2: Run the focused tests and verify the helper is absent**

Run: `pytest tests/test_scan_postprocess.py tests/test_vulnerability_compliance.py -v`

Expected: FAIL because `upsert_asset_scan_evidence` and the table are absent.

- [ ] **Step 3: Add migration and development schema compatibility**

```sql
CREATE TABLE IF NOT EXISTS asset_scan_evidence (
    asset_id TEXT PRIMARY KEY REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
    postprocess_run_id TEXT NOT NULL,
    mp_task_id TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_scan_evidence_scanned_at
    ON asset_scan_evidence(scanned_at DESC);
```

Add the equivalent `CREATE TABLE IF NOT EXISTS` and index entries to `app/db.py` so direct `db.init_db()` test setups remain compatible with Alembic-managed installations.

- [ ] **Step 4: Implement latest-only upsert**

```python
def record_completed_scan_evidence(postprocess_run_id, *, mp_task_id, scanned_at):
    with connect() as conn:
        result = conn.execute(
            """
            INSERT INTO asset_scan_evidence (
                asset_id, postprocess_run_id, mp_task_id, scanned_at, updated_at
            )
            SELECT DISTINCT asset_id, %s, %s, %s, NOW()
            FROM scan_postprocess_items
            WHERE postprocess_run_id = %s
              AND status = 'completed'
              AND NULLIF(asset_id, '') IS NOT NULL
            ON CONFLICT (asset_id) DO UPDATE SET
                postprocess_run_id = EXCLUDED.postprocess_run_id,
                mp_task_id = EXCLUDED.mp_task_id,
                scanned_at = EXCLUDED.scanned_at,
                updated_at = NOW()
            WHERE EXCLUDED.scanned_at >= asset_scan_evidence.scanned_at
            """,
            (postprocess_run_id, mp_task_id, scanned_at, postprocess_run_id),
        )
    return int(result.rowcount or 0)
```

- [ ] **Step 5: Record evidence only after successful card persistence**

In `run_scan_postprocess`, call the helper after `monitor_successful_scan_jobs` returns `scan_finished_at` and after `refresh_scan_postprocess_counts` confirms at least one completed item. The helper's `INSERT ... SELECT` records only items already marked `completed`, so `build_failed`, `removal_failed`, and cancelled items are excluded.

- [ ] **Step 6: Run migration and scan tests**

Run: `pytest tests/test_scan_postprocess.py tests/test_vulnerability_compliance.py -v`

Expected: PASS, including no evidence write on failed/cancelled processing.

- [ ] **Step 7: Commit scan evidence**

```bash
git add migrations/versions/20260825_0016_asset_scan_evidence.py app/db.py app/main.py tests/test_scan_postprocess.py tests/test_vulnerability_compliance.py
git commit -m "feat: retain asset scan completion evidence"
```

---

### Task 3: Compliance Repository and Dataset

**Files:**
- Create: `app/repositories/compliance.py`
- Modify: `app/repositories/bundle.py`
- Test: `tests/test_vulnerability_compliance.py`

**Interfaces:**
- Consumes: pure rules from `app.domain.compliance` and table `asset_scan_evidence`.
- Produces: `ComplianceRepository.dataset(scope: ComplianceScope, assessment_date: date, asset_ids: list[str] | None = None) -> ComplianceDataset`.
- Produces: `ComplianceRepository.summary(*, scope: ComplianceScope, assessment_date: date) -> dict[str, Any]`.
- Produces: `ComplianceRepository.findings(*, scope: ComplianceScope, assessment_date: date, limit: int, offset: int, sort_by: str, sort_dir: str) -> dict[str, Any]`.
- Produces: `ComplianceRepository.stale_assets(*, scope: ComplianceScope, assessment_date: date, limit: int, offset: int, sort_by: str, sort_dir: str) -> dict[str, Any]`.

- [ ] **Step 1: Write failing repository contract tests**

```python
def test_dataset_separates_fresh_critical_findings_from_stale_assets():
    repository = ComplianceRepository(connection_factory=lambda: FakeConnection([
        card("external-fresh", "10.255.1.10", "Server", scanned_at="2026-08-20", severity="critical"),
        card("external-high", "10.255.1.11", "Server", scanned_at="2026-08-20", severity="high"),
        card("external-stale", "10.255.1.12", "Workstation", scanned_at="2026-07-01", severity="critical"),
    ]))
    dataset = repository.dataset(scope="internet", assessment_date=date(2026, 8, 25))
    assert [row["asset_id"] for row in dataset.findings] == ["external-fresh"]
    assert [row["asset_id"] for row in dataset.stale_assets] == ["external-stale"]
    assert dataset.summary["critical_findings"] == 1


def test_organization_dataset_groups_only_by_asset_type():
    dataset = repository.dataset(scope="organization", assessment_date=date(2026, 8, 25))
    assert dataset.summary["by_asset_category"] == {
        "user_device": 1,
        "server": 1,
        "unclassified": 1,
    }
```

- [ ] **Step 2: Run repository tests and verify failure**

Run: `pytest tests/test_vulnerability_compliance.py -v`

Expected: FAIL because `ComplianceRepository` and `ComplianceDataset` do not exist.

- [ ] **Step 3: Implement a single base query and immutable dataset**

```python
@dataclass(frozen=True)
class ComplianceDataset:
    scope: ComplianceScope
    assessment_date: date
    generated_at: datetime
    summary: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    assets: tuple[dict[str, Any], ...]
    stale_assets: tuple[dict[str, Any], ...]
    diagnostics: dict[str, int]


class ComplianceRepository:
    def dataset(self, *, scope, assessment_date, asset_ids=None):
        rows = self._load_rows(asset_ids=asset_ids)
        return build_compliance_dataset(rows, scope=scope, assessment_date=assessment_date)
```

The base SQL must join `asset_cards`, `asset_scan_evidence`, `asset_card_vulnerability_groups`, and `asset_card_vulnerabilities`; normalize severity with the existing `_normalized_severity` expression; and expose both `evidence.scanned_at` and `card.last_seen`. Fetch each asset's card even when it has no findings so coverage totals remain correct. Deduplicate findings by the existing vulnerability selector rules.

- [ ] **Step 4: Apply scope, date source, freshness, and pagination once**

Use `is_internet_asset` for `internet`; use the complement for `organization`. Select `scan_at = evidence.scanned_at or card.last_seen` and `scan_date_source = "scan_completed"` or `"asset_card_last_seen"`. Build `assets`, `findings`, and `stale_assets` from the same normalized rows, then paginate copies in `findings()` and `stale_assets()` so dashboard and reports share totals.

- [ ] **Step 5: Register repository bundle interface**

```python
from .compliance import ComplianceRepository

class RepositoryBundle:
    def __init__(self) -> None:
        # existing repositories remain unchanged
        self.compliance = ComplianceRepository()
```

- [ ] **Step 6: Run repository tests**

Run: `pytest tests/test_vulnerability_compliance.py -v`

Expected: PASS for scope, freshness, fallback, critical-only, category, coverage, sorting, and pagination cases.

- [ ] **Step 7: Commit repository dataset**

```bash
git add app/repositories/compliance.py app/repositories/bundle.py tests/test_vulnerability_compliance.py
git commit -m "feat: query vulnerability compliance datasets"
```

---

### Task 4: Compliance Service and Dashboard API

**Files:**
- Create: `app/services/compliance.py`
- Create: `app/api/compliance.py`
- Modify: `app/services/bundle.py`
- Modify: `app/api/routers.py`
- Test: `tests/test_vulnerability_compliance.py`
- Modify: `tests/test_architecture.py`

**Interfaces:**
- Consumes: `ComplianceRepository` methods from Task 3.
- Produces: `ComplianceService.summary`, `findings`, `stale_assets`, and `report_dataset`.
- Produces routes under `/api/vulnerabilities/compliance/{scope}`.

- [ ] **Step 1: Write failing API validation and response tests**

```python
def test_compliance_summary_passes_assessment_date_to_service(client, service):
    service.summary.return_value = {"scope": "internet", "critical_findings": 2}
    response = client.get(
        "/api/vulnerabilities/compliance/internet/summary",
        params={"assessment_date": "2026-08-25"},
    )
    assert response.status_code == 200
    service.summary.assert_called_once_with(scope="internet", assessment_date=date(2026, 8, 25))


def test_compliance_rejects_unknown_scope(client):
    response = client.get(
        "/api/vulnerabilities/compliance/unknown/summary",
        params={"assessment_date": "2026-08-25"},
    )
    assert response.status_code == 422
```

- [ ] **Step 2: Run API tests and verify missing routes**

Run: `pytest tests/test_vulnerability_compliance.py tests/test_architecture.py -v`

Expected: FAIL with `404` and missing architecture route declarations.

- [ ] **Step 3: Implement service delegation and stable defaults**

```python
class ComplianceService:
    def __init__(self, repository: ComplianceRepository) -> None:
        self._repository = repository

    def summary(self, *, scope: ComplianceScope, assessment_date: date) -> dict[str, Any]:
        return self._repository.summary(scope=scope, assessment_date=assessment_date)

    def report_dataset(self, *, scope, assessment_date, asset_ids=None) -> ComplianceDataset:
        return self._repository.dataset(
            scope=scope, assessment_date=assessment_date, asset_ids=asset_ids
        )
```

Register `self.compliance = ComplianceService(repositories.compliance)` in `ServiceBundle`.

- [ ] **Step 4: Implement dashboard routers**

```python
dashboard_router = APIRouter(
    prefix="/api/vulnerabilities/compliance", tags=["vulnerability-compliance"]
)

@dashboard_router.get("/{scope}/summary")
def compliance_summary(
    scope: ComplianceScope,
    request: Request,
    assessment_date: date = Query(default_factory=date.today),
) -> dict:
    return request.app.state.container.services.compliance.summary(
        scope=scope, assessment_date=assessment_date
    )
```

Add equivalent `findings` and `stale-assets` routes with `limit` 1..500, nonnegative `offset`, and explicit sort fields. Convert service `ValueError` to `422` with a stable `INVALID_COMPLIANCE_QUERY` code.

- [ ] **Step 5: Register the dashboard router and architecture contract**

Import `dashboard_router` in `app/api/routers.py` and add it to `API_ROUTERS`. Add the three dashboard route templates (`summary`, `findings`, and `stale-assets`) to `tests/test_architecture.py`.

- [ ] **Step 6: Run API and architecture tests**

Run: `pytest tests/test_vulnerability_compliance.py tests/test_architecture.py -v`

Expected: PASS for summary, findings, stale assets, defaults, pagination, sort validation, and route registration.

- [ ] **Step 7: Commit service and dashboard API**

```bash
git add app/services/compliance.py app/services/bundle.py app/api/compliance.py app/api/routers.py tests/test_vulnerability_compliance.py tests/test_architecture.py
git commit -m "feat: expose vulnerability compliance dashboard API"
```

---

### Task 5: PDF/XLSX Rendering and Audited Downloads

**Files:**
- Create: `app/reports/__init__.py`
- Create: `app/reports/compliance.py`
- Modify: `app/api/compliance.py`
- Modify: `app/api/routers.py`
- Modify: `requirements.txt`
- Modify: `requirements-dev.txt`
- Test: `tests/test_compliance_reports.py`
- Modify: `tests/test_architecture.py`

**Interfaces:**
- Consumes: `ComplianceDataset` from Task 3 and `ComplianceService.report_dataset` from Task 4.
- Produces: `render_compliance_pdf(dataset: ComplianceDataset) -> bytes`.
- Produces: `render_compliance_xlsx(dataset: ComplianceDataset) -> bytes`.
- Produces route: `POST /api/reports/vulnerabilities/compliance/{scope}/{format}`.

- [ ] **Step 1: Pin document dependencies**

Add:

```text
reportlab==4.4.4
openpyxl==3.1.5
```

Add to `requirements-dev.txt`:

```text
pypdf==6.1.1
```

Run: `pip install -r requirements.txt`

Expected: dependencies install without changing unrelated packages.

- [ ] **Step 2: Write failing renderer tests**

```python
def test_xlsx_contains_required_sheets_and_safe_cells(dataset):
    content = render_compliance_xlsx(dataset_with_title("=DANGEROUS"))
    workbook = load_workbook(BytesIO(content), data_only=False)
    assert workbook.sheetnames == [
        "Сводка", "Критические уязвимости", "Активы", "Не соответствует свежести"
    ]
    assert workbook["Критические уязвимости"]["F2"].value == "'=DANGEROUS"


def test_pdf_is_parseable_and_contains_freshness_warning(dataset):
    content = render_compliance_pdf(dataset)
    assert content.startswith(b"%PDF-")
    text = extract_pdf_text(content)
    assert "Не соответствует требованиям по свежести" in text
    assert "10.255.0.0/16" in text
```

Use `pypdf` only in `requirements-dev.txt` for text assertions; production generation remains ReportLab.

- [ ] **Step 3: Implement safe XLSX renderer**

```python
def safe_sheet_cell(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def render_compliance_xlsx(dataset):
    workbook = Workbook(write_only=False)
    # create exactly four named sheets, append typed rows, freeze row 1,
    # set auto_filter.ref, widths, date formats, and critical/stale status fills
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()
```

Populate every sheet from the same `dataset` object. Do not rerun repository queries inside a renderer.

- [ ] **Step 4: Implement paginated PDF renderer**

Use ReportLab Platypus `SimpleDocTemplate`, `Paragraph`, `Table`, `TableStyle`, and `PageTemplate`. Add DejaVu Sans regular and bold TTF files plus the DejaVu license under `app/reports/fonts/`, and register both fonts by absolute path derived from `Path(__file__).parent`. Repeat table headers, wrap long cells with `Paragraph`, add page numbers, and render a visible incompleteness warning whenever `dataset.stale_assets` or unclassified organization assets are nonempty.

- [ ] **Step 5: Write failing download and audit tests**

```python
def test_report_download_returns_binary_without_writing_server_file(client, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    response = client.post(
        "/api/reports/vulnerabilities/compliance/internet/xlsx",
        json={"assessment_date": "2026-08-25", "asset_ids": []},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    assert list(tmp_path.iterdir()) == []


def test_report_audit_contains_metadata_not_findings(client, audit_event):
    client.post(
        "/api/reports/vulnerabilities/compliance/internet/pdf",
        json={"assessment_date": "2026-08-25", "asset_ids": []},
    )
    details = audit_event.call_args.kwargs["details"]
    assert details["scope"] == "internet"
    assert details["format"] == "pdf"
    assert "findings" not in details
```

- [ ] **Step 6: Implement report request and in-memory response**

```python
class ComplianceReportRequest(BaseModel):
    assessment_date: date = Field(default_factory=date.today)
    asset_ids: list[str] = Field(default_factory=list, max_length=5000)

    @field_validator("asset_ids")
    @classmethod
    def normalize_asset_ids(cls, values):
        result = []
        for value in values:
            asset_id = str(value).strip()
            if asset_id and asset_id not in result:
                result.append(asset_id)
        return result


MEDIA_TYPES = {
    "pdf": "application/pdf",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
RENDERERS = {"pdf": render_compliance_pdf, "xlsx": render_compliance_xlsx}


def compliance_report_filename(scope, format, assessment_date):
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"critical_vulnerabilities_{scope}_{assessment_date:%Y%m%d}_{timestamp}.{format}"


def report_audit_details(dataset, format, *, elapsed_ms):
    return {
        "scope": dataset.scope,
        "format": format,
        "assessment_date": dataset.assessment_date.isoformat(),
        "fresh_findings": len(dataset.findings),
        "stale_assets": len(dataset.stale_assets),
        "elapsed_ms": elapsed_ms,
    }


def audited_binary_stream(content, *, request, user, details):
    outcome = "interrupted"
    try:
        yield content
        outcome = "success"
    except Exception:
        outcome = "error"
        raise
    finally:
        app_auth.audit_event(
            request=request,
            user=user,
            event_type="compliance_report_generated",
            decision="allow" if outcome == "success" else "deny",
            permission_key="imports_exports.read",
            target_type="report",
            target_id=f"{details['scope']}:{details['format']}",
            details={**details, "outcome": outcome},
        )


@report_router.post("/{scope}/{format}")
def download_compliance_report(scope, format, payload, request):
    started = time.perf_counter()
    dataset = _service(request).report_dataset(
        scope=scope,
        assessment_date=payload.assessment_date,
        asset_ids=payload.asset_ids,
    )
    content = RENDERERS[format](dataset)
    details = report_audit_details(
        dataset,
        format,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    filename = compliance_report_filename(scope, format, payload.assessment_date)
    return StreamingResponse(
        audited_binary_stream(
            content,
            request=request,
            user=getattr(request.state, "user", None),
            details=details,
        ),
        media_type=MEDIA_TYPES[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

Define `report_router = APIRouter(prefix="/api/reports/vulnerabilities/compliance", tags=["vulnerability-compliance-reports"])`, register it in `app/api/routers.py`, and add `/api/reports/vulnerabilities/compliance/{scope}/{format}` to `tests/test_architecture.py`. Catch renderer exceptions before constructing the response, write a deny/error audit record, and return the existing structured `500` operator message. `audited_binary_stream` writes `success` only after the response iterator completes and records `interrupted` when Starlette closes the iterator early. Do not log dataset rows.

- [ ] **Step 7: Run report tests**

Run: `pytest tests/test_compliance_reports.py tests/test_vulnerability_compliance.py tests/test_auth.py -v`

Expected: PASS for PDF text, XLSX sheets/types/formula safety, filenames, RBAC, metadata-only audit, empty datasets, and no server artifacts.

- [ ] **Step 8: Commit report generation**

```bash
git add requirements.txt requirements-dev.txt app/reports app/api/compliance.py app/api/routers.py tests/test_compliance_reports.py tests/test_vulnerability_compliance.py tests/test_architecture.py
git commit -m "feat: generate compliance PDF and XLSX reports"
```

---

### Task 6: Compliance Query Hook and Dashboard Component

**Files:**
- Create: `src/features/vulnerabilities/useComplianceDashboard.js`
- Create: `src/features/vulnerabilities/ComplianceDashboard.jsx`
- Modify: `src/features/vulnerabilities/VulnerabilitiesDashboard.jsx`
- Modify: `src/features/vulnerabilities/index.jsx`
- Test: `src/test/vulnerability-compliance-dashboard.test.jsx`

**Interfaces:**
- Consumes: Task 4 dashboard endpoints and Task 5 report endpoint.
- Produces: `useComplianceDashboard({scope, assessmentDate, findingsOffset, staleOffset})`.
- Produces: `ComplianceDashboard({showAlert})`.

- [ ] **Step 1: Write failing data-loading and scope tests**

```jsx
it("loads internet compliance using the selected assessment date", async () => {
  renderDashboard();
  fireEvent.change(screen.getByLabelText("Дата оценки"), {
    target: { value: "2026-08-25" },
  });
  fireEvent.click(screen.getByRole("tab", { name: "Внешний контур" }));
  await waitFor(() => expect(api).toHaveBeenCalledWith(
    "/api/vulnerabilities/compliance/internet/summary?assessment_date=2026-08-25",
  ));
  expect(screen.getByText("10.255.0.0/16")).toBeInTheDocument();
});

it("shows stale assets separately from fresh findings", async () => {
  renderDashboardWithResponses();
  expect(await screen.findByText("CVE-2026-1001")).toBeInTheDocument();
  expect(screen.getByRole("heading", {
    name: "Не соответствует требованиям по свежести",
  })).toBeInTheDocument();
  expect(screen.getByText("31 день")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run frontend tests and verify missing component**

Run: `npm test -- --run src/test/vulnerability-compliance-dashboard.test.jsx`

Expected: FAIL because the hook/component does not exist.

- [ ] **Step 3: Implement stable query keys and pagination**

```javascript
export function useComplianceDashboard({
  scope,
  assessmentDate,
  findingsOffset,
  staleOffset,
  pageSize = 50,
}) {
  const common = { assessment_date: assessmentDate };
  return {
    summaryQuery: useQuery({
      queryKey: ["vulnerability-compliance-summary", scope, assessmentDate],
      queryFn: () => api(complianceUrl(scope, "summary", common)),
    }),
    findingsQuery: useQuery({
      queryKey: ["vulnerability-compliance-findings", scope, assessmentDate, findingsOffset],
      queryFn: () => api(complianceUrl(scope, "findings", {
        ...common, limit: pageSize, offset: findingsOffset,
      })),
      placeholderData: (previous) => previous,
    }),
    staleQuery: useQuery({
      queryKey: ["vulnerability-compliance-stale", scope, assessmentDate, staleOffset],
      queryFn: () => api(complianceUrl(scope, "stale-assets", {
        ...common, limit: pageSize, offset: staleOffset,
      })),
      placeholderData: (previous) => previous,
    }),
  };
}
```

- [ ] **Step 4: Implement the compliance workspace**

Add a third top-level workspace tab, `compliance`, beside existing current/resolved views. Render `ComplianceDashboard` only when selected so existing queries are not duplicated. Inside it, use semantic `role="tablist"` for `internet` and `organization`, a native date input, six compact KPIs, the fresh critical-findings table, and the stale-assets table. Reset both offsets when scope or date changes.

- [ ] **Step 5: Add organization category rendering**

Render `user_device`, `server`, and `unclassified` counts from the API. Use labels `Пользовательские устройства`, `Серверы`, and `Не классифицировано`; never derive category in JavaScript.

- [ ] **Step 6: Run frontend component tests**

Run: `npm test -- --run src/test/vulnerability-compliance-dashboard.test.jsx src/test/vulnerabilities-dashboard.test.jsx`

Expected: PASS and no requests to existing trend endpoints while the compliance workspace is active.

- [ ] **Step 7: Commit dashboard data flow**

```bash
git add src/features/vulnerabilities/useComplianceDashboard.js src/features/vulnerabilities/ComplianceDashboard.jsx src/features/vulnerabilities/VulnerabilitiesDashboard.jsx src/features/vulnerabilities/index.jsx src/test/vulnerability-compliance-dashboard.test.jsx
git commit -m "feat: add critical vulnerability compliance dashboard"
```

---

### Task 7: Direct Browser Downloads and Responsive Styling

**Files:**
- Modify: `src/features/vulnerabilities/ComplianceDashboard.jsx`
- Modify: `src/api/client.js`
- Modify: `src/styles/vulnerabilities.css`
- Test: `src/test/vulnerability-compliance-dashboard.test.jsx`

**Interfaces:**
- Consumes: existing `downloadApiFile(url, options)` and Task 5 report route.
- Produces: independent busy states `compliance-pdf` and `compliance-xlsx`.

- [ ] **Step 1: Write failing download interaction tests**

```jsx
it.each(["PDF", "XLSX"])("downloads %s for the active scope", async (format) => {
  renderDashboard();
  fireEvent.click(screen.getByRole("button", { name: `Скачать ${format}` }));
  await waitFor(() => expect(downloadApiFile).toHaveBeenCalledWith(
    `/api/reports/vulnerabilities/compliance/internet/${format.toLowerCase()}`,
    {
      method: "POST",
      body: JSON.stringify({ assessment_date: "2026-08-25", asset_ids: [] }),
    },
  ));
});

it("keeps PDF and XLSX busy states independent", () => {
  renderDashboard({ busyFormat: "pdf" });
  expect(screen.getByRole("button", { name: /PDF/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: /XLSX/ })).toBeEnabled();
});
```

- [ ] **Step 2: Run tests and confirm missing download behavior**

Run: `npm test -- --run src/test/vulnerability-compliance-dashboard.test.jsx`

Expected: FAIL because report buttons do not call `downloadApiFile`.

- [ ] **Step 3: Implement direct downloads and operator feedback**

Use the existing download helper without changing where the browser saves files. Keep independent local busy flags, show `Отчет скачан: <filename>` on success, and surface `operatorMessage` on failure. Do not create report history or server-file links.

- [ ] **Step 4: Add responsive, restrained compliance styles**

Add `.compliance-toolbar`, `.compliance-kpis`, `.compliance-table-wrap`, and `.compliance-status` styles. Reuse existing colors/tokens, keep card radius at the existing system value, use horizontal table scrolling below 900px, stack toolbar controls below 700px, and ensure button labels do not overflow at 360px.

- [ ] **Step 5: Run frontend tests, lint, and build**

Run: `npm test -- --run src/test/vulnerability-compliance-dashboard.test.jsx src/test/vulnerabilities-dashboard.test.jsx`

Run: `npm run lint`

Run: `npm run build`

Expected: all commands exit 0; the production build contains the new compliance workspace.

- [ ] **Step 6: Commit downloads and styling**

```bash
git add src/features/vulnerabilities/ComplianceDashboard.jsx src/api/client.js src/styles/vulnerabilities.css src/test/vulnerability-compliance-dashboard.test.jsx
git commit -m "feat: download compliance reports from dashboard"
```

---

### Task 8: Documentation and End-to-End Verification

**Files:**
- Modify: `README.md`
- Modify: `tests/e2e/shell.spec.js`
- Modify: `src/test/layout.test.jsx` only if the existing navigation contract requires the new workspace label.

**Interfaces:**
- Consumes: all previous tasks.
- Produces: documented operator workflow and verified production behavior.

- [ ] **Step 1: Add an E2E scenario for both scopes and both formats**

```javascript
test("operator reviews compliance freshness and downloads both formats", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await page.getByRole("tab", { name: "Контроль требований" }).click();
  await expect(page.getByText("10.255.0.0/16")).toBeVisible();
  await expect(page.getByRole("heading", {
    name: "Не соответствует требованиям по свежести",
  })).toBeVisible();
  await page.getByRole("button", { name: "Скачать PDF" }).click();
  await page.getByRole("tab", { name: "Пользовательские устройства и серверы" }).click();
  await page.getByRole("button", { name: "Скачать XLSX" }).click();
});
```

Mock API datasets and download responses in the existing `tests/e2e/shell.spec.js` route dispatcher; assert the organization tab displays all three asset categories.

- [ ] **Step 2: Document the operator workflow and API**

Add README sections describing:

```text
Внешний контур: 10.255.0.0/16
Окно свежести: 30 календарных дней включительно
Основная дата: завершение сканирования
Резервная дата: asset_cards.last_seen (явно маркируется)
Форматы: PDF и XLSX, прямое скачивание без хранения на сервере
Разрешение: imports_exports.read
```

List all dashboard and report endpoints with `scope`, `assessment_date`, pagination, and report request examples.

- [ ] **Step 3: Run backend regression suite**

Run: `pytest -q`

Expected: all backend tests pass, including compliance, authentication, reports, scan postprocessing, architecture, and migrations.

- [ ] **Step 4: Run frontend quality suite**

Run: `npm run quality`

Expected: lint, Vitest, and Vite build all exit 0.

- [ ] **Step 5: Run E2E scenario**

Run: `npx playwright test tests/e2e/shell.spec.js`

Expected: all shell workflows pass at configured desktop and mobile projects; downloads are observed without writing application-side report artifacts.

- [ ] **Step 6: Verify report artifacts programmatically**

Run:

```bash
pytest tests/test_compliance_reports.py -v
python -m compileall app
git diff --check
```

Expected: PDF/XLSX parse checks pass, Python compilation succeeds, and no whitespace errors are reported.

- [ ] **Step 7: Commit documentation and E2E coverage**

```bash
git add README.md tests/e2e/shell.spec.js src/test/layout.test.jsx
git commit -m "docs: document vulnerability compliance reporting"
```

---

## Final Acceptance Checklist

- [ ] Internet dashboard includes only assets whose valid IP is inside `10.255.0.0/16`.
- [ ] Organization dashboard categorizes only from `asset_type` and retains an unclassified group.
- [ ] Exactly-30-day scans are fresh; older and missing dates are stale.
- [ ] Completed scan evidence overrides the clearly labeled `last_seen` fallback.
- [ ] Fresh tables and totals include only normalized `critical` findings.
- [ ] Stale assets remain visible but are excluded from compliant totals.
- [ ] PDF and XLSX represent the same immutable dataset and contain required sections/sheets.
- [ ] Browser receives direct downloads; no generated report file exists on the server.
- [ ] Audit stores metadata and outcome without vulnerability rows or binary content.
- [ ] RBAC, backend, frontend, build, and E2E suites pass.
