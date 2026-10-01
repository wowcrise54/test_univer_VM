"""Attention, search and compliance contracts against disposable PostgreSQL."""

from datetime import UTC, date, datetime, timedelta

import pytest

from app import db
from app.automations.repository import AutomationRepository
from app.repositories.attention import AttentionRepository, encode_cursor
from app.repositories.compliance import ComplianceRepository
from app.services.compliance import ComplianceService

pytestmark = pytest.mark.integration
ASSESSMENT = date(2026, 1, 31)
ALL_PERMISSIONS = {
    "assets.read",
    "asset_cards.read",
    "tasks.read",
    "remediation.read",
    "operations.read",
    "automations.read",
}


def _card(conn, asset_id, name, last_seen, *, ip="192.0.2.1", asset_type="Server"):
    conn.execute(
        "INSERT INTO asset_cards(asset_id,display_name,ip_address,asset_type,first_seen,last_seen) VALUES(%s,%s,%s,%s,%s,%s)",
        (asset_id, name, ip, asset_type, db.now_utc(), last_seen),
    )


def _finding(conn, asset_id, source, key, *, severity="critical", cvss=10):
    group = conn.execute(
        """INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at)
           VALUES(%s,%s,'os',%s,0,%s) ON CONFLICT(asset_id,source_type,collection_id)
           DO UPDATE SET updated_at=EXCLUDED.updated_at RETURNING id""",
        (asset_id, source, source, db.now_utc()),
    ).fetchone()
    return conn.execute(
        """INSERT INTO asset_card_vulnerabilities(asset_id,group_id,vulnerability_id,cve_name,name,severity,cvss_score,updated_at)
           VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (asset_id, group["id"], key, f"CVE-{key}", f"app vulnerability {key}", severity, cvss, db.now_utc()),
    ).fetchone()["id"]


@pytest.fixture
def attention_data(test_db):
    now = datetime.now(UTC)
    with db.connect() as conn:
        _card(conn, "healthy", "app healthy", now.isoformat())
        _card(conn, "stale", "app stale", (now - timedelta(days=30)).isoformat())
        conn.execute(
            "INSERT INTO assets(asset_key,mp_asset_id,fqdn,first_seen,last_seen) VALUES('missing','missing','app missing',%s,%s)",
            (now.isoformat(), now.isoformat()),
        )
        for key, severity, owner, due, status in (
            ("critical", "critical", "Alice", now - timedelta(days=1), "open"),
            ("high", "high", "Bob", now + timedelta(days=1), "in_progress"),
            ("medium", "medium", "Alice", now - timedelta(days=1), "open"),
            ("low", "low", "Bob", None, "open"),
            ("resolved", "critical", "Alice", now - timedelta(days=1), "resolved"),
        ):
            conn.execute(
                "INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,title,severity,assignee,due_at,status) VALUES(%s,'healthy',%s,%s,%s,%s,%s,%s)",
                (f"app-{key}", key, f"app {key}", severity, owner, due, status),
            )
        for key, deleted in (("active", None), ("deleted", now.isoformat())):
            conn.execute(
                "INSERT INTO scan_tasks(mp_task_id,name,payload_json,created_at,updated_at,deleted_at) VALUES(%s,%s,'{}',%s,%s,%s)",
                (f"app-{key}", f"app {key}", now.isoformat(), now.isoformat(), deleted),
            )
        finding = _finding(conn, "healthy", "os", "test")
    db.register_operation(
        "app-retry",
        kind="asset_card_build",
        source_id="app-retry",
        subject_id="healthy",
        subject_label="app retry",
        status="failed",
        message="Build failed",
    )
    db.register_operation(
        "app-interrupted",
        kind="scan",
        source_id="app-interrupted",
        subject_label="app interrupted",
        status="interrupted",
    )
    db.register_operation("app-completed", kind="scan", source_id="app-completed", status="completed")
    repository = AutomationRepository()
    definition = {"steps": [{"step_id": "query", "type": "asset_query", "config": {}}]}
    runbook = repository.create_runbook(name="app runbook", description="", definition=definition)
    run = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=definition,
        trigger_type="manual",
        dry_run=True,
        status="completed_with_warnings",
    )
    return {"repository": AttentionRepository(), "run_id": run["run_id"], "finding": str(finding)}


def test_attention_priorities_reasons_retry_and_cursor_pagination(attention_data):
    repository = attention_data["repository"]
    page = repository.attention(permissions=ALL_PERMISSIONS, limit=2, cursor=None)
    assert page["total"] == 10
    items = list(page["items"])
    while page["next_cursor"]:
        page = repository.attention(permissions=ALL_PERMISSIONS, limit=2, cursor=page["next_cursor"])
        assert page["total"] == 10
        items.extend(page["items"])
    assert len({(item["type"], item["id"]) for item in items}) == 10
    assert items[0]["id"] == "app-critical" and items[0]["priority"] == "critical"
    cases = {item["id"]: item for item in items if item["type"] == "case"}
    assert cases["app-medium"]["priority"] == "high" and cases["app-medium"]["reason"] == "SLA просрочен"
    assert cases["app-low"]["priority"] == "medium" and cases["app-low"]["due_at"] is None
    assert cases["app-high"]["reason"] == "Открытый remediation-кейс"
    operations = {item["id"]: item for item in items if item["type"] == "operation"}
    assert operations["app-retry"]["can_retry"] and operations["app-retry"]["action"] == "retry"
    assert operations["app-retry"]["reason"] == "Build failed"
    assert (
        not operations["app-interrupted"]["can_retry"] and operations["app-interrupted"]["action"] == "open_operation"
    )
    coverage = {item["id"]: item["reason"] for item in items if item["type"] == "coverage"}
    assert coverage == {
        "healthy": "Последнее обновление завершилось ошибкой",
        "stale": "Карточка устарела",
        "missing": "Карточка отсутствует",
    }
    automation = next(item for item in items if item["type"] == "automation")
    assert automation["id"] == attention_data["run_id"] and automation["title"] == "app runbook"


@pytest.mark.parametrize(
    "permissions,types,total",
    [
        (set(), set(), 0),
        ({"assets.read"}, set(), 0),
        ({"asset_cards.read"}, set(), 0),
        ({"assets.read", "asset_cards.read"}, {"coverage"}, 3),
        ({"remediation.read"}, {"case"}, 4),
        ({"operations.read"}, {"operation"}, 2),
        ({"automations.read"}, {"automation"}, 1),
    ],
)
def test_attention_permissions_limit_every_source(attention_data, permissions, types, total):
    result = attention_data["repository"].attention(permissions=permissions, limit=50, cursor=None)
    assert result["total"] == total
    assert {item["type"] for item in result["items"]} == types


def test_attention_owner_and_filters_are_applied_before_pagination(attention_data):
    repository = attention_data["repository"]
    result = repository.attention(
        permissions=ALL_PERMISSIONS, owner="aLiCe", kind="case", priority="high", limit=1, cursor=None
    )
    assert result["total"] == 1 and result["items"][0]["id"] == "app-medium"
    assert result["next_cursor"] is None
    empty = repository.attention(
        permissions=ALL_PERMISSIONS, owner="Alice", kind="case", limit=1, cursor=encode_cursor(20)
    )
    assert empty == {"items": [], "total": 2, "next_cursor": None}


@pytest.mark.parametrize(
    "permission,kind,expected",
    [
        ("asset_cards.read", "asset", {"healthy", "stale"}),
        ("assets.read", "vulnerability", None),
        ("tasks.read", "task", {"app-active"}),
        ("remediation.read", "case", {"app-critical", "app-high", "app-medium", "app-low"}),
        ("operations.read", "operation", {"app-retry", "app-interrupted", "app-completed"}),
    ],
)
def test_search_enforces_permissions_and_excludes_deleted_or_resolved_rows(attention_data, permission, kind, expected):
    repository = attention_data["repository"]
    result = repository.search(query=" APP ", kind=None, permissions={permission}, limit=50, cursor=None)
    assert {item["type"] for item in result["items"]} == {kind}
    assert {item["id"] for item in result["items"]} == (
        expected if expected is not None else {attention_data["finding"]}
    )
    assert result["next_cursor"] is None
    assert repository.search(query="app", kind=kind, permissions=set(), limit=50, cursor=None)["items"] == []


def test_search_paginated_order_and_explicit_kind(attention_data):
    repository = attention_data["repository"]
    full = repository.search(query="app", kind=None, permissions=ALL_PERMISSIONS, limit=50, cursor=None)["items"]
    assert len(full) == 11
    collected, cursor = [], None
    while True:
        page = repository.search(query="app", kind=None, permissions=ALL_PERMISSIONS, limit=3, cursor=cursor)
        collected.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert collected == full
    assert repository.search(query="app", kind="task", permissions=ALL_PERMISSIONS, limit=50, cursor=None)["items"] == [
        item for item in full if item["type"] == "task"
    ]
    assert (
        repository.search(query="app", kind=None, permissions=ALL_PERMISSIONS, limit=3, cursor=encode_cursor(50))[
            "items"
        ]
        == []
    )


def test_search_treats_wildcards_backslash_and_sql_metacharacters_as_literals(test_db):
    with db.connect() as conn:
        _card(conn, "literal", "node_%\\name", db.now_utc())
        _card(conn, "wildcard", "node-xxname", db.now_utc())
    repository = AttentionRepository()
    result = repository.search(query="node_%\\", kind="asset", permissions={"asset_cards.read"}, limit=50, cursor=None)
    assert [item["id"] for item in result["items"]] == ["literal"]
    assert (
        repository.search(query="' OR 1=1 --", kind=None, permissions=ALL_PERMISSIONS, limit=50, cursor=None)["items"]
        == []
    )


@pytest.fixture
def compliance_data(test_db):
    with db.connect() as conn:
        for asset, seen, ip, category in (
            ("fresh", "2025-12-01T00:00:00Z", "192.0.2.1", "Server"),
            ("stale", "2026-01-15T00:00:00Z", "192.0.2.2", "Laptop"),
            ("missing-date", "", None, None),
            ("internet", "2026-01-20T00:00:00Z", "10.255.1.1", "Appliance"),
        ):
            _card(conn, asset, asset, seen, ip=ip, asset_type=category)
            _finding(conn, asset, "os", "shared")
        for asset, scanned in (("fresh", "2026-01-15T00:00:00Z"), ("stale", "2025-12-01T00:00:00Z")):
            conn.execute(
                "INSERT INTO asset_scan_evidence(asset_id,postprocess_run_id,mp_task_id,scanned_at) VALUES(%s,'postprocess','task',%s)",
                (asset, scanned),
            )
        _finding(conn, "fresh", "os", "shared")
        _finding(conn, "fresh", "software", "shared", cvss=9)
        _finding(conn, "fresh", "os", "low", severity="low", cvss=2)
    return ComplianceService(ComplianceRepository())


def test_compliance_uses_scan_evidence_for_freshness_and_deduplicates_findings(compliance_data):
    dataset = compliance_data.report_dataset(scope="organization", assessment_date=ASSESSMENT)
    assert dataset.summary["assets_total"] == 3 and dataset.summary["fresh_assets"] == 1
    assert dataset.summary["stale_assets"] == 2 and dataset.summary["critical_findings"] == 2
    assert dataset.summary["unique_vulnerabilities"] == 1 and dataset.summary["affected_assets"] == 1
    assert dataset.summary["by_asset_category"] == {"server": 1, "user_device": 1, "unclassified": 1}
    assert dataset.diagnostics == {"invalid_or_missing_ip": 1}
    assert {item["source_type"] for item in dataset.findings} == {"os", "software"}
    assets = {item["asset_id"]: item for item in dataset.assets}
    assert (
        assets["fresh"]["scan_at"] == "2026-01-15T00:00:00+00:00"
        and assets["fresh"]["scan_date_source"] == "scan_completed"
    )
    assert assets["stale"]["age_days"] == 61 and not assets["stale"]["is_fresh"]
    assert assets["missing-date"]["freshness_reason"] == "missing_scan_date"
    assert compliance_data.summary(scope="organization", assessment_date=ASSESSMENT) == dataset.summary
    internet = compliance_data.report_dataset(scope="internet", assessment_date=ASSESSMENT)
    assert [item["asset_id"] for item in internet.assets] == ["internet"]
    assert internet.summary["critical_findings"] == 1


@pytest.mark.parametrize(
    "ids,expected",
    [
        (["fresh", "fresh", "internet"], {"fresh"}),
        (["absent"], set()),
        ([], {"fresh", "stale", "missing-date"}),
    ],
)
def test_compliance_selection_deduplicates_asset_ids_and_respects_scope(compliance_data, ids, expected):
    result = compliance_data.report_dataset(scope="organization", assessment_date=ASSESSMENT, asset_ids=ids)
    assert {item["asset_id"] for item in result.assets} == expected


@pytest.mark.parametrize("direction,first_score", [("asc", 9), ("desc", 10)])
def test_compliance_sorting_pages_preserve_total_on_empty_page(compliance_data, direction, first_score):
    options = {"scope": "organization", "assessment_date": ASSESSMENT, "limit": 1, "sort_dir": direction}
    first = compliance_data.findings(**options)
    assert first["total"] == 2 and first["rows"][0]["cvss_score"] == first_score
    second = compliance_data.findings(**options, offset=1)
    assert second["total"] == 2 and second["rows"][0]["source_type"] != first["rows"][0]["source_type"]
    assert compliance_data.findings(**options, offset=20) == {"rows": [], "total": 2}
    stale = compliance_data.stale_assets(scope="organization", assessment_date=ASSESSMENT, sort_dir="asc")
    assert [item["asset_id"] for item in stale["rows"]] == ["stale", "missing-date"]
    assert stale["total"] == 2


@pytest.mark.parametrize(
    "method,options,message",
    [
        ("findings", {"sort_by": "invalid"}, "Unsupported sort field"),
        ("stale_assets", {"sort_dir": "invalid"}, "sort_dir must be asc or desc"),
    ],
)
def test_compliance_rejects_invalid_sort_options(compliance_data, method, options, message):
    with pytest.raises(ValueError, match=message):
        getattr(compliance_data, method)(scope="organization", assessment_date=ASSESSMENT, **options)
