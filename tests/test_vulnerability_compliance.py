from datetime import date
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app import db, main
from app.domain.compliance import (
    classify_asset_type,
    evaluate_freshness,
    is_internet_asset,
)
from app.repositories.compliance import build_compliance_dataset
from app.services.compliance import ComplianceService


def test_internet_scope_is_exact_10_255_slash_16():
    assert is_internet_asset("10.255.0.0") is True
    assert is_internet_asset("10.255.255.255") is True
    assert is_internet_asset("10.254.255.255") is False
    assert is_internet_asset("10.256.0.1") is False
    assert is_internet_asset(None) is False


def test_freshness_includes_exact_thirty_day_boundary():
    assessment = date(2026, 8, 25)
    boundary = evaluate_freshness("2026-07-26T00:00:00Z", assessment)
    stale = evaluate_freshness("2026-07-25T23:59:59Z", assessment)
    missing = evaluate_freshness(None, assessment)

    assert boundary.is_fresh is True
    assert boundary.age_days == 30
    assert stale.is_fresh is False
    assert stale.reason == "stale"
    assert missing.reason == "missing_scan_date"


def test_asset_type_is_not_inferred_from_hostname_or_os():
    assert classify_asset_type("Server") == "server"
    assert classify_asset_type("Workstation") == "user_device"
    assert classify_asset_type("Windows Server 2025") == "unclassified"
    assert classify_asset_type(None) == "unclassified"


def test_completed_scan_evidence_selects_only_completed_assets():
    class Result:
        rowcount = 2

    class Connection:
        def __init__(self):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, params):
            self.calls.append((sql, params))
            return Result()

    connection = Connection()
    with patch.object(db, "connect", return_value=connection):
        count = db.record_completed_scan_evidence(
            "postprocess-1",
            mp_task_id="task-1",
            scanned_at="2026-08-25T10:00:00+00:00",
        )

    sql, params = connection.calls[-1]
    assert count == 2
    assert "FROM scan_postprocess_items" in sql
    assert "status = 'completed'" in sql
    assert "ON CONFLICT (asset_id) DO UPDATE" in sql
    assert "EXCLUDED.scanned_at >= asset_scan_evidence.scanned_at" in sql
    assert params == (
        "postprocess-1",
        "task-1",
        "2026-08-25T10:00:00+00:00",
        "postprocess-1",
    )


def test_completed_postprocess_records_scan_evidence():
    client = MagicMock()
    claimed = {
        "run_id": "postprocess-1",
        "mp_task_id": "task-1",
        "started_from": "manual",
        "options": {},
        "cancel_requested": False,
    }
    monitoring = {
        "successful_job_count": 1,
        "total_job_count": 1,
        "scan_finished_at": "2026-08-25T09:00:00+00:00",
    }
    with (
        patch.object(main.db, "claim_scan_postprocess_run", return_value=claimed),
        patch.object(main, "MpVmClient", return_value=client),
        patch.object(main, "monitor_successful_scan_jobs", return_value=monitoring),
        patch.object(
            main.db,
            "refresh_scan_postprocess_counts",
            return_value={"completed_count": 1, "failed_count": 0},
        ),
        patch.object(main.db, "record_completed_scan_evidence") as evidence,
        patch.object(main.db, "update_scan_task_status"),
        patch.object(main.db, "finish_scan_postprocess_run"),
        patch.object(main, "capture_vulnerability_snapshot"),
        patch.object(main, "schedule_scan_docker_group_cleanup"),
    ):
        main.run_scan_postprocess(
            run_id="postprocess-1",
            auth=SimpleNamespace(),
            token="token",
        )

    evidence.assert_called_once_with(
        "postprocess-1",
        mp_task_id="task-1",
        scanned_at="2026-08-25T09:00:00+00:00",
    )


def test_dataset_separates_fresh_critical_findings_from_stale_assets():
    rows = [
        {
            "asset_id": "external-fresh",
            "display_name": "edge-1",
            "ip_address": "10.255.1.10",
            "asset_type": "Server",
            "scanned_at": "2026-08-20T10:00:00Z",
            "card_last_seen": "2026-08-20T10:00:00Z",
            "vulnerability_id": "vuln-1",
            "cve": "CVE-2026-0001",
            "vulnerability_name": "Critical issue",
            "severity": "critical",
            "cvss_score": 9.8,
            "source_type": "os",
        },
        {
            "asset_id": "external-fresh",
            "display_name": "edge-1",
            "ip_address": "10.255.1.10",
            "asset_type": "Server",
            "scanned_at": "2026-08-20T10:00:00Z",
            "card_last_seen": "2026-08-20T10:00:00Z",
            "vulnerability_id": "vuln-2",
            "severity": "high",
        },
        {
            "asset_id": "external-stale",
            "display_name": "edge-2",
            "ip_address": "10.255.1.11",
            "asset_type": "Workstation",
            "scanned_at": "2026-07-01T10:00:00Z",
            "card_last_seen": "2026-07-01T10:00:00Z",
            "vulnerability_id": "vuln-3",
            "severity": "critical",
        },
    ]

    dataset = build_compliance_dataset(
        rows,
        scope="internet",
        assessment_date=date(2026, 8, 25),
    )

    assert [row["asset_id"] for row in dataset.findings] == ["external-fresh"]
    assert [row["asset_id"] for row in dataset.stale_assets] == ["external-stale"]
    assert dataset.summary["critical_findings"] == 1
    assert dataset.summary["fresh_assets"] == 1


def test_organization_dataset_uses_asset_type_and_excludes_internet_scope():
    rows = [
        {"asset_id": "server", "ip_address": "10.1.0.1", "asset_type": "Server", "card_last_seen": "2026-08-20T10:00:00Z"},
        {"asset_id": "user", "ip_address": "10.1.0.2", "asset_type": "Laptop", "card_last_seen": "2026-08-20T10:00:00Z"},
        {"asset_id": "unknown", "ip_address": "10.1.0.3", "asset_type": "Router", "card_last_seen": "2026-08-20T10:00:00Z"},
        {"asset_id": "external", "ip_address": "10.255.1.1", "asset_type": "Server", "card_last_seen": "2026-08-20T10:00:00Z"},
    ]
    dataset = build_compliance_dataset(rows, scope="organization", assessment_date=date(2026, 8, 25))
    assert dataset.summary["by_asset_category"] == {
        "user_device": 1,
        "server": 1,
        "unclassified": 1,
    }
    assert {row["asset_id"] for row in dataset.assets} == {"server", "user", "unknown"}


def test_compliance_service_delegates_summary():
    repository = MagicMock()
    repository.summary.return_value = {"scope": "internet", "critical_findings": 2}
    service = ComplianceService(repository)
    result = service.summary(scope="internet", assessment_date=date(2026, 8, 25))
    assert result["critical_findings"] == 2
    repository.summary.assert_called_once_with(
        scope="internet",
        assessment_date=date(2026, 8, 25),
    )


def test_compliance_routes_are_registered():
    from app.api.routers import API_ROUTERS

    paths = {route.path for router in API_ROUTERS for route in router.routes}
    assert "/api/vulnerabilities/compliance/{scope}/summary" in paths
    assert "/api/vulnerabilities/compliance/{scope}/findings" in paths
    assert "/api/vulnerabilities/compliance/{scope}/stale-assets" in paths
    assert "/api/reports/vulnerabilities/compliance/{scope}/{report_format}" in paths
