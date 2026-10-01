from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app import db
from app.repositories.remediation import CoverageRepository, RemediationRepository


def _asset_with_finding(*, severity: str = "high", truncated: bool = False) -> None:
    current = db.now_utc()
    with db.connect() as conn:
        conn.execute("INSERT INTO remediation_sla_policy(policy_id) VALUES (1) ON CONFLICT DO NOTHING")
        conn.execute(
            """INSERT INTO asset_cards(asset_id, display_name, ip_address, fqdn, first_seen, last_seen)
               VALUES ('host-1', 'Host One', '192.0.2.1', 'host-1.example', %s, %s)""",
            (current, current),
        )
        group = conn.execute(
            """INSERT INTO asset_card_vulnerability_groups
               (asset_id, source_type, collection_type, collection_id, name,
                vulnerability_count, group_order, truncated, updated_at)
               VALUES ('host-1', 'os', 'os', 'os-1', 'Linux', 1, 0, %s, %s)
               RETURNING id""",
            (truncated, current),
        ).fetchone()
        conn.execute(
            """INSERT INTO asset_card_vulnerabilities
               (asset_id, group_id, vulnerability_instance_id, vulnerability_id,
                cve_name, name, severity, cvss_score, updated_at)
               VALUES ('host-1', %s, 'finding-1', 'vuln-1', 'CVE-2026-1234',
                       'Remote code execution', %s, 8.8, %s)""",
            (group["id"], severity, current),
        )


def test_reconciliation_respects_truncation_freshness_and_reopens_resolved_cases(test_db):
    repository = RemediationRepository()
    _asset_with_finding(truncated=True)
    assert repository.reconcile_asset("missing", stale_days=7) == {"created": 0, "reopened": 0, "resolved": 0}
    assert repository.reconcile_asset("host-1", stale_days=7) == {"created": 1, "reopened": 0, "resolved": 0}
    case = repository.list(status="open")["rows"][0]
    assert case["vulnerability_key"] == "id:vuln-1"
    assert case["title"] == "Remote code execution"
    assert case["cve"] == "CVE-2026-1234"
    assert case["severity"] == "high"
    assert case["due_at"] is not None
    assert repository.asset_ids() == ["host-1"]

    with db.connect() as conn:
        conn.execute("DELETE FROM asset_card_vulnerabilities WHERE asset_id='host-1'")
        conn.execute("UPDATE asset_card_vulnerability_groups SET truncated=TRUE WHERE asset_id='host-1'")
    assert repository.reconcile_asset("host-1", stale_days=7)["resolved"] == 0
    with db.connect() as conn:
        conn.execute("UPDATE asset_card_vulnerability_groups SET truncated=FALSE WHERE asset_id='host-1'")
        stale_at = (datetime.now(UTC) - timedelta(days=10)).isoformat()
        conn.execute("UPDATE asset_cards SET last_seen=%s WHERE asset_id='host-1'", (stale_at,))
    assert repository.reconcile_asset("host-1", stale_days=7)["resolved"] == 0
    with db.connect() as conn:
        conn.execute("UPDATE asset_cards SET last_seen=%s WHERE asset_id='host-1'", (db.now_utc(),))
    assert repository.reconcile_asset("host-1", stale_days=7) == {"created": 0, "reopened": 0, "resolved": 1}
    resolved = repository.get(case["case_id"])
    assert resolved["status"] == "resolved"
    assert resolved["version"] == case["version"] + 1
    assert resolved["events"][0]["event_type"] == "finding_absent"

    current = db.now_utc()
    with db.connect() as conn:
        group_id = conn.execute("SELECT id FROM asset_card_vulnerability_groups WHERE asset_id='host-1'").fetchone()[
            "id"
        ]
        conn.execute(
            """INSERT INTO asset_card_vulnerabilities
               (asset_id, group_id, vulnerability_instance_id, vulnerability_id,
                cve_name, name, severity, cvss_score, updated_at)
               VALUES ('host-1', %s, 'finding-2', 'vuln-1', 'CVE-2026-1234',
                       'Remote code execution', 'high', 8.8, %s)""",
            (group_id, current),
        )
    assert repository.reconcile_asset("host-1", stale_days=7) == {"created": 0, "reopened": 1, "resolved": 0}
    reopened = repository.get(case["case_id"])
    assert reopened["status"] == "open"
    assert reopened["resolved_at"] is None
    assert reopened["reopened_at"] is not None
    stats = repository.resolution_stats(days=30)
    assert stats["confirmed_resolutions"] == 1
    assert stats["currently_resolved"] == 0
    assert stats["recent"][0]["resolution_title"] == "Remote code execution"


def test_sla_recalculation_expired_exceptions_and_daily_digest_are_idempotent(test_db):
    repository = RemediationRepository()
    _asset_with_finding(severity="critical")
    assert repository.reconcile_asset("host-1", stale_days=7)["created"] == 1
    case = repository.list()["rows"][0]
    original_due = datetime.fromisoformat(case["due_at"])

    policy = repository.update_policy({"critical_days": 2}, apply_to_open=True)
    assert policy["critical_days"] == 2
    updated = repository.get(case["case_id"])
    assert updated["version"] == case["version"] + 1
    assert (
        timedelta(days=1, hours=23)
        < datetime.fromisoformat(updated["due_at"]) - datetime.now(UTC)
        < timedelta(days=2, minutes=1)
    )
    assert original_due > datetime.fromisoformat(updated["due_at"])
    assert updated["events"][0]["event_type"] == "policy_recalculated"

    with db.connect() as conn:
        conn.execute(
            """UPDATE remediation_cases SET status='risk_accepted', risk_reason='legacy reason',
               risk_expires_at=%s, exception_reason='accepted for test', exception_expires_at=%s
               WHERE case_id=%s""",
            (datetime.now(UTC) - timedelta(days=1), datetime.now(UTC) - timedelta(days=1), case["case_id"]),
        )
    assert repository.expire_risk_acceptances() == 1
    expired = repository.get(case["case_id"])
    assert expired["status"] == "open"
    assert expired["risk_reason"] is None
    assert expired["exception_reason"] is None
    assert expired["risk_expires_at"] is None
    assert expired["events"][0]["event_type"] == "exception_expired"
    assert repository.expire_risk_acceptances() == 0

    digest = {"open": 1, "overdue": 1, "near_due": 0}
    assert repository.ensure_daily_digest(webhook_enabled=True, summary=digest) is True
    assert repository.ensure_daily_digest(webhook_enabled=True, summary=digest) is False
    with db.connect() as conn:
        notification = conn.execute(
            "SELECT notification_id, details_json FROM notifications WHERE event_type='remediation.daily_digest'"
        ).fetchone()
        deliveries = conn.execute(
            "SELECT COUNT(*) AS count FROM webhook_deliveries WHERE notification_id=%s",
            (notification["notification_id"],),
        ).fetchone()["count"]
    assert notification["details_json"] == '{"open": 1, "overdue": 1, "near_due": 0}'
    assert deliveries == 1
    assert repository.ensure_daily_digest(webhook_enabled=False, summary={"open": 0}) is False


def test_coverage_inventory_classifies_assets_and_preserves_total_on_empty_page(test_db):
    current = db.now_utc()
    stale = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    with db.connect() as conn:
        for asset_id in ("healthy", "stale", "truncated", "failed", "missing"):
            conn.execute(
                "INSERT INTO assets(asset_key, mp_asset_id, ip_address, fqdn, first_seen, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (asset_id, asset_id, f"192.0.2.{len(asset_id)}", f"{asset_id}.example", current, current),
            )
        for asset_id, seen_at in (("healthy", current), ("stale", stale), ("truncated", current), ("failed", current)):
            conn.execute(
                """INSERT INTO asset_cards(asset_id, display_name, ip_address, fqdn, first_seen, last_seen)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (asset_id, asset_id, f"192.0.2.{len(asset_id)}", f"{asset_id}.example", current, seen_at),
            )
        conn.execute(
            """INSERT INTO asset_card_vulnerability_groups
               (asset_id, source_type, collection_type, collection_id, name, group_order, truncated, updated_at)
               VALUES ('truncated', 'os', 'os', 'os-1', 'Linux', 0, TRUE, %s)""",
            (current,),
        )
        conn.execute(
            """INSERT INTO operations(operation_id, kind, source_id, status, stage, subject_id, created_at, updated_at)
               VALUES ('failed-card-build', 'asset_card_build', 'failed-card-build', 'completed_with_errors',
                       'failed', 'failed', %s, %s)""",
            (current, current),
        )

    repository = CoverageRepository()
    summary = repository.summary(stale_days=7)
    assert summary == {
        "total_assets": 5,
        "healthy_assets": 1,
        "coverage_percent": 20.0,
        "missing_card": 1,
        "stale": 1,
        "truncated": 1,
        "last_refresh_failed": 1,
        "stale_days": 7,
    }
    assert repository.list_assets(stale_days=7, q="HEALTHY.EXAMPLE", issue=None, limit=10, offset=0)["total"] == 1
    for issue in ("missing", "stale", "truncated", "failed"):
        result = repository.list_assets(stale_days=7, q=None, issue=issue, limit=10, offset=0)
        assert result["total"] == 1
        field = {"missing": "missing_card", "failed": "last_refresh_failed"}.get(issue, issue)
        assert result["rows"][0][field] is True

    beyond_page = repository.list_assets(stale_days=7, q=None, issue=None, limit=2, offset=100)
    assert beyond_page["rows"] == []
    assert beyond_page["total"] == 5


def _start(repository, **options):
    return repository.start_for_finding(
        asset_id="host-1",
        vulnerability_key="id:vuln-1",
        **{"assignee": None, "due_at": None, "comment": None, "resume_exception": False, **options},
    )


@pytest.mark.parametrize("severity", ["critical", "medium", "low", "unknown"])
def test_start_finding_assigns_severity_sla_and_does_not_duplicate_an_active_case(test_db, severity):
    repository = RemediationRepository()
    _asset_with_finding(severity=severity)
    started = _start(repository)
    assert started["status"] == "in_progress"
    assert started["cvss_score"] == 8.8
    assert (started["due_at"] is None) is (severity == "unknown")
    if severity != "unknown":
        days = repository.policy()[f"{severity}_days"]
        remaining = datetime.fromisoformat(started["due_at"]) - datetime.now(UTC)
        assert timedelta(days=days) - timedelta(minutes=1) < remaining <= timedelta(days=days)
    replay = _start(repository)
    assert replay["case_id"] == started["case_id"]
    assert replay["version"] == started["version"]
    assert len(replay["events"]) == len(started["events"])


@pytest.mark.parametrize("status", ["risk_accepted", "false_positive"])
def test_start_requires_explicit_confirmation_before_resuming_an_exception(test_db, status):
    repository = RemediationRepository()
    _asset_with_finding()
    started = _start(repository)
    expiry = datetime.now(UTC) + timedelta(days=30)
    excepted = repository.update(
        started["case_id"],
        {
            "status": status,
            "exception_reason": "Validated temporary exception",
            "exception_expires_at": expiry,
            "risk_reason": "Legacy reason",
            "risk_expires_at": expiry,
        },
        expected_version=started["version"],
        comment="Reviewed",
    )
    if status == "risk_accepted":
        assert excepted["risk_reason"] == "Validated temporary exception"
        assert excepted["risk_expires_at"] == expiry.isoformat()
    with pytest.raises(ValueError, match="Explicit confirmation"):
        _start(repository)
    assert repository.get(started["case_id"])["version"] == excepted["version"]
    resumed = _start(repository, resume_exception=True, assignee="Operator")
    assert resumed["status"] == "in_progress"
    assert resumed["assignee"] == "Operator"
    assert resumed["version"] == excepted["version"] + 1
    assert all(
        resumed[field] is None
        for field in (
            "exception_reason",
            "exception_expires_at",
            "risk_reason",
            "risk_expires_at",
        )
    )
    assert resumed["events"][0]["old_status"] == status


@pytest.mark.parametrize("severity,manual", [("high", False), ("unknown", False), ("high", True)])
def test_start_reopens_a_resolved_finding_with_fresh_or_explicit_due_date(test_db, severity, manual):
    repository = RemediationRepository()
    _asset_with_finding(severity=severity)
    started = _start(repository)
    with db.connect() as conn:
        conn.execute(
            "UPDATE remediation_cases SET status='resolved', resolved_at=NOW(), due_at=NOW()-INTERVAL '1 day', "
            "manual_due=TRUE WHERE case_id=%s",
            (started["case_id"],),
        )
    due = datetime.now(UTC) + timedelta(days=3) if manual else None
    reopened = _start(repository, due_at=due)
    assert reopened["status"] == "in_progress"
    assert reopened["resolved_at"] is None
    assert reopened["reopened_at"] is not None
    assert reopened["manual_due"] is manual
    assert (reopened["due_at"] is None) is (severity == "unknown" and not manual)
    if manual:
        assert reopened["due_at"] == due.isoformat()
    elif severity != "unknown":
        assert datetime.fromisoformat(reopened["due_at"]) > datetime.now(UTC)
    assert any(event["event_type"] == "finding_reappeared" for event in reopened["events"])


def test_filters_empty_page_and_sla_changes_preserve_a_manual_due_date(test_db):
    repository = RemediationRepository()
    _asset_with_finding()
    due = datetime.now(UTC) - timedelta(days=1)
    started = _start(repository, assignee="Alice", due_at=due, comment="Urgent")
    filters = {"status": "in_progress", "severity": "high", "assignee": "ALICE", "overdue": True, "q": "cve-2026"}
    selected = repository.list(**filters)
    assert selected["total"] == 1
    assert selected["rows"][0]["case_id"] == started["case_id"]
    assert selected["rows"][0]["overdue"] is True
    for key, value in {"status": "open", "severity": "low", "assignee": "Bob", "q": "absent"}.items():
        assert repository.list(**{**filters, key: value}) == {"rows": [], "total": 0}
    assert repository.list(**filters, offset=100) == {"rows": [], "total": 1}
    repository.update_policy({"high_days": 1}, apply_to_open=False)
    repository.update_policy({"high_days": 2}, apply_to_open=True)
    retained = repository.get(started["case_id"])
    assert retained["due_at"] == due.isoformat()
    assert retained["version"] == started["version"]


def test_case_updates_check_versions_and_keep_comments_without_changing_fields(test_db):
    repository = RemediationRepository()
    _asset_with_finding()
    started = _start(repository)
    assert repository.update("missing", {"assignee": "Alice"}, expected_version=1, comment=None) is None
    with pytest.raises(RuntimeError, match="VERSION_CONFLICT"):
        repository.update(started["case_id"], {"assignee": "Alice"}, expected_version=0, comment=None)
    unchanged = repository.update(
        started["case_id"],
        {"title": "Unexpected overwrite"},
        expected_version=started["version"],
        comment=None,
    )
    assert unchanged["title"] == started["title"]
    assert unchanged["version"] == started["version"]
    commented = repository.update(started["case_id"], {}, expected_version=started["version"], comment="Investigating")
    assert commented["version"] == started["version"]
    assert commented["events"][0]["comment"] == "Investigating"
    assert len(commented["events"]) == len(started["events"]) + 1


def test_missing_findings_and_empty_summary_have_no_side_effects(test_db):
    repository = RemediationRepository()
    with db.connect() as conn:
        conn.execute("INSERT INTO remediation_sla_policy(policy_id) VALUES (1)")
    assert repository.summary() == {
        "open": 0,
        "overdue": 0,
        "near_due": 0,
        "risk_accepted": 0,
        "resolved_30d": 0,
        "mean_time_to_resolve_days": None,
    }
    assert repository.get("missing") is None
    assert repository.ensure_daily_digest(webhook_enabled=False) is False
    with pytest.raises(LookupError, match="FINDING_NOT_FOUND"):
        _start(repository)
    assert repository.list() == {"rows": [], "total": 0}


def test_unknown_severity_reconciliation_creates_a_case_without_a_due_date(test_db):
    repository = RemediationRepository()
    _asset_with_finding(severity="unrated")
    assert repository.reconcile_asset("host-1", stale_days=7)["created"] == 1
    case = repository.list()["rows"][0]
    assert case["severity"] == "unknown"
    assert case["due_at"] is None


def test_explicit_due_date_updates_and_refresh_keep_operator_fields(test_db):
    repository = RemediationRepository()
    _asset_with_finding()
    started = _start(repository, assignee="Alice")
    due = datetime.now(UTC) + timedelta(days=4)
    updated = repository.update(started["case_id"], {"due_at": due}, expected_version=started["version"], comment=None)
    assert updated["manual_due"] is True
    assert updated["due_at"] == due.isoformat()
    assert repository.reconcile_asset("host-1", stale_days=7) == {"created": 0, "reopened": 0, "resolved": 0}
    refreshed = repository.get(started["case_id"])
    assert refreshed["status"] == "in_progress"
    assert refreshed["assignee"] == "Alice"
    assert refreshed["due_at"] == due.isoformat()
    assert refreshed["version"] == updated["version"] + 1
    assert not any(event["event_type"] == "finding_reappeared" for event in refreshed["events"])
    cleared = repository.update(
        refreshed["case_id"], {"due_at": None}, expected_version=refreshed["version"], comment=None
    )
    assert cleared["due_at"] is None and cleared["manual_due"] is True


def test_case_deleted_after_start_transaction_returns_a_missing_finding_error(test_db, monkeypatch):
    repository = RemediationRepository()
    _asset_with_finding()
    get_case = repository.get

    def delete_before_read(case_id):
        with db.connect() as conn:
            conn.execute("DELETE FROM remediation_cases WHERE case_id=%s", (case_id,))
        return get_case(case_id)

    monkeypatch.setattr(repository, "get", delete_before_read)
    with pytest.raises(LookupError, match="FINDING_NOT_FOUND"):
        _start(repository)
    assert repository.list() == {"rows": [], "total": 0}
