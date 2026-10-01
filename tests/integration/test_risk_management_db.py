"""Risk management executes real PostgreSQL queries against disposable test data."""
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from app import db
from app.repositories.risk import MODEL_VERSION, RiskRepository
from app.services.risk import RiskService

pytestmark = pytest.mark.integration
MISSING_CAMPAIGN = "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def risk_data(test_db):
    now = db.now_utc()
    with db.connect() as conn:
        for asset, ip, fqdn in (("asset-a", "10.0.0.1", "one.example"), ("asset-b", "10.0.0.2", "two.example")):
            conn.execute("INSERT INTO asset_cards(asset_id,display_name,ip_address,fqdn,first_seen,last_seen) VALUES(%s,%s,%s,%s,%s,%s)", (asset, asset, ip, fqdn, now, now))
        for case_id, asset, key, severity, cvss, status in (
            ("case-critical", "asset-a", "shared", "critical", 10, "open"),
            ("case-high", "asset-b", "shared", "high", 8, "in_progress"),
            ("case-low", "asset-a", "low-key", "low", 0, "risk_accepted"),
            ("case-resolved", "asset-b", "resolved-key", "critical", 10, "resolved"),
        ):
            conn.execute("INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,severity,cvss_score,status) VALUES(%s,%s,%s,%s,%s,%s)", (case_id, asset, key, severity, cvss, status))
    return RiskService(RiskRepository())


def test_asset_context_upsert_deduplicates_targets_preserves_fields_and_records_audit(risk_data):
    assert risk_data.set_contexts(["asset-a", "asset-a", "missing"], {"criticality": "critical", "owner": " Team ", "tags": ["api", " api ", "", "production"]}, "operator") == {"updated_count": 1, "asset_ids": ["asset-a"]}
    with db.connect() as conn:
        first = conn.execute("SELECT * FROM asset_contexts WHERE asset_id='asset-a'").fetchone()
        assert first["owner"] == "Team" and first["tags"] == ["api", "production"]
        assert first["environment"] == "production" and first["exposure"] == "internal"
    risk_data.set_contexts(["asset-a"], {"owner": None, "exposure": "external"}, "second-operator")
    with db.connect() as conn:
        current = conn.execute("SELECT * FROM asset_contexts WHERE asset_id='asset-a'").fetchone()
        assert current["criticality"] == "critical" and current["tags"] == ["api", "production"]
        assert current["owner"] is None and current["version"] == first["version"] + 1
        assert current["updated_by"] == "second-operator"
        events = conn.execute("SELECT actor_username,changes_json FROM asset_context_events ORDER BY event_id").fetchall()
    assert len(events) == 2 and events[-1]["changes_json"] == {"owner": None, "exposure": "external"}


@pytest.mark.parametrize("values", [{}, {"unknown": "ignored"}, {"criticality": "invalid"}, {"environment": "invalid"}, {"exposure": "invalid"}])
def test_invalid_context_cannot_partially_modify_assets(risk_data, values):
    with pytest.raises(ValueError):
        risk_data.set_contexts(["asset-a", "asset-b"], values, "operator")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) count FROM asset_contexts").fetchone()["count"] == 0
        assert conn.execute("SELECT COUNT(*) count FROM asset_context_events").fetchone()["count"] == 0


def test_context_normalizes_owner_length_tag_order_and_count(risk_data):
    risk_data.set_contexts(["asset-b"], {"owner": "x" * 250, "tags": [f"tag-{i:02}" for i in range(60)] + [" ", "tag-00"]}, None)
    with db.connect() as conn:
        current = conn.execute("SELECT * FROM asset_contexts WHERE asset_id='asset-b'").fetchone()
    assert len(current["owner"]) == 200 and len(current["tags"]) == 50
    assert current["tags"] == sorted(current["tags"])


@pytest.mark.parametrize("column,key", [("asset_id", "ASSET-A"), ("ip", "10.0.0.1"), ("fqdn", "ONE.EXAMPLE")])
def test_context_csv_matches_case_insensitive_identity_and_bom(risk_data, column, key):
    result = risk_data.import_contexts(f"\ufeff{column},criticality,environment,exposure,owner,tags\n{key},high,test,external, Operations ,\"api, api, test\"\n", "importer")
    assert result == {"matched": 1, "unmatched": [], "errors": []}
    with db.connect() as conn:
        current = conn.execute("SELECT * FROM asset_contexts WHERE asset_id='asset-a'").fetchone()
    assert current["owner"] == "Operations" and current["tags"] == ["api", "test"]
    assert current["environment"] == "test" and current["updated_by"] == "importer"


def test_context_csv_reports_bad_rows_without_losing_successful_updates(risk_data):
    result = risk_data.import_contexts("asset_id,criticality\nasset-a,high\nmissing,medium\nasset-b,invalid\nasset-b,\n", "importer")
    assert result["matched"] == 1 and result["unmatched"] == ["missing"]
    assert [row["line"] for row in result["errors"]] == [4, 5]
    with db.connect() as conn:
        assert conn.execute("SELECT criticality FROM asset_contexts WHERE asset_id='asset-a'").fetchone()["criticality"] == "high"
        assert conn.execute("SELECT 1 FROM asset_contexts WHERE asset_id='asset-b'").fetchone() is None


@pytest.mark.parametrize("level", ["urgent", "high", "medium", "low"])
def test_risk_level_filters_use_the_same_scoring_query_for_count_and_rows(risk_data, level):
    risk_data.set_contexts(["asset-a"], {"criticality": "critical", "exposure": "external"}, "operator")
    risk_data.set_contexts(["asset-b"], {"criticality": "low", "exposure": "isolated"}, "operator")
    result = risk_data.queue(level=level, limit=1)
    all_rows = risk_data.queue(limit=500)["rows"]
    expected = [row for row in all_rows if row["risk_level"] == level]
    assert result["total"] == len(expected)
    assert result["rows"] == expected[:1]
    assert result["risk_model_version"] == MODEL_VERSION


def test_risk_queue_context_filters_paging_and_sql_metacharacters(risk_data):
    risk_data.set_contexts(["asset-a"], {"criticality": "high", "environment": "test", "exposure": "external", "owner": "Team ' OR 1=1 --", "tags": ["api"]}, "operator")
    filters = {"criticality": "high", "environment": "test", "exposure": "external", "owner": "Team ' OR 1=1 --", "tag": "api"}
    first = risk_data.queue(**filters, limit=1)
    assert first["total"] == 2 and len(first["rows"]) == 1
    assert first["rows"][0]["asset_id"] == "asset-a"
    second = risk_data.queue(**filters, limit=1, offset=1)
    assert second["total"] == 2 and second["rows"][0]["case_id"] != first["rows"][0]["case_id"]
    assert risk_data.queue(owner="' OR 1=1 --")["total"] == 0
    assert risk_data.queue(limit=999, offset=-1)["limit"] == 500
    assert risk_data.queue(limit=0)["limit"] == 1
    assert risk_data.queue(offset=100)["rows"] == []


def test_risk_queue_scores_are_bounded_and_explain_host_spread_and_overdue_sla(risk_data):
    past = datetime.now(UTC) - timedelta(days=120)
    with db.connect() as conn:
        conn.execute("UPDATE remediation_cases SET due_at=%s,first_seen_at=%s WHERE case_id='case-critical'", (past, past))
    risk_data.set_contexts(["asset-a"], {"criticality": "critical", "exposure": "external"}, "operator")
    result = risk_data.queue()
    critical = next(row for row in result["rows"] if row["case_id"] == "case-critical")
    assert critical["risk_score"] == 100 and critical["risk_level"] == "urgent"
    assert critical["cvss_score"] == 10.0 and isinstance(critical["due_at"], str)
    assert "affected_hosts:2" in critical["risk_factors"] and "sla:tracked" in critical["risk_factors"]
    assert "case-resolved" not in [row["case_id"] for row in result["rows"]]
    summary = risk_data.summary()
    assert summary["total"] == 3 and sum(summary[key] for key in ("urgent", "high", "medium", "low")) == 3


@pytest.mark.parametrize("assignment", [False, True])
def test_campaign_creation_deduplicates_cases_and_audits_assignments(risk_data, assignment):
    due = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    values = {"name": "Critical campaign", "case_ids": ["case-critical", "case-critical", "case-high"]}
    if assignment:
        values.update(assignee="Team", due_at=due)
    campaign = risk_data.create_campaign(values, "operator")
    assert campaign["total"] == 2 and len(campaign["cases"]) == 2
    assert campaign["created_by"] == "operator" and campaign["awaiting_verification"] == 2
    assert campaign["events"][0]["changes"]["case_ids"] == ["case-critical", "case-high"]
    assert risk_data.list_campaigns()["total"] == 1
    for case in campaign["cases"]:
        assert case["version"] == (2 if assignment else 1)
        assert case["manual_due"] is assignment
        assert case["assignee"] == ("Team" if assignment else None)
    assert risk_data.get_campaign(MISSING_CAMPAIGN) is None


def test_campaign_invalid_case_rolls_back_campaign_and_audit(risk_data):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        risk_data.create_campaign({"name": "Invalid campaign", "case_ids": ["case-critical", "missing"]}, "operator")
    assert risk_data.list_campaigns() == {"rows": [], "total": 0}
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) count FROM remediation_campaign_events").fetchone()["count"] == 0
        assert conn.execute("SELECT version FROM remediation_cases WHERE case_id='case-critical'").fetchone()["version"] == 1


def test_campaign_updates_ignore_unknown_fields_keep_explicit_nulls_and_version_audit(risk_data):
    campaign = risk_data.create_campaign({"name": "Campaign", "case_ids": ["case-critical"], "assignee": "Team"}, "operator")
    key = campaign["campaign_id"]
    unchanged = risk_data.update_campaign(key, {"unknown": "ignored"}, "operator")
    assert unchanged["version"] == campaign["version"] and len(unchanged["events"]) == 1
    updated = risk_data.update_campaign(key, {"assignee": None, "status": "active", "comment": "Started"}, "other")
    assert updated["assignee"] is None and updated["status"] == "active"
    assert updated["version"] == campaign["version"] + 1
    event = next(event for event in updated["events"] if event["event_type"] == "updated")
    assert event["actor_username"] == "other" and event["changes"]["assignee"] is None
    assert risk_data.update_campaign(MISSING_CAMPAIGN, {"name": "Missing"}, "operator") is None
    assert risk_data.update_campaign(MISSING_CAMPAIGN, {}, "operator") is None


def test_campaign_verification_targets_only_actionable_cases_and_are_deduplicated(risk_data):
    campaign = risk_data.create_campaign({"name": "Mixed cases", "case_ids": ["case-critical", "case-high", "case-low", "case-resolved"]}, "operator")
    result = risk_data.verification_targets(campaign["campaign_id"], "verifier")
    assert result["asset_ids"] == ["asset-a", "asset-b"]
    current = risk_data.get_campaign(campaign["campaign_id"])
    event = next(row for row in current["events"] if row["event_type"] == "verification_requested")
    assert event["changes"]["asset_ids"] == ["asset-a", "asset-b"] and event["actor_username"] == "verifier"
    assert risk_data.verification_targets(MISSING_CAMPAIGN, "verifier") is None
    with db.connect() as conn:
        conn.execute("UPDATE remediation_cases SET status='resolved'")
    assert risk_data.verification_targets(campaign["campaign_id"], "verifier")["asset_ids"] == []

def test_risk_queue_uses_materialized_exploitation_evidence_without_loading_passport_payload(risk_data):
    before = next(row for row in risk_data.queue()["rows"] if row["case_id"] == "case-critical")
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute("INSERT INTO vulnerability_passports(internal_id,raw_detail_json,first_seen,last_seen) VALUES(%s,%s,%s,%s)", ("passport", '{"exploit": true}', now, now))
        conn.execute("UPDATE remediation_cases SET passport_internal_id='passport' WHERE case_id='case-critical'")
        conn.execute("UPDATE remediation_cases SET cvss_score=NULL WHERE case_id='case-low'")
    rows = risk_data.queue()["rows"]
    after = next(row for row in rows if row["case_id"] == "case-critical")
    assert after["risk_score"] == before["risk_score"] + 5
    assert after["exploitation_evidence"] is True
    assert "exploitation:local-passport" in after["risk_factors"]
    assert "raw_detail_json" not in after
    assert next(row for row in rows if row["case_id"] == "case-low")["cvss_score"] is None


def test_explicit_null_tags_clear_previous_tags_as_allowed_by_http_schema(risk_data):
    risk_data.set_contexts(["asset-a"], {"tags": ["old"]}, "operator")
    risk_data.set_contexts(["asset-a"], {"tags": None}, "operator")
    with db.connect() as conn:
        current = conn.execute("SELECT tags,version FROM asset_contexts WHERE asset_id='asset-a'").fetchone()
        assert current["tags"] == [] and current["version"] == 2