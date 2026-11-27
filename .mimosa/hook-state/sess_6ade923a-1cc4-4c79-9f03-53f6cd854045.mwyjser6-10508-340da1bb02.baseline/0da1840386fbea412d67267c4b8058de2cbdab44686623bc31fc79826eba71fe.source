from datetime import date, datetime
from threading import Event
from unittest.mock import MagicMock

import pytest

from app.domain.compliance import evaluate_freshness
from app.repositories.compliance import build_compliance_dataset
from app.services import passport_refresh


@pytest.mark.parametrize("scan", [datetime(2026, 1, 1), "2026-01-01T00:00:00"])
def test_naive_scan_dates_are_interpreted_as_utc_at_the_freshness_boundary(scan):
    result = evaluate_freshness(scan, date(2026, 1, 31))
    assert result.is_fresh and result.age_days == 30
    assert result.scan_at.isoformat() == "2026-01-01T00:00:00+00:00"


def test_dataset_deduplicates_by_asset_finding_and_source_and_counts_missing_ips():
    base = {
        "asset_id": "host",
        "ip_address": "192.0.2.1",
        "card_last_seen": "2026-01-15T00:00:00Z",
        "asset_type": "Server",
        "severity": "critical",
        "vulnerability_id": "vuln",
        "source_type": "os",
    }
    rows = [
        base,
        base,
        {**base, "source_type": "software"},
        {**base, "vulnerability_id": None},
        {**base, "severity": "low"},
        {**base, "asset_id": ""},
        {**base, "asset_id": "no-ip", "ip_address": None, "asset_type": "Laptop", "severity": "low"},
    ]
    dataset = build_compliance_dataset(rows, scope="organization", assessment_date=date(2026, 1, 31))
    assert len(dataset.assets) == 2
    assert len(dataset.findings) == 2
    assert {finding["source_type"] for finding in dataset.findings} == {"os", "software"}
    assert dataset.summary["unique_vulnerabilities"] == 1
    assert dataset.summary["by_asset_category"] == {"user_device": 1, "server": 1, "unclassified": 0}
    assert dataset.diagnostics == {"invalid_or_missing_ip": 1}


@pytest.mark.parametrize(
    "trend,detail,expected",
    [
        (None, None, "completed"),
        ({"status": "failed"}, None, "completed_with_errors"),
        ({"status": "completed"}, {"job_id": "detail"}, "completed"),
    ],
)
def test_catalog_refresh_preserves_result_and_submits_detail_arguments(monkeypatch, trend, detail, expected):
    update = MagicMock()
    monkeypatch.setattr(passport_refresh.passport_refresh, "update", update)
    submit = MagicMock()
    detail_worker = MagicMock()

    def query(payload, tasks, progress):
        assert payload == {"scope": "all"}
        progress(70, "save", "Saved")
        tasks.add_task(detail_worker, "job", limit=5)
        return {"total": 3, "db": {"saved": 3}, "trend_sync": trend, "detail_job": detail}

    passport_refresh.run("refresh", {"scope": "all"}, query, submit, Event())
    submit.assert_called_once_with("passport-detail", detail_worker, "job", limit=5)
    assert update.call_args.kwargs["status"] == expected
    assert update.call_args.kwargs["result"] == {
        "total": 3,
        "db": {"saved": 3},
        "trend_sync": trend,
        "detail_job": detail,
    }
    assert update.call_args.kwargs["percent"] == 100


@pytest.mark.parametrize("before_query", [False, True])
def test_catalog_cancellation_never_submits_queued_detail_work(monkeypatch, before_query):
    update = MagicMock()
    monkeypatch.setattr(passport_refresh.passport_refresh, "update", update)
    cancel = Event()
    submit = MagicMock()

    def query(_payload, tasks, _progress):
        tasks.add_task(MagicMock())
        cancel.set()
        return {"total": 2}

    execute = MagicMock(side_effect=query)
    if before_query:
        cancel.set()
    passport_refresh.run("refresh", {}, execute, submit, cancel)
    assert execute.call_count == int(not before_query)
    submit.assert_not_called()
    assert update.call_args.kwargs["status"] == "cancelled"


@pytest.mark.parametrize("stage", ["query", "submit"])
def test_catalog_failures_are_persisted_with_bounded_error_messages(monkeypatch, stage):
    update = MagicMock()
    monkeypatch.setattr(passport_refresh.passport_refresh, "update", update)

    def query(_payload, tasks, _progress):
        if stage == "query":
            raise RuntimeError("e" * 2500)
        tasks.add_task(MagicMock())
        return {}

    submit = MagicMock(side_effect=RuntimeError("e" * 2500))
    passport_refresh.run("refresh", {}, query, submit, Event())
    assert update.call_args.kwargs["status"] == "failed"
    assert len(update.call_args.kwargs["message"]) == 2000
    if stage == "query":
        submit.assert_not_called()
