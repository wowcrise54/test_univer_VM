"""Periodic refreshes include details and propagate parent cancellation."""
from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import BackgroundTasks

from app import db
from app.api.schemas import VulnerabilityPassportQueryRequest
from app.services import passport_refresh as service
from app.services import vulnerability_passport_jobs as jobs


@pytest.mark.parametrize(
    "child_status,trend_status,expected",
    [
        ("completed", "completed", "completed"),
        ("completed_with_errors", "completed", "completed_with_errors"),
        ("completed", "failed", "completed_with_errors"),
        ("failed", "completed", "failed"),
        ("interrupted", "completed", "failed"),
        ("running", "completed", "failed"),
        ("cancelled", "completed", "cancelled"),
        (None, "completed", "failed"),
    ],
)
def test_periodic_parent_waits_for_child_and_aggregates_status(monkeypatch, child_status, trend_status, expected):
    update = Mock()
    monkeypatch.setattr(service.passport_refresh, "update", update)
    child = {"job_id": "child", "status": child_status} if child_status else None
    monkeypatch.setattr(db, "get_vulnerability_passport_detail_job", Mock(return_value=child))
    parent_event = threading.Event()
    submit = Mock()

    def details(*, parent_cancel_event, **kwargs):
        assert parent_cancel_event is parent_event
        assert update.call_args.kwargs["status"] == "running"
        assert update.call_args.kwargs["result"]["detail_job"]["job_id"] == "child"

    def query(_payload, tasks, progress):
        progress(90, "trends", "Trends")
        tasks.add_task(details, job_id="child", cancel_event=threading.Event())
        return {"total": 1, "detail_job": {"job_id": "child"}, "trend_sync": {"status": trend_status}}

    service.run("parent", {}, query, submit, parent_event, complete_after_details=True)
    submit.assert_not_called()
    assert update.call_args.kwargs["status"] == expected
    assert update.call_args.kwargs["result"]["detail_job"] == child


@pytest.mark.parametrize("raise_error", [False, True])
def test_periodic_cleanup_of_child_not_started(monkeypatch, raise_error):
    update = Mock()
    finish = Mock()
    remove = Mock()
    monkeypatch.setattr(service.passport_refresh, "update", update)
    monkeypatch.setattr(db, "get_vulnerability_passport_detail_job", Mock(return_value={"status": "queued"}))
    monkeypatch.setattr(db, "finish_vulnerability_passport_detail_job", finish)
    from app import main

    monkeypatch.setattr(main.CONTAINER.operation_runner.cancellations, "remove", remove)
    parent = threading.Event()
    own = threading.Event()
    details = Mock()

    def query(_payload, tasks, _progress):
        tasks.add_task(details, job_id="child", cancel_event=own)
        if raise_error:
            raise RuntimeError("broken response preparation")
        parent.set()
        return {"detail_job": {"job_id": "child"}}

    service.run("parent", {}, query, Mock(), parent, complete_after_details=True)
    details.assert_not_called()
    assert own.is_set()
    expected = "failed" if raise_error else "cancelled"
    assert update.call_args.kwargs["status"] == expected
    assert finish.call_args.kwargs["status"] == expected
    remove.assert_called_once_with("passport-detail", "child")


def test_periodic_without_details_can_complete(monkeypatch):
    update = Mock()
    monkeypatch.setattr(service.passport_refresh, "update", update)
    service.run("parent", {}, lambda *_: {"total": 0}, Mock(), threading.Event(), complete_after_details=True)
    assert update.call_args.kwargs["status"] == "completed"


def test_periodic_parent_cancelled_during_child(monkeypatch):
    parent = threading.Event()
    update = Mock()
    monkeypatch.setattr(service.passport_refresh, "update", update)
    monkeypatch.setattr(db, "get_vulnerability_passport_detail_job", Mock(return_value={"job_id": "child", "status": "completed"}))

    def query(_payload, tasks, _progress):
        tasks.add_task(lambda **_: parent.set(), job_id="child", cancel_event=threading.Event())
        return {"detail_job": {"job_id": "child"}}

    service.run("parent", {}, query, Mock(), parent, complete_after_details=True)
    assert update.call_args.kwargs["status"] == "cancelled"


def test_periodic_adapter_forces_details_without_changing_manual_defaults(monkeypatch):
    query = Mock(return_value={})
    run = Mock()
    monkeypatch.setattr(jobs, "_execute_vulnerability_passport_query", query)
    monkeypatch.setattr(jobs.passport_refresh_service, "run", run)
    payload = VulnerabilityPassportQueryRequest()
    parent = threading.Event()
    jobs.run_periodic_vulnerability_passport_refresh_job("parent", payload, parent)
    assert run.call_args.kwargs == {"complete_after_details": True}
    execute = run.call_args.args[2]
    tasks = BackgroundTasks()
    progress = Mock()
    execute(payload, tasks, progress)
    query.assert_called_once_with(payload, tasks, progress, force_details=True)


@pytest.mark.parametrize("during_fetch", [False, True])
def test_parent_cancellation_stops_detail_scheduling(monkeypatch, during_fetch):
    from app import main

    parent = threading.Event()
    own = threading.Event()
    job = {"status": "running", "loaded_count": 0, "failed_count": 0}
    finish = Mock()
    fetched = []
    closed = Mock()

    class Client:
        session = SimpleNamespace(close=closed)

        def __init__(self, _auth):
            pass

        def get_vulnerability_passport(self, _token, identifier):
            fetched.append(identifier)
            parent.set()
            return {"description": "new"}

    monkeypatch.setattr(main, "MpVmClient", Client)
    monkeypatch.setattr(db, "start_vulnerability_passport_detail_job", Mock(return_value=job))
    monkeypatch.setattr(db, "get_vulnerability_passport_detail_job", Mock(return_value=job))
    monkeypatch.setattr(db, "save_vulnerability_passport_detail_job_batch", Mock())
    monkeypatch.setattr(db, "finish_vulnerability_passport_detail_job", finish)
    cleanup = Mock()
    monkeypatch.setattr(jobs, "unregister_vulnerability_passport_detail_job", cleanup)
    if not during_fetch:
        parent.set()
    jobs.run_vulnerability_passport_detail_job(
        job_id="child", auth=SimpleNamespace(), token="test", internal_ids=["p1", "p2", "p3"],
        cancel_event=own, parent_cancel_event=parent, workers=1,
    )
    assert fetched == (["p1"] if during_fetch else [])
    assert finish.call_args.kwargs["status"] == "cancelled"
    assert closed.call_count == int(during_fetch)
    cleanup.assert_called_once_with("child")


@pytest.mark.parametrize("forced", [False, True])
def test_query_forces_candidates_only_when_explicit(monkeypatch, forced):
    from app import main

    client = SimpleNamespace(auth=SimpleNamespace(), create_pdql_token=lambda *_a, **_kw: "pdql")
    monkeypatch.setattr(main, "require_mpvm", lambda: (client, "test"))
    monkeypatch.setattr(main, "fetch_asset_grid_records", lambda **_: ([{"@VulnerPassport": {"internalId": "p1"}}], {"reportedTotal": 1}))
    monkeypatch.setattr(main, "sync_trending_vulnerability_passports", lambda **_: {"status": "completed"})
    monkeypatch.setattr(db, "get_active_vulnerability_passport_detail_job", lambda: None)
    monkeypatch.setattr(db, "upsert_vulnerability_passports", lambda *_a, **_kw: {"saved": 1})
    candidates = Mock(return_value={"requested": ["p1"], "eligible": [], "skipped_fresh": ["p1"]})
    monkeypatch.setattr(db, "vulnerability_passport_detail_refresh_candidates", candidates)
    monkeypatch.setattr(db, "create_vulnerability_passport_detail_job", lambda *_a, **_kw: {"job_id": "child", "status": "completed"})
    monkeypatch.setattr(db, "list_vulnerability_passports", lambda **_: {"rows": []})
    jobs._execute_vulnerability_passport_query(VulnerabilityPassportQueryRequest(), BackgroundTasks(), force_details=forced)
    assert candidates.call_args.kwargs.get("force", False) is forced


@pytest.mark.parametrize("records,summary", [
    ([], {"reportedTotal": None}),
    ([{"@VulnerPassport": {"internalId": "p1"}}], {"reportedTotal": 2}),
    ([{}, {}], {"reportedTotal": 2}),
])
def test_invalid_full_catalog_has_no_local_writes(monkeypatch, records, summary):
    from app import main

    client = SimpleNamespace(create_pdql_token=lambda *_a, **_kw: "pdql")
    monkeypatch.setattr(main, "require_mpvm", lambda: (client, "test"))
    monkeypatch.setattr(main, "fetch_asset_grid_records", lambda **_: (records, summary))
    save = Mock()
    trends = Mock()
    detail = Mock()
    monkeypatch.setattr(db, "get_active_vulnerability_passport_detail_job", lambda: None)
    monkeypatch.setattr(db, "upsert_vulnerability_passports", save)
    monkeypatch.setattr(main, "sync_trending_vulnerability_passports", trends)
    monkeypatch.setattr(db, "create_vulnerability_passport_detail_job", detail)
    with pytest.raises(ValueError):
        jobs._execute_vulnerability_passport_query(VulnerabilityPassportQueryRequest(), BackgroundTasks())
    save.assert_not_called()
    trends.assert_not_called()
    detail.assert_not_called()
