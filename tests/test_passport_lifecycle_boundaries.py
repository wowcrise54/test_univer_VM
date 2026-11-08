"""Failure, shutdown and reservation boundaries of passive synchronization."""
from __future__ import annotations

import threading
from contextlib import nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import BackgroundTasks

from app import diagnostics
from app.core.config import Settings
from app.core.runtime import CancellationRegistry
from app.repositories import passport_refresh as repository
from app.services import passport_refresh as refresh
from app.services import passport_scheduler as scheduling


def scheduler(**kwargs):
    runner = SimpleNamespace(cancellations=CancellationRegistry(), submit=Mock())
    settings = Settings(_env_file=None, passport_sync_enabled=True)
    return scheduling.PassportSyncScheduler(
        settings=settings, runner=runner, ready=kwargs.get("ready", lambda: True),
        execute=kwargs.get("execute", Mock()),
    )


def test_loop_survives_failure_and_uses_interruptible_wait(monkeypatch):
    service = scheduler()
    stop = Mock()
    stop.is_set.return_value = False
    stop.wait.side_effect = [False, True]
    service._stop = stop
    tick = Mock(side_effect=[RuntimeError("fake failure"), None])
    monkeypatch.setattr(service, "tick", tick)
    log = Mock()
    monkeypatch.setattr(scheduling, "log_exception", log)
    service._loop()
    assert tick.call_count == 2
    assert stop.wait.call_args_list[0].args == (30,)
    log.assert_called_once_with("passport-sync", "passport.periodic.tick.failed")


def test_stopped_loop_never_ticks(monkeypatch):
    service = scheduler()
    actual_tick = service.tick
    service.stop()
    tick = Mock()
    monkeypatch.setattr(service, "tick", tick)
    service._loop()
    actual_tick()
    tick.assert_not_called()


def test_unavailable_connection_is_logged_once_and_rechecked(monkeypatch):
    ready = Mock(side_effect=[False, False, True, False])
    service = scheduler(ready=ready)
    reserve = Mock(return_value=None)
    log = Mock()
    monkeypatch.setattr(scheduling.passport_refresh, "reserve_periodic", reserve)
    monkeypatch.setattr(scheduling, "log_event", log)
    for _ in range(4):
        service.tick()
    assert log.call_count == 2
    reserve.assert_called_once()


def test_stop_during_reservation_disposes_queued_operation(monkeypatch):
    service = scheduler()

    def reserve(*args, **kwargs):
        service.stop()
        return {"operation_id": "reserved"}

    monkeypatch.setattr(scheduling.passport_refresh, "reserve_periodic", reserve)
    update = Mock()
    monkeypatch.setattr(scheduling.passport_refresh, "update", update)
    service.tick()
    service.execute.assert_not_called()
    assert update.call_args.kwargs["status"] == "cancelled"
    assert service.runner.cancellations.get("passport-refresh", "reserved") is None
    assert service._operation_id is None


def test_stop_from_active_callback_sets_parent_event_and_cleans_up(monkeypatch):
    service = scheduler()

    def execute(identifier, payload, event):
        assert identifier == "active"
        assert not event.is_set()
        service.stop()
        assert event.is_set()

    service.execute = execute
    monkeypatch.setattr(scheduling.passport_refresh, "reserve_periodic", lambda *_a, **_kw: {"operation_id": "active"})
    service.tick()
    assert service._operation_id is None
    assert service.runner.cancellations.get("passport-refresh", "active") is None


def test_completed_scheduler_future_can_restart():
    service = scheduler()
    future = Mock()
    future.done.return_value = True
    service._future = future
    service.stop()
    service.start()
    service.runner.submit.assert_called_once_with("passport-sync-scheduler", service._loop)
    assert not service._stop.is_set()


def test_missing_advisory_lock_result_fails_closed(monkeypatch):
    connection = MagicMock()
    connection.execute.return_value.fetchone.return_value = None
    monkeypatch.setattr(repository.db, "init_db", Mock())
    monkeypatch.setattr(repository.db, "connect", lambda: nullcontext(connection))
    assert repository.reserve_periodic({}, now=datetime(2026, 11, 8, tzinfo=UTC), interval_seconds=60) is None


@pytest.mark.parametrize("current", [None, {"status": "completed"}, {"status": "running"}])
def test_cleanup_never_overwrites_started_or_terminal_children(monkeypatch, current):
    tasks = BackgroundTasks()
    tasks.add_task(Mock(), job_id="child", cancel_event=threading.Event())
    monkeypatch.setattr(refresh.db, "get_vulnerability_passport_detail_job", lambda _: current)
    finish = Mock()
    monkeypatch.setattr(refresh.db, "finish_vulnerability_passport_detail_job", finish)
    refresh._finish_pending_details(tasks, "cancelled")
    finish.assert_not_called()


def test_cleanup_handles_missing_child_event(monkeypatch):
    from app import main

    tasks = BackgroundTasks()
    tasks.add_task(Mock(), job_id="child")
    monkeypatch.setattr(refresh.db, "get_vulnerability_passport_detail_job", lambda _: {"status": "queued"})
    finish = Mock()
    monkeypatch.setattr(refresh.db, "finish_vulnerability_passport_detail_job", finish)
    remove = Mock()
    monkeypatch.setattr(main.CONTAINER.operation_runner.cancellations, "remove", remove)
    refresh._finish_pending_details(tasks, "failed")
    assert finish.call_args.kwargs["status"] == "failed"
    remove.assert_called_once_with("passport-detail", "child")


def test_parent_cancel_between_queued_callbacks_cleans_remaining_child(monkeypatch):
    from app import main

    event = threading.Event()
    own = threading.Event()
    second = Mock()
    update = Mock()
    monkeypatch.setattr(refresh.passport_refresh, "update", update)
    monkeypatch.setattr(refresh.db, "get_vulnerability_passport_detail_job", lambda _: {"status": "queued"})
    finish = Mock()
    monkeypatch.setattr(refresh.db, "finish_vulnerability_passport_detail_job", finish)
    monkeypatch.setattr(main.CONTAINER.operation_runner.cancellations, "remove", Mock())

    def query(_payload, tasks, _progress):
        tasks.add_task(lambda **_: event.set())
        tasks.add_task(second, job_id="child", cancel_event=own)
        return {"detail_job": {"job_id": "child"}}

    refresh.run("parent", {}, query, Mock(), event, complete_after_details=True)
    second.assert_not_called()
    assert own.is_set()
    assert finish.call_args.kwargs["status"] == "cancelled"
    assert update.call_args.kwargs["status"] == "cancelled"


def test_diagnostic_skip_paths_do_not_capture_traffic(monkeypatch):
    """Keep the diagnostic fail-closed gate covered without real HTTP traffic."""
    monkeypatch.setattr(diagnostics, "_CONFIG", SimpleNamespace(debug_mode=False))
    log = Mock()
    monkeypatch.setattr(diagnostics, "log_event", log)
    diagnostics.capture_http_traffic("passport.test", payload={"description": "test"})
    log.assert_not_called()
    assert diagnostics.parse_http_body("&&", "application/x-www-form-urlencoded") == "&&"
    assert diagnostics.describe_sql_parameters("SELECT harmless", 7) == 7
