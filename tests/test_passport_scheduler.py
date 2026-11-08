from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from app.services.passport_scheduler import PassportSyncScheduler


class ImmediateRunner:
    def __init__(self) -> None:
        self.cancellations = Mock()
        self.cancellations.register.side_effect = lambda *_: threading.Event()
        self.futures = []

    def submit(self, _queue, function):
        future = Mock(done=lambda: False)
        self.futures.append((future, function))
        return future


def settings(enabled=True):
    return SimpleNamespace(passport_sync_enabled=enabled, passport_sync_interval_seconds=3600,
                           automation_scheduler_poll_seconds=30)


def test_disabled_scheduler_does_not_submit_or_reserve():
    runner = ImmediateRunner()
    scheduler = PassportSyncScheduler(settings=settings(False), runner=runner, ready=Mock(), execute=Mock())
    with patch("app.services.passport_scheduler.passport_refresh.reserve_periodic") as reserve:
        scheduler.start()
        scheduler.tick()
    assert runner.futures == []
    reserve.assert_not_called()


def test_start_is_idempotent_and_tick_executes_reserved_operation():
    runner = ImmediateRunner()
    execute = Mock()
    scheduler = PassportSyncScheduler(settings=settings(), runner=runner, ready=Mock(return_value=True), execute=execute)
    operation = {"operation_id": "op-1"}
    with patch("app.services.passport_scheduler.passport_refresh.reserve_periodic", return_value=operation):
        scheduler.start()
        scheduler.start()
        scheduler.tick()
    assert len(runner.futures) == 1
    execute.assert_called_once()
    assert execute.call_args.args[0] == "op-1"
    assert execute.call_args.args[1].load_details is True


def test_execute_error_marks_failed_and_does_not_escape_next_loop_tick():
    runner = ImmediateRunner()
    execute = Mock(side_effect=RuntimeError("remote unavailable"))
    scheduler = PassportSyncScheduler(settings=settings(), runner=runner, ready=Mock(return_value=True), execute=execute)
    with (
        patch("app.services.passport_scheduler.passport_refresh.reserve_periodic", return_value={"operation_id": "op-2"}),
        patch("app.services.passport_scheduler.passport_refresh.update") as update,
        pytest.raises(RuntimeError),
    ):
        scheduler.tick()

    assert update.call_args.kwargs["status"] == "failed"
    assert runner.cancellations.remove.called


def test_stop_cancels_current_operation():
    runner = ImmediateRunner()
    scheduler = PassportSyncScheduler(settings=settings(), runner=runner, ready=Mock(return_value=True), execute=Mock())
    scheduler._operation_id = "op-3"
    scheduler.stop()
    runner.cancellations.cancel.assert_called_once_with("passport-refresh", "op-3")
