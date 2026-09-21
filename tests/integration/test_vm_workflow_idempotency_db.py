"""Integration: VM workflow idempotency and concurrency against real PostgreSQL.

These tests exercise the real ``VmWorkflowRepository`` + ``VmWorkflowService``
pair over the disposable test database from ``compose.test.yml``.
"""

from __future__ import annotations

import threading
from typing import Any, cast

import pytest

from app.repositories.vm_workflows import VmWorkflowRepository
from app.services.vm_workflows import VmWorkflowService


class ImmediateFuture:
    def add_done_callback(self, callback):
        callback(self)


class FakeCancellations:
    def cancel(self, kind, value):
        return True


class FakeRunner:
    def __init__(self):
        self.submitted = []
        self.lock = threading.Lock()
        self.cancellations = FakeCancellations()

    def submit(self, queue, function, *args):
        with self.lock:
            self.submitted.append((queue, args))
        return ImmediateFuture()


def _service(runner: FakeRunner) -> VmWorkflowService:
    repository = VmWorkflowRepository()
    service = VmWorkflowService(
        cast(Any, repository), cast(Any, runner), remediation=object(),
    )
    service.status_provider = lambda: {"components": {"mpvm": {"state": "ok"}}}
    return service


def _workflow_count() -> int:
    from app import db

    with db.connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS count FROM vm_workflow_runs").fetchone()
    return int(row["count"])


def test_identical_replay_returns_existing_workflow_without_restarting(test_db):
    """Same key + identical task_id/options → the existing workflow, no new run."""
    runner = FakeRunner()
    service = _service(runner)

    first, replayed = service.start_scan(
        task_id="task-1", options={"wait_for_finish": True}, actor="op", idempotency_key="key-1",
    )
    assert replayed is False

    second, replayed = service.start_scan(
        task_id="task-1", options={"wait_for_finish": True}, actor="op", idempotency_key="key-1",
    )

    assert replayed is True
    assert second["workflow_id"] == first["workflow_id"]
    assert _workflow_count() == 1
    assert len(runner.submitted) == 1


def test_replayed_key_with_different_request_is_rejected(test_db):
    """Regression: a reused key with a changed task_id must not replay silently."""
    runner = FakeRunner()
    service = _service(runner)
    service.start_scan(
        task_id="task-1", options={}, actor="op", idempotency_key="key-1",
    )

    with pytest.raises(ValueError):
        service.start_scan(
            task_id="task-2", options={}, actor="op", idempotency_key="key-1",
        )
    with pytest.raises(ValueError):
        service.start_scan(
            task_id="task-1", options={"require_clean_jobs": True}, actor="op", idempotency_key="key-1",
        )

    assert _workflow_count() == 1
    assert len(runner.submitted) == 1


def test_parallel_identical_requests_create_exactly_one_workflow(test_db):
    """Regression: two concurrent clicks with one key must not raise a
    UniqueViolation and must not create a second workflow."""
    runner = FakeRunner()
    service = _service(runner)
    errors: list[BaseException] = []
    workflows: list[dict[str, Any]] = []
    replays: list[bool] = []
    barrier = threading.Barrier(2)

    def call():
        try:
            barrier.wait()
            workflow, replay = service.start_scan(
                task_id="task-1", options={}, actor="op", idempotency_key="race-key",
            )
            workflows.append(workflow)
            replays.append(replay)
        except BaseException as exc:  # noqa: BLE001 - captured for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert _workflow_count() == 1
    assert len(runner.submitted) == 1
    assert len(workflows) == 2
    assert workflows[0]["workflow_id"] == workflows[1]["workflow_id"]
    assert sorted(replays) == [False, True]


def test_parallel_requests_with_same_key_but_different_request_are_rejected(test_db):
    """A racing request must not silently replay a workflow for another task."""
    runner = FakeRunner()
    service = _service(runner)
    errors: list[BaseException] = []
    workflows: list[dict[str, Any]] = []
    barrier = threading.Barrier(2)

    def call(task_id: str):
        try:
            barrier.wait()
            workflow, _ = service.start_scan(
                task_id=task_id, options={}, actor="op", idempotency_key="race-key",
            )
            workflows.append(workflow)
        except BaseException as exc:  # noqa: BLE001 - captured for the assertion
            errors.append(exc)

    threads = [threading.Thread(target=call, args=(task_id,)) for task_id in ("task-1", "task-2")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(workflows) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert "different scan request" in str(errors[0])
    assert _workflow_count() == 1
    assert len(runner.submitted) == 1


def test_replay_after_process_restart_reads_workflow_from_db(test_db):
    """A fresh service instance (simulated restart) must replay the persisted row."""
    first_runner, second_runner = FakeRunner(), FakeRunner()
    first = _service(first_runner)
    workflow, replayed = first.start_scan(
        task_id="task-1", options={}, actor="op", idempotency_key="restart-key",
    )
    assert replayed is False

    second = _service(second_runner)
    restored, replayed = second.start_scan(
        task_id="task-1", options={}, actor="op", idempotency_key="restart-key",
    )

    assert replayed is True
    assert restored["workflow_id"] == workflow["workflow_id"]
    assert restored["request"]["task_id"] == "task-1"
    assert second_runner.submitted == []
    assert _workflow_count() == 1


def test_retry_rejects_reused_key_for_a_different_workflow(test_db):
    """A retry key already used by another workflow must not be replayed."""
    runner = FakeRunner()
    service = _service(runner)
    source, _ = service.start_scan(
        task_id="task-1", options={}, actor="op", idempotency_key="source-key",
    )

    repository = VmWorkflowRepository()
    repository.update_run(source["workflow_id"], status="failed", stage="failed", progress_percent=100)

    with pytest.raises(ValueError):
        service.retry(source["workflow_id"], "op", "source-key")

    assert _workflow_count() == 1
    assert len(runner.submitted) == 1
