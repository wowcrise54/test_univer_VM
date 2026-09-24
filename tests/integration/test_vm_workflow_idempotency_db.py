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


def test_asset_group_replay_rejects_different_group_or_assets(test_db):
    """The persisted group workflow must match the complete retry request."""
    runner = FakeRunner()
    service = _service(runner)
    first, replayed = service.start_asset_group_scan(
        asset_group_id="group-1",
        asset_ids=["asset-1"],
        options={},
        actor="op",
        idempotency_key="group-key",
    )
    assert replayed is False

    with pytest.raises(ValueError, match="different workflow request"):
        service.start_asset_group_scan(
            asset_group_id="group-2",
            asset_ids=["asset-1"],
            options={},
            actor="op",
            idempotency_key="group-key",
        )
    with pytest.raises(ValueError, match="different workflow request"):
        service.start_asset_group_scan(
            asset_group_id="group-1",
            asset_ids=["asset-2"],
            options={},
            actor="op",
            idempotency_key="group-key",
        )

    restored, replayed = service.start_asset_group_scan(
        asset_group_id="group-1",
        asset_ids=["asset-1"],
        options={},
        actor="op",
        idempotency_key="group-key",
    )
    assert replayed is True
    assert restored["workflow_id"] == first["workflow_id"]
    assert _workflow_count() == 1
    assert len(runner.submitted) == 1


def test_campaign_verification_finalizes_all_cases_with_one_version_change(test_db):
    """A failed asset must not be briefly marked passed or versioned twice."""
    from app import db

    campaign_id = "11111111-1111-1111-1111-111111111111"
    workflow_id = "22222222-2222-2222-2222-222222222222"
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO remediation_campaigns(campaign_id,name) VALUES(%s,%s)",
            (campaign_id, "Verification campaign"),
        )
        conn.execute(
            "INSERT INTO vm_workflow_runs(workflow_id,kind,status) VALUES(%s,'verification','running')",
            (workflow_id,),
        )
        for case_id, asset_id, status in (
            ("case-passed", "asset-passed", "resolved"),
            ("case-failed", "asset-failed", "resolved"),
        ):
            conn.execute(
                """INSERT INTO remediation_cases(case_id,asset_id,vulnerability_key,status,
                       verification_status,verification_workflow_id)
                   VALUES(%s,%s,%s,%s,'running',%s)""",
                (case_id, asset_id, f"key:{case_id}", status, workflow_id),
            )
            conn.execute(
                "INSERT INTO remediation_campaign_cases(campaign_id,case_id) VALUES(%s,%s)",
                (campaign_id, case_id),
            )

    VmWorkflowRepository().finalize_campaign_verification(
        campaign_id, workflow_id, ["asset-failed"],
    )

    with db.connect() as conn:
        rows = conn.execute(
            """SELECT rc.case_id,rc.verification_status,rc.version
               FROM remediation_cases rc JOIN remediation_campaign_cases cc ON cc.case_id=rc.case_id
               WHERE cc.campaign_id=%s ORDER BY rc.case_id""",
            (campaign_id,),
        ).fetchall()

    assert [(row["case_id"], row["verification_status"], row["version"]) for row in rows] == [
        ("case-failed", "failed", 2),
        ("case-passed", "passed", 2),
    ]
