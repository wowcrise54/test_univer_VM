from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app import db
from app.services.vm_workflows import VmWorkflowService


@pytest.fixture
def workflow_service():
    workflow = {
        "workflow_id": "wf-1",
        "kind": "verification",
        "status": "queued",
        "request": {"asset_ids": ["asset-1", "asset-1", "asset-2"]},
        "result": {},
        "steps": [{"step_key": key, "status": "pending"} for key in ("targets", "scan", "postprocess", "reconcile")],
    }
    repository = MagicMock()
    repository.get.side_effect = lambda _identifier: workflow
    repository.active.return_value = []
    repository.create.return_value = (workflow, False)
    repository.by_operation.return_value = None
    repository.by_idempotency_key.return_value = None

    def update_run(_identifier, **values):
        workflow.update(values)

    def update_step(_identifier, step_key, **values):
        step = next((item for item in workflow["steps"] if item["step_key"] == step_key), None)
        if step is None:
            step = {"step_key": step_key}
            workflow["steps"].append(step)
        step.update(values)

    repository.update_run.side_effect = update_run
    repository.update_step.side_effect = update_step
    runner = MagicMock()
    runner.submit.side_effect = lambda *_args: Future()
    runner.cancellations.register.return_value = MagicMock(is_set=MagicMock(return_value=False))
    remediation = MagicMock()
    remediation.reconcile_all.return_value = {"created": 1, "reopened": 0, "resolved": 2}
    service = VmWorkflowService(repository, runner, remediation)
    return SimpleNamespace(
        service=service, repository=repository, runner=runner, workflow=workflow, remediation=remediation
    )


def test_preflight_keeps_permission_health_target_and_conflict_information(workflow_service):
    state = workflow_service
    state.repository.active.return_value = [{"workflow_id": "active", "request": {"task_id": "task-1"}}]
    state.service.configure(
        scan_starter=MagicMock(),
        verification_starter=MagicMock(),
        operation_canceller=MagicMock(),
        task_provider=lambda: [{"mp_task_id": "other"}, {"mp_task_id": "task-1", "payload": {"name": "Scoped"}}],
        status_provider=lambda: {"components": {"mpvm": {"state": "error", "message": "Offline"}}},
        operation_provider=lambda: {
            "rows": [
                {"operation_id": "done", "status": "completed", "subject_id": "task-1"},
                {"operation_id": "unrelated", "status": "running", "subject_id": "other"},
                {"operation_id": "matching", "status": "running", "subject_id": "task-1"},
            ]
        },
    )
    result = state.service.scan_preflight(task_id="task-1", options={}, can_execute=False)
    assert [issue["code"] for issue in result["blocking_issues"]] == ["PERMISSION_DENIED", "MPVM_UNAVAILABLE"]
    assert [issue["code"] for issue in result["warnings"]] == ["TARGETS_NOT_EXPLICIT", "ACTIVE_CONFLICTS"]
    assert result["task"]["name"] == "Scoped"
    assert len(result["conflicting_operations"]) == 2
    assert result["target_count"] == 0


@pytest.mark.parametrize("existing", [{"kind": "verification"}, {"kind": "scan", "retry_of": "old"}])
def test_scan_replay_cannot_reuse_other_workflow_or_retry_key(workflow_service, existing):
    state = workflow_service
    state.repository.by_idempotency_key.return_value = existing
    with pytest.raises(ValueError, match="another workflow"):
        state.service.start_scan(task_id="task-1", options={}, actor=None, idempotency_key="same")
    state.repository.create.assert_not_called()
    state.runner.submit.assert_not_called()


@pytest.mark.parametrize("key", [None, "click-key"])
def test_tracking_existing_scan_persists_child_before_monitoring(workflow_service, key):
    state = workflow_service
    result = state.service.track_scan(
        task_id="task-1", operation_id="child-1", options={}, actor="operator", idempotency_key=key
    )
    assert result["operation_id"] == "child-1"
    assert result["status"] == "running"
    assert result["stage"] == "postprocess"
    assert state.repository.create.call_args.kwargs["idempotency_key"] == (f"workflow:{key}" if key else None)
    state.runner.submit.assert_called_once_with("vm-workflow", state.service._run, "wf-1", True)


def test_tracking_an_already_linked_scan_does_not_schedule_twice(workflow_service):
    state = workflow_service
    state.repository.by_operation.return_value = {"workflow_id": "original"}
    assert state.service.track_scan(task_id="task", operation_id="child", options={}, actor=None) == {
        "workflow_id": "original"
    }
    state.repository.create.assert_not_called()
    state.runner.submit.assert_not_called()


@pytest.mark.parametrize("mode", ["missing", "active", "empty", "new", "replay"])
def test_campaign_start_handles_missing_empty_active_and_replayed_targets(workflow_service, mode):
    state = workflow_service
    targets = None if mode == "missing" else [] if mode == "empty" else ["asset-1"]
    state.repository.campaign_targets.return_value = targets
    state.repository.active_for_campaign.return_value = {"workflow_id": "already-active"} if mode == "active" else None
    state.repository.create.return_value = (state.workflow, mode == "replay")
    result, replay, selected = state.service.start_verification(
        campaign_id="campaign-1", options={}, actor=None, idempotency_key="key"
    )
    assert selected == (targets or [])
    if mode == "missing":
        assert result is None and replay is False
        state.repository.create.assert_not_called()
    elif mode == "active":
        assert result["workflow_id"] == "already-active" and replay is True
        state.repository.create.assert_not_called()
    elif mode == "empty":
        assert result["status"] == "completed" and replay is False
        assert result["result"]["asset_ids"] == []
        assert [step["status"] for step in result["steps"]] == ["completed", "skipped", "skipped", "completed"]
    elif mode == "new":
        state.repository.set_campaign_verification.assert_called_once_with("campaign-1", "wf-1", "queued")
        state.runner.submit.assert_called_once()
    else:
        assert replay is True
        state.repository.update_run.assert_not_called()
    if mode != "new":
        state.runner.submit.assert_not_called()


@pytest.mark.parametrize("method", ["start_asset_group_scan", "start_asset_group_verification"])
def test_empty_asset_group_finishes_without_child_operations(workflow_service, method):
    state = workflow_service
    result, replay = getattr(state.service, method)(
        asset_group_id="group", asset_ids=[None, ""], options={}, actor=None, idempotency_key=None
    )
    assert replay is False
    assert result["status"] == "completed"
    assert [item["status"] for item in result["steps"]] == ["completed", "skipped", "skipped", "skipped"]
    state.runner.submit.assert_not_called()


def test_scheduling_deduplicates_inflight_workers_and_releases_finished_worker(workflow_service):
    state = workflow_service
    future = Future()
    state.runner.submit.return_value = future
    state.runner.submit.side_effect = None
    state.service._schedule("wf-1")
    state.service._schedule("wf-1")
    assert state.runner.submit.call_count == 1
    future.set_result(None)
    assert "wf-1" not in state.service._scheduled
    state.service._schedule("wf-1")
    assert state.runner.submit.call_count == 2


@pytest.mark.parametrize("campaign", [None, "campaign-1"])
def test_verification_start_errors_finish_without_monitoring_or_reconciliation(workflow_service, campaign):
    state = workflow_service
    state.workflow["campaign_id"] = campaign
    errors = [{"asset_id": "asset-1", "message": "No scanner task"}, {"message": "Unavailable"}]
    state.service.verification_starter = MagicMock(return_value={"operation_ids": [], "errors": errors})
    state.service._run("wf-1", False)
    assert state.workflow["status"] == "completed_with_errors"
    assert state.workflow["result"]["start_errors"] == errors
    assert state.workflow["result"]["failed_assets"] == ["asset-1", ""]
    assert [item["status"] for item in state.workflow["steps"]] == ["completed", "failed", "skipped", "skipped"]
    if campaign:
        state.repository.finalize_campaign_verification.assert_called_once_with(campaign, "wf-1", ["asset-1"])
    else:
        state.repository.finalize_campaign_verification.assert_not_called()
    state.remediation.reconcile_all.assert_not_called()
    state.runner.cancellations.remove.assert_called_once_with("vm-workflow", "wf-1")


@pytest.mark.parametrize("status", [None, "completed", "cancelled"])
def test_worker_does_not_restart_absent_or_terminal_workflows(workflow_service, status):
    state = workflow_service
    state.repository.get.side_effect = None
    state.repository.get.return_value = None if status is None else {"status": status}
    state.service._run("wf-1", False)
    state.repository.update_run.assert_not_called()
    state.runner.cancellations.remove.assert_called_once()


def test_cancellation_at_worker_start_cancels_only_unfinished_steps(workflow_service):
    state = workflow_service
    state.workflow.update(cancel_requested=True, campaign_id="campaign-1")
    state.workflow["steps"][0]["status"] = "completed"
    state.workflow["steps"][1]["status"] = "running"
    state.service._run("wf-1", False)
    assert [step["status"] for step in state.workflow["steps"]] == ["completed", "cancelled", "cancelled", "cancelled"]
    assert state.workflow["status"] == "cancelled"
    state.repository.set_campaign_verification.assert_called_once_with(
        "campaign-1", "wf-1", "failed", "Проверка отменена."
    )


def test_monitor_tolerates_missing_operation_then_reconciles_saved_terminal_result(workflow_service, monkeypatch):
    state = workflow_service
    state.workflow["request"] = {}
    child = {"operation_id": "child", "status": "completed", "progress_percent": 100}
    lookup = MagicMock(side_effect=[None, child])
    monkeypatch.setattr(db, "get_operation", lookup)
    token = MagicMock()
    token.is_set.return_value = False
    state.service._monitor("wf-1", ["child"], token)
    token.wait.assert_called_once_with(1)
    lookup.assert_called_with("child", sync_sources=True)
    assert state.workflow["status"] == "completed"
    assert state.workflow["result"]["reconciliation"] == {"created": 1, "reopened": 0, "resolved": 2}


def test_monitor_waits_for_every_child_and_uses_all_children_as_progress_denominator(workflow_service, monkeypatch):
    state = workflow_service
    state.workflow["request"] = {"options": {"reconcile": False}}
    first = {"operation_id": "one", "status": "completed", "progress_percent": 100}
    second = {"operation_id": "two", "status": "failed", "progress_percent": 100}
    monkeypatch.setattr(db, "get_operation", MagicMock(side_effect=[first, None, first, second]))
    token = MagicMock()
    token.is_set.return_value = False
    state.service._monitor("wf-1", ["one", "two"], token)
    progress = [
        call.kwargs["progress_percent"]
        for call in state.repository.update_step.call_args_list
        if call.args[1] == "postprocess"
    ]
    assert progress == [50, 100, 100]
    token.wait.assert_called_once_with(1)
    assert state.workflow["status"] == "completed_with_errors"
    assert state.workflow["result"]["failed_operation_ids"] == ["two"]


def test_monitor_rejects_empty_child_list_and_stops_if_workflow_disappears(workflow_service):
    state = workflow_service
    with pytest.raises(RuntimeError, match="no child operations"):
        state.service._monitor("wf-1", [], MagicMock())
    state.repository.get.side_effect = None
    state.repository.get.return_value = None
    state.service._monitor("wf-1", ["child"], MagicMock())
    state.repository.update_run.assert_not_called()


@pytest.mark.parametrize("kind", ["scan", "verification"])
def test_unconfigured_starter_persists_failure_and_keeps_campaign_state(workflow_service, kind):
    state = workflow_service
    state.workflow.update(kind=kind, campaign_id="campaign-1")
    state.workflow["request"]["task_id"] = "task-1"
    state.service._run("wf-1", False)
    assert state.workflow["status"] == "failed"
    assert "not configured" in state.workflow["error"]["message"]
    state.repository.set_campaign_verification.assert_called_once()


def test_start_failure_does_not_overwrite_concurrent_terminal_cancellation(workflow_service):
    state = workflow_service

    def start(*_args):
        state.workflow["status"] = "cancelled"
        raise RuntimeError("late start failure")

    state.service.verification_starter = start
    state.service._run("wf-1", False)
    assert state.workflow["status"] == "cancelled"
    assert "error" not in state.workflow


@pytest.mark.parametrize("source", [None, {"can_retry": False}])
def test_retry_rejects_missing_or_nonretryable_workflows(workflow_service, source):
    state = workflow_service
    state.repository.get.side_effect = None
    state.repository.get.return_value = source
    assert state.service.retry("old", "operator", "key") == (None, False)
    state.repository.create.assert_not_called()
    state.runner.submit.assert_not_called()


@pytest.mark.parametrize("kind,replay", [("scan", False), ("verification", False), ("scan", True)])
def test_retry_reuses_the_request_and_does_not_schedule_a_replayed_attempt(workflow_service, kind, replay):
    state = workflow_service
    state.workflow.update(kind=kind, can_retry=True)
    state.repository.create.return_value = (state.workflow, replay)
    result, reused = state.service.retry("old", "operator", "retry-key")
    assert result is state.workflow and reused is replay
    assert state.repository.create.call_args.kwargs["request"] == state.workflow["request"]
    assert state.repository.create.call_args.kwargs["retry_of"] == "old"
    assert state.runner.submit.call_count == int(not replay)
    state.repository.set_campaign_verification.assert_not_called()


def test_cancellation_still_sets_the_local_token_without_an_operation_canceller(workflow_service):
    state = workflow_service
    state.repository.request_cancel.return_value = state.workflow
    assert state.service.cancel("wf-1") is state.workflow
    state.runner.cancellations.cancel.assert_called_once_with("vm-workflow", "wf-1")


@pytest.mark.parametrize("wait_signaled", [False, True])
def test_monitor_cancels_after_waiting_for_an_unknown_child(workflow_service, monkeypatch, wait_signaled):
    state = workflow_service
    monkeypatch.setattr(db, "get_operation", MagicMock(return_value=None))
    token = MagicMock()
    token.is_set.return_value = False

    def wait(_seconds):
        token.is_set.return_value = True
        return wait_signaled

    token.wait.side_effect = wait
    state.service._monitor("wf-1", ["not-visible-yet"], token)
    assert state.workflow["status"] == "cancelled"
    assert all(step["status"] == "cancelled" for step in state.workflow["steps"])
    state.remediation.reconcile_all.assert_not_called()


def test_persisted_cancellation_stops_monitor_even_without_a_signaled_token(workflow_service, monkeypatch):
    state = workflow_service
    state.workflow["cancel_requested"] = True
    lookup = MagicMock()
    monkeypatch.setattr(db, "get_operation", lookup)
    token = MagicMock(is_set=MagicMock(return_value=False))
    state.service._monitor("wf-1", ["child"], token)
    assert state.workflow["status"] == "cancelled"
    lookup.assert_not_called()


def test_worker_monitors_a_persisted_child_without_starting_another_scan(workflow_service):
    state = workflow_service
    state.workflow["result"] = {"operation_ids": ["persisted-child"]}
    state.service.verification_starter = MagicMock()
    state.service._monitor = MagicMock()
    state.service._run("wf-1", True)
    state.service.verification_starter.assert_not_called()
    assert state.service._monitor.call_args.args[:2] == ("wf-1", ["persisted-child"])


@pytest.mark.parametrize("kind", ["scan", "verification"])
def test_recovery_without_any_saved_child_persists_failure_without_reconciliation(workflow_service, kind):
    state = workflow_service
    state.workflow["kind"] = kind
    state.service._run("wf-1", True)
    assert state.workflow["status"] == "failed"
    assert state.workflow["error"]["message"] == "Workflow has no child operations."
    state.remediation.reconcile_all.assert_not_called()


def test_monitor_does_not_repeat_unchanged_progress_updates(workflow_service, monkeypatch):
    state = workflow_service
    state.workflow["steps"][2]["progress_percent"] = 100
    state.workflow["request"] = {"options": {"reconcile": False}}
    monkeypatch.setattr(
        db,
        "get_operation",
        MagicMock(
            return_value={
                "operation_id": "child",
                "status": "completed",
                "progress_percent": 100,
            }
        ),
    )
    state.service._monitor("wf-1", ["child"], MagicMock(is_set=MagicMock(return_value=False)))
    assert state.workflow["status"] == "completed"
    assert not any(
        call.args[1] == "postprocess" and "status" not in call.kwargs
        for call in state.repository.update_step.call_args_list
    )
