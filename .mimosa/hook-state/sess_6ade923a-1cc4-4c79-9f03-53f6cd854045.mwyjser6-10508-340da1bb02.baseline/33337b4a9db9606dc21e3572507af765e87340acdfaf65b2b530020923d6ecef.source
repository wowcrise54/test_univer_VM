"""Persist workflow failures and cancellation without calling MP VM."""
from unittest.mock import MagicMock

import pytest

from app.repositories.vm_workflows import VmWorkflowRepository
from app.services.vm_workflows import VmWorkflowService

pytestmark = pytest.mark.integration


def create_scan(repository):
    workflow, replay = repository.create(
        kind="scan", request={"task_id": "local-test-task", "options": {}},
        requested_by="operator",
    )
    assert not replay
    return workflow["workflow_id"]


@pytest.mark.parametrize("reject_start", [False, True])
def test_failed_scan_start_is_persisted_and_never_restarted(test_db, reject_start):
    repository = VmWorkflowRepository()
    workflow_id = create_scan(repository)
    runner = MagicMock()
    service = VmWorkflowService(repository, runner, remediation=object())
    starter = MagicMock()
    if reject_start:
        starter.return_value = {"status": "rejected", "error": "Local test rejection"}
    else:
        starter.side_effect = RuntimeError("Local test rejection")
    service.scan_starter = starter

    service._run(workflow_id, False)
    failed = repository.get(workflow_id)
    assert failed["status"] == failed["stage"] == "failed"
    assert failed["started_at"] and failed["finished_at"]
    assert failed["error"] == {"message": "Local test rejection"}
    assert failed["can_retry"] and not failed["can_cancel"]
    validation = next(step for step in failed["steps"] if step["step_key"] == "validation")
    assert validation["status"] == "failed"
    assert validation["error"] == failed["error"]
    assert validation["started_at"] and validation["finished_at"]
    runner.cancellations.remove.assert_called_once_with("vm-workflow", workflow_id)

    service._run(workflow_id, False)
    starter.assert_called_once()
    assert repository.get(workflow_id)["error"] == failed["error"]


def test_cancelled_before_start_persists_all_steps_and_skips_remote_start(test_db):
    repository = VmWorkflowRepository()
    workflow_id = create_scan(repository)
    repository.request_cancel(workflow_id)
    runner = MagicMock()
    service = VmWorkflowService(repository, runner, remediation=object())
    service.scan_starter = MagicMock()

    service._run(workflow_id, False)
    cancelled = repository.get(workflow_id)
    assert cancelled["status"] == "cancelled"
    assert cancelled["finished_at"]
    assert all(step["status"] == "cancelled" and step["finished_at"] for step in cancelled["steps"])
    service.scan_starter.assert_not_called()
    runner.cancellations.remove.assert_called_once_with("vm-workflow", workflow_id)


def test_started_scan_persists_child_operation_before_monitoring(test_db):
    repository = VmWorkflowRepository()
    workflow_id = create_scan(repository)
    operation_id = "00000000-0000-0000-0000-000000000001"
    runner = MagicMock()
    service = VmWorkflowService(repository, runner, remediation=object())
    service.scan_starter = MagicMock(return_value={"status": "started", "operation_id": operation_id})
    service._monitor = MagicMock()

    service._run(workflow_id, False)
    running = repository.get(workflow_id)
    assert running["status"] == "running"
    assert running["stage"] == "postprocess"
    assert running["operation_id"] == operation_id
    assert running["progress_percent"] == 35
    steps = {step["step_key"]: step for step in running["steps"]}
    assert steps["validation"]["status"] == steps["scan"]["status"] == "completed"
    assert steps["scan"]["result"] == {"task_id": "local-test-task"}
    assert steps["postprocess"]["status"] == "running"
    assert steps["postprocess"]["operation_id"] == operation_id
    service._monitor.assert_called_once_with(workflow_id, [operation_id], runner.cancellations.register.return_value)
