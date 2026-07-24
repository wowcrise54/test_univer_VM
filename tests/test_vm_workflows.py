import threading
import time
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

from app import auth
from app.services.vm_workflows import VmWorkflowService


class ImmediateFuture:
    def add_done_callback(self, callback):
        callback(self)


class FakeCancellations:
    def __init__(self):
        self.cancelled = []

    def cancel(self, kind, value):
        self.cancelled.append((kind, value))
        return True


class FakeRunner:
    def __init__(self):
        self.submitted = []
        self.cancellations = FakeCancellations()

    def submit(self, queue, function, *args):
        self.submitted.append((queue, function, args))
        return ImmediateFuture()


class FakeRepository:
    def __init__(self):
        self.workflow = {"workflow_id": "wf-1", "kind": "scan", "status": "queued", "steps": [], "request": {}}
    def create(self, **values):
        self.workflow = {**self.workflow, "kind": values["kind"], "request": values["request"]}
        return self.workflow, False
    def get(self, _workflow_id): return self.workflow


def test_scan_workflow_is_persisted_before_it_is_scheduled():
    repository, runner = FakeRepository(), FakeRunner()
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())
    workflow, replay = service.start_scan(task_id="task-1", options={"wait_for_finish": True}, actor="operator", idempotency_key="key-1")
    assert not replay
    assert workflow["request"]["task_id"] == "task-1"
    assert runner.submitted[0][0] == "vm-workflow"


def test_vm_api_permissions_reuse_existing_fine_grained_catalog():
    assert auth.required_permission("GET", "/api/vm/overview") == "operations.read"
    assert auth.required_permission("POST", "/api/vm/workflows/scan") == "tasks.execute"
    assert auth.required_permission("POST", "/api/vm/workflows/wf-1/cancel") == "operations.cancel"
    assert auth.required_permission("POST", "/api/vm/workflows/wf-1/retry") == "operations.retry"


def test_vm_migration_is_additive_and_links_verification():
    source = Path("migrations/versions/20260714_0011_vm_workflows.py").read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS vm_workflow_runs" in source
    assert "CREATE TABLE IF NOT EXISTS vm_workflow_steps" in source
    assert "ADD COLUMN IF NOT EXISTS verification_status" in source
    assert "DROP TABLE" not in source.split("def upgrade()", 1)[1].split("def downgrade()", 1)[0]


def test_reconciliation_error_is_isolated_and_workflow_completes_with_errors():
    repository = MagicMock()
    runner = MagicMock()
    remediation = MagicMock()
    remediation.reconcile_asset.side_effect = [RuntimeError("asset unavailable"), {"created": 1, "reopened": 0, "resolved": 0}]
    service = VmWorkflowService(repository, runner, remediation=remediation)
    workflow = {
        "workflow_id": "wf-1",
        "kind": "verification",
        "campaign_id": None,
        "request": {"asset_ids": ["asset-1", "asset-2"]},
        "result": {},
    }

    service._reconcile("wf-1", workflow, [], [])

    run_update = repository.update_run.call_args.kwargs
    assert run_update["status"] == "completed_with_errors"
    assert run_update["result"]["reconciliation"]["created"] == 1
    assert run_update["result"]["reconciliation_errors"][0]["asset_id"] == "asset-1"


def test_reconciliation_runs_independent_assets_in_parallel():
    repository = MagicMock()
    runner = MagicMock()
    state_lock = threading.Lock()
    active = 0
    peak_active = 0

    def reconcile(_asset_id):
        nonlocal active, peak_active
        with state_lock:
            active += 1
            peak_active = max(peak_active, active)
        time.sleep(0.05)
        with state_lock:
            active -= 1
        return {"created": 1, "reopened": 0, "resolved": 0}

    remediation = MagicMock()
    remediation.reconcile_asset.side_effect = reconcile
    service = VmWorkflowService(repository, runner, remediation=remediation, reconciliation_workers=3)
    workflow = {
        "workflow_id": "wf-parallel",
        "kind": "verification",
        "campaign_id": None,
        "request": {"asset_ids": ["asset-1", "asset-2", "asset-3"]},
        "result": {},
    }

    started = time.perf_counter()
    service._reconcile("wf-parallel", workflow, [], [])
    elapsed = time.perf_counter() - started

    assert peak_active == 3
    assert elapsed < 0.11
    assert repository.update_run.call_args.kwargs["result"]["reconciliation"]["created"] == 3
