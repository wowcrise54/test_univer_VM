from pathlib import Path
from typing import Any, cast

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
