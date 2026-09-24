import threading
import time
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from app import auth
from app.repositories.vm_workflows import VmWorkflowRepository
from app.services.vm_workflows import VmPreflightBlocked, VmWorkflowService


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
    assert auth.required_permission("POST", "/api/vm/workflows/scan/preflight") == "tasks.read"
    assert auth.required_permission("POST", "/api/vm/workflows/wf-1/cancel") == "operations.cancel"
    assert auth.required_permission("POST", "/api/vm/workflows/wf-1/retry") == "operations.retry"


def test_scan_preflight_separates_warnings_from_blocking_conflicts():
    repository, runner = FakeRepository(), FakeRunner()
    repository.active = lambda: []
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())
    service.task_provider = lambda: [{
        "mp_task_id": "task-1", "name": "Production",
        "include_targets": ["10.0.0.1", "10.0.0.2"],
    }]
    service.status_provider = lambda: {"components": {"mpvm": {"state": "ok"}}}
    service.operation_provider = lambda: {"rows": [{
        "operation_id": "op-1", "status": "running", "request": {"task_id": "task-1"},
    }]}

    warning = service.scan_preflight(task_id="task-1", options={"require_clean_jobs": False})
    blocked = service.scan_preflight(task_id="task-1", options={"require_clean_jobs": True})

    assert warning["ready"] is True
    assert warning["target_count"] == 2
    assert warning["warnings"][0]["code"] == "ACTIVE_CONFLICTS"
    assert blocked["ready"] is False
    assert blocked["blocking_issues"][0]["code"] == "ACTIVE_CONFLICTS"


def test_start_scan_repeats_preflight_and_does_not_create_blocked_workflow():
    repository, runner = FakeRepository(), FakeRunner()
    repository.active = lambda: []
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())
    service.task_provider = lambda: []
    service.status_provider = lambda: {"components": {"mpvm": {"state": "ok"}}}

    try:
        service.start_scan(task_id="missing", options={}, actor="operator", idempotency_key="key")
    except VmPreflightBlocked as exc:
        assert exc.result["blocking_issues"][0]["code"] == "TASK_NOT_FOUND"
    else:
        raise AssertionError("Blocked workflow was created")


def test_repeated_start_returns_idempotent_workflow_before_new_preflight():
    repository, runner = FakeRepository(), FakeRunner()
    existing = {"workflow_id": "wf-existing", "kind": "scan", "status": "running",
                "request": {"task_id": "task-1", "options": {"require_clean_jobs": True}}}
    repository.by_idempotency_key = lambda _key: existing
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())
    service.task_provider = lambda: []

    workflow, replay = service.start_scan(
        task_id="task-1", options={"require_clean_jobs": True},
        actor="operator", idempotency_key="same-click",
    )

    assert replay is True
    assert workflow["workflow_id"] == "wf-existing"
    assert runner.submitted == []


def test_asset_group_scan_uses_verification_steps_without_reconcile():
    repository, runner = FakeRepository(), FakeRunner()
    repository.by_idempotency_key = lambda _key: None
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())

    workflow, replay = service.start_asset_group_scan(
        asset_group_id="group-1",
        asset_ids=["asset-1", "asset-1", "asset-2"],
        options={"template_task_id": "template-1"},
        actor="operator",
        idempotency_key="group-scan",
    )

    assert replay is False
    assert workflow["kind"] == "verification"
    assert workflow["request"]["asset_group_id"] == "group-1"
    assert workflow["request"]["asset_ids"] == ["asset-1", "asset-2"]
    assert workflow["request"]["options"]["reconcile"] is False
    assert workflow["request"]["options"]["mode"] == "group_scan"
    assert runner.submitted[0][0] == "vm-workflow"


def test_asset_group_verification_keeps_reconcile_enabled():
    repository, runner = FakeRepository(), FakeRunner()
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())

    workflow, _ = service.start_asset_group_verification(
        asset_group_id="group-1",
        asset_ids=["asset-1"],
        options={},
        actor="operator",
        idempotency_key=None,
    )

    assert workflow["request"]["options"]["reconcile"] is True
    assert workflow["request"]["options"]["mode"] == "group_verification"


def test_asset_group_replay_is_validated_against_the_persisted_request():
    existing = {
        "workflow_id": "wf-existing",
        "kind": "verification",
        "status": "running",
        "request": {
            "asset_group_id": "group-1",
            "asset_ids": ["asset-1"],
            "options": {"reconcile": False, "mode": "group_scan"},
        },
    }

    class ValidatingRepository(FakeRepository):
        def __init__(self):
            super().__init__()
            self.created = []

        def create(self, **values):
            self.created.append(values)
            VmWorkflowRepository._validate_idempotency_replay(
                existing,
                kind=values["kind"],
                request=values["request"],
                retry_of=values.get("retry_of"),
            )
            return existing, True

    repository = ValidatingRepository()
    runner = MagicMock()
    service = VmWorkflowService(repository, runner, remediation=object())

    with pytest.raises(ValueError, match="different workflow request"):
        service.start_asset_group_scan(
            asset_group_id="group-2",
            asset_ids=["asset-2"],
            options={"template_task_id": "template-2"},
            actor="operator",
            idempotency_key="same-click",
        )

    assert repository.created == [{
        "kind": "verification",
        "request": {
            "asset_group_id": "group-2",
            "asset_ids": ["asset-2"],
            "options": {
                "template_task_id": "template-2",
                "reconcile": False,
                "mode": "group_scan",
            },
        },
        "requested_by": "operator",
        "idempotency_key": "same-click",
    }]


def test_resume_monitors_workflow_with_persisted_child_operation_ids():
    repository = MagicMock()
    runner = MagicMock()
    repository.active.return_value = [{
        "workflow_id": "wf-multi",
        "operation_id": None,
        "result": {"operation_ids": ["op-1", "op-2"]},
    }]
    service = VmWorkflowService(repository, runner, remediation=object())

    service.resume()

    runner.submit.assert_called_once()
    assert runner.submit.call_args.args[:2] == ("vm-workflow", service._run)
    assert runner.submit.call_args.args[2:] == ("wf-multi", True)


def test_group_scan_reconcile_step_is_skipped_after_postprocess():
    repository = MagicMock()
    runner = MagicMock()
    remediation = MagicMock()
    service = VmWorkflowService(repository, runner, remediation=remediation)
    workflow = {
        "workflow_id": "wf-group-scan",
        "kind": "verification",
        "campaign_id": None,
        "request": {"asset_ids": ["asset-1"], "options": {"reconcile": False}},
        "result": {},
    }

    service._reconcile("wf-group-scan", workflow, [{"operation_id": "op-1", "status": "completed"}], [])

    remediation.reconcile_asset.assert_not_called()
    reconcile_call = [call for call in repository.update_step.call_args_list if call.args[1] == "reconcile"][-1]
    assert reconcile_call.kwargs["status"] == "skipped"
    assert repository.update_run.call_args.kwargs["status"] == "completed"


def test_retry_group_verification_does_not_require_campaign_id():
    repository = MagicMock()
    runner = MagicMock()
    source = {
        "workflow_id": "wf-source",
        "kind": "verification",
        "status": "failed",
        "can_retry": True,
        "request": {"asset_group_id": "group-1", "asset_ids": ["asset-1"], "options": {"mode": "group_verification"}},
        "steps": [],
    }
    retried = {**source, "workflow_id": "wf-retry", "status": "queued", "can_retry": False}
    repository.get.side_effect = [source, retried]
    repository.create.return_value = (retried, False)
    service = VmWorkflowService(repository, runner, remediation=object())

    result, replay = service.retry("wf-source", "operator", "retry-key")

    assert replay is False
    assert result["workflow_id"] == "wf-retry"
    repository.set_campaign_verification.assert_not_called()


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


def test_campaign_finalization_uses_operation_subject_and_start_error_asset_ids():
    repository = MagicMock()
    runner = MagicMock()
    remediation = MagicMock()
    remediation.reconcile_asset.return_value = {"created": 0, "reopened": 0, "resolved": 0}
    service = VmWorkflowService(repository, runner, remediation=remediation)
    workflow = {
        "workflow_id": "wf-campaign",
        "kind": "verification",
        "campaign_id": "campaign-1",
        "request": {"asset_ids": ["asset-1", "asset-2"], "options": {"reconcile": True}},
        "result": {"start_errors": [{"asset_id": "asset-2", "message": "start failed"}]},
    }
    failed = [{
        "operation_id": "op-1",
        "status": "failed",
        "subject": {"id": "asset-1"},
    }]

    service._reconcile("wf-campaign", workflow, failed, failed)

    repository.finalize_campaign_verification.assert_called_once_with(
        "campaign-1", "wf-campaign", ["asset-1", "asset-2"],
    )


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


# ---------------------------------------------------------------------------
# Regression: idempotency key reuse with a *different* scan request.
#
# Before the fix, `start_scan` returned the existing workflow for ANY replay
# matching the key, silently ignoring a changed `task_id` or `options`.
# ---------------------------------------------------------------------------


def test_repeated_idempotency_key_with_different_task_id_is_rejected():
    repository, runner = FakeRepository(), FakeRunner()
    existing = {
        "workflow_id": "wf-existing", "kind": "scan", "status": "running",
        "request": {"task_id": "task-1", "options": {}},
    }
    repository.by_idempotency_key = lambda _key: existing
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())

    with pytest.raises(ValueError) as exc_info:
        service.start_scan(
            task_id="task-2", options={}, actor="operator", idempotency_key="same-click",
        )

    assert "different scan request" in str(exc_info.value)
    assert runner.submitted == []


def test_repeated_idempotency_key_with_changed_options_is_rejected():
    repository, runner = FakeRepository(), FakeRunner()
    existing = {
        "workflow_id": "wf-existing", "kind": "scan", "status": "running",
        "request": {"task_id": "task-1", "options": {"require_clean_jobs": False}},
    }
    repository.by_idempotency_key = lambda _key: existing
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())

    with pytest.raises(ValueError):
        service.start_scan(
            task_id="task-1",
            options={"require_clean_jobs": True},
            actor="operator",
            idempotency_key="same-click",
        )

    assert runner.submitted == []


def test_identical_idempotent_scan_replay_still_returns_existing_workflow():
    repository, runner = FakeRepository(), FakeRunner()
    existing = {
        "workflow_id": "wf-existing", "kind": "scan", "status": "running",
        "request": {"task_id": "task-1", "options": {"require_clean_jobs": True}},
    }
    repository.by_idempotency_key = lambda _key: existing
    service = VmWorkflowService(cast(Any, repository), cast(Any, runner), remediation=object())

    workflow, replay = service.start_scan(
        task_id="task-1",
        options={"require_clean_jobs": True},
        actor="operator",
        idempotency_key="same-click",
    )

    assert replay is True
    assert workflow["workflow_id"] == "wf-existing"
    assert runner.submitted == []


# ---------------------------------------------------------------------------
# Regression: a disabled local user must not be resurrected by an LDAP login.
# (Integration coverage with a real PostgreSQL lives in tests/integration.)
# ---------------------------------------------------------------------------


def test_ldap_login_rejects_disabled_local_user():
    """A locally disabled account stays disabled even when LDAP verifies it."""
    from app import main
    from fastapi.testclient import TestClient

    identity = {"username": "ivan.petrov", "display_name": "Ivan Petrov", "role": "viewer"}

    with patch.object(auth, "authenticate", lambda u, p: None), \
         patch.object(auth, "resolve_ldap_identity", lambda u, p: identity), \
         patch.object(auth, "_local_user_record", return_value=None), \
         patch.object(auth, "_provision_ldap_user") as provision, \
         patch.object(auth, "audit_event"), \
         patch.object(auth.db, "connect", side_effect=_fake_connect({"is_active": False})):
        response = TestClient(main.app).post(
            "/api/auth/login",
            json={"username": "ivan.petrov", "password": "secret"},
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"
    provision.assert_not_called()


def _fake_connect(row):
    class _Result:
        def fetchone(self):
            return row

    class _Query:
        def fetchone(self):
            return row

    class _Conn:
        def execute(self, sql, params=()):
            return _Query()

    class _Ctx:
        def __enter__(self):
            return _Conn()

        def __exit__(self, *exc):
            return False

    return lambda: _Ctx()
