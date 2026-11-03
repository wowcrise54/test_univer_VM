"""Precheck tasks follow their audit task: deleted with it and after it finishes."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from app import db
from app.api.schemas import DeleteScannerTaskRequest
from app.services import scan_postprocess, scanner_task_launch

pytestmark = pytest.mark.integration


def _task(mp_task_id, *, parent=None, status="created", response=None):
    db.record_scan_task(
        mp_task_id=mp_task_id,
        payload={"name": mp_task_id, "include": {"targets": ["10.0.0.1"]}},
        status=status,
        remote_response=response,
        parent_task_id=parent,
    )


@pytest.fixture
def tasks(test_db):
    _task("audit")
    _task("pre-1", parent="audit", status="precheck_finished", response={"false_targets": ["10.0.0.9"], "audit_task_id": "audit"})
    _task("pre-2", parent="audit", status="precheck_failed")
    _task("other")
    _task("pre-other", parent="other", status="precheck_finished")


def _ids():
    return {row["mp_task_id"] for row in db.list_scan_tasks()}


def test_cleanup_deletes_prechecks_in_mpvm_but_keeps_their_local_result(tasks):
    client = MagicMock()
    result = scanner_task_launch.cleanup_precheck_tasks(client=client, token="t", audit_task_id="audit")

    assert result == {"deleted": 2, "failed": 0}
    assert [call.args[1] for call in client.delete_scanner_task.call_args_list] == ["pre-1", "pre-2"]
    assert _ids() == {"audit", "other", "pre-other"}
    assert db.get_scan_task("pre-1")["last_remote_response"]["false_targets"] == ["10.0.0.9"]
    assert db.list_child_scan_task_ids("audit") == []
    assert scanner_task_launch.cleanup_precheck_tasks(client=client, token="t", audit_task_id="audit") == {
        "deleted": 0, "failed": 0}


def test_failed_remote_delete_is_retried_next_time(tasks):
    client = MagicMock()
    client.delete_scanner_task.side_effect = [requests.ConnectionError("down"), {}]
    assert scanner_task_launch.cleanup_precheck_tasks(client=client, token="t", audit_task_id="audit") == {
        "deleted": 1, "failed": 1}
    assert db.list_child_scan_task_ids("audit") == ["pre-1"]


def test_deleting_the_audit_task_deletes_its_prechecks_everywhere(tasks):
    client = MagicMock()
    with patch("app.main.require_mpvm", return_value=(client, "t")), \
            patch.object(scanner_task_launch, "remote_scanner_task_exists", return_value=True), \
            patch("app.main.CONTAINER", MagicMock()):
        client.delete_scanner_task.return_value = {"id": "audit"}
        scanner_task_launch.delete_scanner_task_impl("audit", DeleteScannerTaskRequest(mode="auto"))

    assert [call.args[1] for call in client.delete_scanner_task.call_args_list] == ["audit", "pre-1", "pre-2"]
    assert _ids() == {"other", "pre-other"}


def test_local_only_delete_removes_prechecks_without_calling_mpvm(tasks):
    with patch("app.main.CONTAINER", MagicMock()):
        scanner_task_launch.delete_scanner_task_impl("audit", DeleteScannerTaskRequest(mode="local_only"))
    assert _ids() == {"other", "pre-other"}


def test_finished_run_cleanup_never_raises(tasks):
    client = MagicMock()
    client.delete_scanner_task.side_effect = RuntimeError("boom")
    scan_postprocess.cleanup_finished_task_prechecks(client=client, token="t", task_id="audit")
    scan_postprocess.cleanup_finished_task_prechecks(client=MagicMock(), token="t", task_id="audit")
    assert db.list_child_scan_task_ids("audit") == []


def test_migration_backfills_the_parent_of_existing_precheck_rows(test_db):
    from app.db import connect

    with connect() as conn:
        for task_id, status, response in (
            ("old-pre", "precheck_finished", '{"audit_task_id": "audit-x", "false_targets": []}'),
            ("old-bad", "precheck_failed", "not json"),
            ("old-audit", "created", '{"audit_task_id": "ignored"}'),
        ):
            conn.execute(
                """INSERT INTO scan_tasks(mp_task_id,name,payload_json,status,last_remote_response_json,created_at,updated_at)
                   VALUES(%s,%s,'{}',%s,%s,'now','now')""",
                (task_id, task_id, status, response),
            )
        from importlib import import_module

        migration = import_module("migrations.versions.20261103_0032_scan_task_parent")
        with patch.object(migration, "op") as op:
            migration.upgrade()
        for statement in (call.args[0] for call in op.execute.call_args_list):
            conn.execute(statement)
        rows = {r["mp_task_id"]: r["parent_task_id"] for r in conn.execute("SELECT mp_task_id,parent_task_id FROM scan_tasks").fetchall()}
    assert rows == {"old-pre": "audit-x", "old-bad": None, "old-audit": None}
