"""Behavioural tests for the HTTP handlers that live in ``app/api/*``.

The handlers are thin: they translate HTTP into calls on the repository /
service layer and map domain errors to status codes. These tests drive them
through the real FastAPI app (so the auth middleware, routing and response
serialisation are exercised) and replace only the layer below the handler.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psycopg.errors
import pytest
import requests
from fastapi.testclient import TestClient

from app import auth, db, main
from app.mpvm_client import MpVmApiError

ADMIN = {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin", "is_active": True}


@pytest.fixture
def client():
    with patch.object(auth, "get_session_user", return_value=ADMIN), patch.object(auth, "audit_event"):
        yield TestClient(main.app)


@pytest.fixture
def repo():
    repository = MagicMock(name="AUTOMATION_REPOSITORY")
    with patch.object(main, "AUTOMATION_REPOSITORY", repository):
        yield repository


@pytest.fixture
def service():
    automation_service = MagicMock(name="automation_service")
    with patch.object(main, "get_automation_service", return_value=automation_service):
        yield automation_service


RUNBOOK = {"name": "Nightly", "description": "d", "steps": [{"step_id": "s1", "type": "pdql_export", "config": {}}]}


# --------------------------------------------------------------------------- automations


def test_automation_templates_and_lists(client, repo):
    repo.list_runbooks.return_value = [{"runbook_id": "r1"}]
    repo.list_schedules.return_value = [{"schedule_id": "s1"}]
    repo.list_runs.return_value = [{"run_id": "run-1"}]

    assert client.get("/api/automations/templates").json()["rows"]
    assert client.get("/api/automations/runbooks").json() == {"rows": [{"runbook_id": "r1"}]}
    assert client.get("/api/automations/schedules").json() == {"rows": [{"schedule_id": "s1"}]}
    assert client.get("/api/automations/runs?limit=9999").json() == {"rows": [{"run_id": "run-1"}]}
    repo.list_runs.assert_called_once_with(limit=500)


def test_create_runbook_maps_domain_errors(client, service):
    service.create_runbook.return_value = {"runbook_id": "r1"}
    created = client.post("/api/automations/runbooks", json=RUNBOOK)
    assert created.status_code == 201 and created.json() == {"runbook_id": "r1"}

    service.create_runbook.side_effect = ValueError("bad step")
    assert client.post("/api/automations/runbooks", json=RUNBOOK).status_code == 422

    service.create_runbook.side_effect = psycopg.errors.UniqueViolation("duplicate")
    assert client.post("/api/automations/runbooks", json=RUNBOOK).status_code == 409


def test_get_update_delete_runbook(client, repo, service):
    repo.get_runbook.return_value = None
    assert client.get("/api/automations/runbooks/r1").status_code == 404
    repo.get_runbook.return_value = {"runbook_id": "r1"}
    assert client.get("/api/automations/runbooks/r1").json() == {"runbook_id": "r1"}

    service.update_runbook.return_value = {"runbook_id": "r1", "name": "Nightly"}
    assert client.put("/api/automations/runbooks/r1", json=RUNBOOK).json()["name"] == "Nightly"
    service.update_runbook.return_value = None
    assert client.put("/api/automations/runbooks/r1", json=RUNBOOK).status_code == 404
    service.update_runbook.side_effect = ValueError("bad")
    assert client.put("/api/automations/runbooks/r1", json=RUNBOOK).status_code == 422

    repo.delete_runbook.return_value = True
    assert client.delete("/api/automations/runbooks/r1").json() == {"runbook_id": "r1", "deleted": True}
    repo.delete_runbook.return_value = False
    assert client.delete("/api/automations/runbooks/r1").status_code == 404


def test_clone_publish_and_run_runbook(client, repo, service):
    repo.get_runbook.return_value = None
    assert client.post("/api/automations/runbooks/r1/clone").status_code == 404
    repo.get_runbook.return_value = {"name": "Nightly", "description": None, "draft": {"steps": []}}
    service.create_runbook.return_value = {"runbook_id": "r2"}
    assert client.post("/api/automations/runbooks/r1/clone").status_code == 201
    assert service.create_runbook.call_args.args[0] == "Nightly — копия"

    service.publish.return_value = {"version": 1}
    assert client.post("/api/automations/runbooks/r1/publish", json={"confirm_name": "Nightly"}).json() == {"version": 1}
    service.publish.return_value = None
    assert client.post("/api/automations/runbooks/r1/publish", json={"confirm_name": "x"}).status_code == 404
    service.publish.side_effect = PermissionError("confirm the runbook name")
    assert client.post("/api/automations/runbooks/r1/publish", json={"confirm_name": "x"}).status_code == 409

    service.start_run.return_value = {"run_id": "run-1"}
    started = client.post("/api/automations/runbooks/r1/run", json={"dry_run": True}, headers={"X-Idempotency-Key": "k1"})
    assert started.status_code == 202
    assert service.start_run.call_args.kwargs == {"dry_run": True, "idempotency_key": "k1"}
    service.start_run.side_effect = ValueError("not published")
    assert client.post("/api/automations/runbooks/r1/run", json={}).status_code == 409


def test_schedule_lifecycle(client, repo, service):
    body = {"runbook_id": "r1", "name": "Daily", "cron_expression": "0 3 * * *", "timezone": "UTC", "enabled": True}

    repo.get_version.return_value = None
    assert client.post("/api/automations/schedules", json=body).status_code == 409
    repo.get_version.return_value = {"version": 1}
    service.next_run.side_effect = ValueError("bad cron")
    assert client.post("/api/automations/schedules", json=body).status_code == 422
    service.next_run.side_effect = None
    service.next_run.return_value = "2026-01-02T03:00:00+00:00"
    repo.create_schedule.return_value = {"schedule_id": "s1"}
    assert client.post("/api/automations/schedules", json=body).status_code == 201

    repo.update_schedule.return_value = {"schedule_id": "s1"}
    assert client.put("/api/automations/schedules/s1", json=body).json() == {"schedule_id": "s1"}
    repo.update_schedule.return_value = None
    assert client.put("/api/automations/schedules/s1", json=body).status_code == 404
    service.next_run.side_effect = ValueError("bad cron")
    assert client.put("/api/automations/schedules/s1", json=body).status_code == 422

    repo.delete_schedule.return_value = True
    assert client.delete("/api/automations/schedules/s1").json() == {"schedule_id": "s1", "deleted": True}
    repo.delete_schedule.return_value = False
    assert client.delete("/api/automations/schedules/s1").status_code == 404


def test_run_detail_cancel_and_retry(client, repo, service):
    repo.get_run.return_value = None
    assert client.get("/api/automations/runs/run-1").status_code == 404
    repo.get_run.return_value = {"run_id": "run-1", "runbook_id": "r1", "steps": []}
    assert client.get("/api/automations/runs/run-1").json()["run_id"] == "run-1"

    repo.request_cancel.return_value = False
    assert client.post("/api/automations/runs/run-1/cancel").status_code == 409

    repo.request_cancel.return_value = True
    repo.get_run.return_value = {
        "run_id": "run-1",
        "steps": [{"child_operation_id": None}, {"child_operation_id": "child-1"}, {"child_operation_id": "child-2"}],
    }
    with patch.object(db, "get_operation", return_value={"can_cancel": True}), patch.object(main, "cancel_operation") as cancel:
        result = client.post("/api/automations/runs/run-1/cancel")
    assert result.status_code == 200
    cancel.assert_called_once_with("child-1")  # only the first cancellable child is cancelled

    repo.get_run.return_value = None
    assert client.post("/api/automations/runs/run-1/cancel").json() == {"run_id": "run-1", "status": "cancelling"}

    assert client.post("/api/automations/runs/run-1/retry").status_code == 404
    repo.get_run.return_value = {"runbook_id": "r1"}
    service.start_run.return_value = {"run_id": "run-2"}
    assert client.post("/api/automations/runs/run-1/retry").status_code == 202
    service.start_run.assert_called_with("r1", trigger_type="retry")


def test_notifications(client, repo):
    repo.list_notifications.return_value = {"rows": [], "unread": 0}
    assert client.get("/api/notifications?unread_only=true&limit=0").json() == {"rows": [], "unread": 0}
    repo.list_notifications.assert_called_once_with(unread_only=True, limit=1)

    repo.mark_notification_read.return_value = True
    assert client.post("/api/notifications/n1/read").json() == {"notification_id": "n1", "is_read": True}
    repo.mark_notification_read.return_value = False
    assert client.post("/api/notifications/n1/read").status_code == 404


# ---------------------------------------------------------------------------- operations


@pytest.fixture
def container():
    fake = MagicMock(name="CONTAINER")
    with patch.object(main, "CONTAINER", fake):
        yield fake


def test_operations_list_summary_and_history(client, container):
    container.services.operations.list.return_value = {"rows": []}
    assert client.get("/api/operations?status=running&sort_dir=asc").json() == {"rows": []}
    container.services.operations.list.side_effect = ValueError("unknown column")
    failed = client.get("/api/operations?sort_by=nope")
    assert failed.status_code == 422 and failed.json()["detail"]["code"] == "INVALID_SORT"

    container.services.operations.summary.return_value = {"active": 1}
    assert client.get("/api/operations/summary").json() == {"active": 1}

    container.services.operations.clear_history.return_value = {"cleared": 2}
    assert client.post("/api/operations/clear-history").json() == {"cleared": 2}
    container.services.operations.clear_history.assert_called_once_with(actor="admin")


def test_operation_detail_and_saved_views(client, container):
    container.repositories.operations.get.return_value = None
    assert client.get("/api/operations/op-1").status_code == 404
    container.repositories.operations.get.return_value = {"operation_id": "op-1"}
    assert client.get("/api/operations/op-1").json() == {"operation_id": "op-1"}

    container.repositories.operations.saved_views.return_value = [{"id": 1}]
    assert client.get("/api/saved-views?route=/operations").json() == {"rows": [{"id": 1}]}

    with patch.object(db, "save_view", return_value={"id": 2}) as save:
        assert client.post("/api/saved-views", json={"route": " /operations ", "name": " Mine ", "filters": {"q": "x"}}).json() == {"id": 2}
    save.assert_called_once_with("/operations", "Mine", {"q": "x"})

    with patch.object(db, "delete_saved_view", return_value=True):
        assert client.delete("/api/saved-views/2").json() == {"id": 2, "deleted": True}
    with patch.object(db, "delete_saved_view", return_value=False):
        assert client.delete("/api/saved-views/2").status_code == 404


@pytest.mark.parametrize(
    ("kind", "handler"),
    [
        ("asset_card_build", "cancel_asset_card_build_job"),
        ("passport_detail_sync", "cancel_vulnerability_passport_detail_job"),
        ("passport_catalog_refresh", "cancel_vulnerability_passport_refresh_job"),
        ("scan_postprocess", "cancel_scan_postprocess_run"),
    ],
)
def test_cancel_operation_dispatches_by_kind(client, container, kind, handler):
    operation = {"operation_id": "op-1", "kind": kind, "source_id": "src-1", "can_cancel": True}
    with patch.object(db, "get_operation", return_value=operation), patch.object(main, handler) as cancel:
        assert client.post("/api/operations/op-1/cancel").status_code == 200
    cancel.assert_called_once_with("src-1")


def test_cancel_operation_edge_cases(client, container):
    with patch.object(db, "get_operation", return_value=None):
        assert client.post("/api/operations/op-1/cancel").status_code == 404

    finished = {"operation_id": "op-1", "kind": "scan_postprocess", "source_id": "s", "can_cancel": False}
    with patch.object(db, "get_operation", return_value=finished):
        assert client.post("/api/operations/op-1/cancel").json() == finished

    automation = {"operation_id": "op-1", "kind": "automation_run", "source_id": "run-9", "can_cancel": True}
    with patch.object(db, "get_operation", return_value=automation), patch("app.api.operations.cancel_automation_run") as cancel_run:
        assert client.post("/api/operations/op-1/cancel").status_code == 200
    cancel_run.assert_called_once_with("run-9")


def test_cancel_bulk_refresh_cancels_children_and_marks_cancelling(client, container):
    operation = {
        "operation_id": "op-1",
        "kind": "asset_card_bulk_refresh",
        "source_id": "bulk-1",
        "can_cancel": True,
        "progress_percent": 40,
        "result": {"child_operation_ids": ["c1", " ", "c2"], "current_child_operation_id": "c3"},
    }
    children = {"c1": {"can_cancel": True}, "c2": {"can_cancel": False}, "c3": None}
    lookups = []

    def fake_get(operation_id, **_kwargs):
        lookups.append(operation_id)
        return operation if operation_id == "op-1" else children[operation_id]

    with (
        patch.object(db, "get_operation", side_effect=fake_get),
        patch.object(db, "register_operation") as register,
        patch.object(main, "cancel_operation") as cancel_child,
    ):
        assert client.post("/api/operations/op-1/cancel").status_code == 200
    container.operation_runner.cancellations.cancel.assert_called_once_with("asset-card-bulk-refresh", "bulk-1")
    cancel_child.assert_called_once_with("c1")
    assert register.call_args.kwargs["status"] == "cancelling"


def test_retry_operation_branches(client, container):
    base = {"operation_id": "op-1", "can_retry": True, "request": {}}

    with patch.object(db, "get_operation_by_idempotency_key", return_value={"operation_id": "old"}):
        replay = client.post("/api/operations/op-1/retry", headers={"X-Idempotency-Key": "k"})
    assert replay.json() == {"operation": {"operation_id": "old"}, "idempotent_replay": True}

    with patch.object(db, "get_operation_by_idempotency_key", return_value=None):
        with patch.object(db, "get_operation", return_value=None):
            assert client.post("/api/operations/op-1/retry").status_code == 404
        with patch.object(db, "get_operation", return_value={**base, "can_retry": False, "kind": "x"}):
            assert client.post("/api/operations/op-1/retry").json()["detail"]["code"] == "OPERATION_NOT_RETRYABLE"
        with patch.object(db, "get_operation", return_value={**base, "kind": "something_else"}):
            assert client.post("/api/operations/op-1/retry").status_code == 409

        with patch.object(db, "get_operation", return_value={**base, "kind": "passport_detail_sync"}):
            assert client.post("/api/operations/op-1/retry").json()["detail"]["code"] == "RETRY_CONTEXT_MISSING"

        passport = {**base, "kind": "passport_detail_sync", "request": {"pdql": "select()"}}
        with patch.object(db, "get_operation", return_value=passport), patch.object(main, "query_vulnerability_passports", return_value={"detail_job": None}):
            assert client.post("/api/operations/op-1/retry").json()["detail"]["code"] == "RETRY_NOT_REQUIRED"

        container.operation_runner = MagicMock()
        with (
            patch.object(db, "get_operation", return_value=passport),
            patch.object(main, "query_vulnerability_passports", return_value={"detail_job": {"job_id": "new-1"}}),
            patch.object(db, "sync_operations_from_sources"),
            patch.object(db, "set_operation_retry", return_value={"operation_id": "new-1"}) as set_retry,
        ):
            done = client.post("/api/operations/op-1/retry", headers={"X-Idempotency-Key": "k2"})
        assert done.status_code == 202 and done.json() == {"operation": {"operation_id": "new-1"}, "retry_of": "op-1"}
        set_retry.assert_called_once_with("new-1", "op-1", "k2")


def test_retry_asset_card_build_and_automation_run(client, container, repo, service):
    card = {"operation_id": "op-1", "can_retry": True, "kind": "asset_card_build", "request": {"asset_id": "a1"}}
    with (
        patch.object(db, "get_operation_by_idempotency_key", return_value=None),
        patch.object(db, "get_operation", return_value=card),
        patch.object(main, "create_asset_card_build_job", return_value={"job": {"job_id": "job-2"}}),
        patch.object(db, "sync_operations_from_sources"),
        patch.object(db, "set_operation_retry", return_value=None),
        patch.object(db, "get_operation", side_effect=[card, {"operation_id": "job-2"}]),
    ):
        assert client.post("/api/operations/op-1/retry").json()["operation"] == {"operation_id": "job-2"}

    run = {"operation_id": "op-2", "can_retry": True, "kind": "automation_run", "source_id": "run-1"}
    with patch.object(db, "get_operation_by_idempotency_key", return_value=None), patch.object(db, "get_operation", return_value=run):
        repo.get_run.return_value = None
        assert client.post("/api/operations/op-2/retry").json()["detail"]["code"] == "RETRY_CONTEXT_MISSING"
        repo.get_run.return_value = {"runbook_id": "r1"}
        service.start_run.return_value = {"run_id": "run-2"}
        with patch.object(db, "sync_operations_from_sources"), patch.object(db, "set_operation_retry", return_value={"operation_id": "run-2"}):
            assert client.post("/api/operations/op-2/retry").status_code == 202


def test_operation_diagnostics_archive(client, tmp_path):
    with patch.object(db, "get_operation", return_value=None):
        assert client.get("/api/operations/op-1/diagnostics").status_code == 404

    archive = tmp_path / "diag.zip"
    archive.write_bytes(b"PK")
    with (
        patch.object(db, "get_operation", return_value={"operation_id": "op-1"}),
        patch("app.api.operations.build_operation_diagnostic_archive", return_value=archive),
    ):
        response = client.get("/api/operations/op-1/diagnostics")
    assert response.status_code == 200 and response.headers["content-type"] == "application/zip"


def test_frontend_diagnostics_are_accepted_and_correlated(client):
    events = [
        {"event": "ui.error", "level": "error", "fields": {"token": "secret"}, "trace_id": "trace-abc123"},
        {"event": "ui.info", "level": "info"},
    ]
    with patch("app.api.operations.log_event") as log_event:
        response = client.post("/api/diagnostics/frontend", json={"events": events})
    assert response.status_code == 202 and response.json()["accepted"] == 2
    assert log_event.call_count == 2
    assert "secret" not in str(log_event.call_args_list[0].kwargs["frontend_fields"])


# ---------------------------------------------------------------------------- passports


@pytest.fixture
def refresh_repo():
    with patch("app.api.passports.passport_refresh") as module:
        yield module


def test_passport_refresh_job_creation_guards(client, container, refresh_repo):
    with patch.object(main, "require_mpvm", return_value=(MagicMock(), "t")):
        with patch.object(db, "get_active_vulnerability_passport_detail_job", return_value={"job_id": "d1"}):
            assert client.post("/api/vulnerability-passports/refresh-jobs").status_code == 409
        with patch.object(db, "get_active_vulnerability_passport_detail_job", return_value=None):
            refresh_repo.create.side_effect = psycopg.errors.UniqueViolation("busy")
            refresh_repo.latest.return_value = {"operation_id": "p0"}
            busy = client.post("/api/vulnerability-passports/refresh-jobs")
            assert busy.status_code == 409 and busy.json()["detail"]["context"]["job"] == {"operation_id": "p0"}

            refresh_repo.create.side_effect = None
            refresh_repo.create.return_value = {"operation_id": "p1"}
            with patch("app.api.passports.run_vulnerability_passport_refresh_job"):
                created = client.post("/api/vulnerability-passports/refresh-jobs")
            assert created.status_code == 202 and created.json() == {"job": {"operation_id": "p1"}}
            container.operation_runner.cancellations.register.assert_called_once()


def test_passport_refresh_job_read_and_cancel(client, container, refresh_repo):
    refresh_repo.latest.return_value = {"operation_id": "p1"}
    assert client.get("/api/vulnerability-passports/refresh-jobs/latest").json() == {"job": {"operation_id": "p1"}}

    refresh_repo.get.return_value = None
    assert client.get("/api/vulnerability-passports/refresh-jobs/p1").status_code == 404
    assert client.post("/api/vulnerability-passports/refresh-jobs/p1/cancel").status_code == 404

    refresh_repo.get.return_value = {"operation_id": "p1"}
    assert client.get("/api/vulnerability-passports/refresh-jobs/p1").json() == {"operation_id": "p1"}
    refresh_repo.request_cancel.return_value = {"operation_id": "p1", "status": "cancelling"}
    assert client.post("/api/vulnerability-passports/refresh-jobs/p1/cancel").json()["status"] == "cancelling"
    container.operation_runner.cancellations.cancel.assert_called_with("passport-refresh", "p1")
    refresh_repo.request_cancel.return_value = None
    assert client.post("/api/vulnerability-passports/refresh-jobs/p1/cancel").json() == {"operation_id": "p1"}


def test_passport_trending_refresh_maps_errors(client):
    with patch.object(main, "require_mpvm", return_value=(MagicMock(), "t")):
        with patch.object(main, "sync_trending_vulnerability_passports", return_value={"saved": 3}):
            assert client.post("/api/vulnerability-passports/trending/refresh").json() == {"saved": 3}
        with patch.object(main, "sync_trending_vulnerability_passports", side_effect=requests.ConnectionError("down")):
            assert client.post("/api/vulnerability-passports/trending/refresh").status_code >= 400


def test_passport_local_list_and_detail_jobs(client, container):
    container.services.passports.list.return_value = {"rows": []}
    assert client.get("/api/vulnerability-passports/local?q=cve&severity=High").json() == {"rows": []}
    container.services.passports.list.side_effect = ValueError("bad sort")
    assert client.get("/api/vulnerability-passports/local?sort_by=x").status_code == 422

    with patch.object(db, "get_active_vulnerability_passport_detail_job", return_value=None):
        assert client.get("/api/vulnerability-passports/detail-jobs/active").json() == {"job": None}
    with patch.object(db, "get_vulnerability_passport_detail_job", return_value=None):
        assert client.get("/api/vulnerability-passports/detail-jobs/j1").status_code == 404
        assert client.post("/api/vulnerability-passports/detail-jobs/j1/cancel").status_code == 404
    with patch.object(db, "get_vulnerability_passport_detail_job", return_value={"job_id": "j1", "status": "running"}):
        assert client.get("/api/vulnerability-passports/detail-jobs/j1").json()["job_id"] == "j1"
        with patch.object(db, "request_vulnerability_passport_detail_job_cancel", return_value={"job_id": "j1", "status": "cancelling"}):
            assert client.post("/api/vulnerability-passports/detail-jobs/j1/cancel").json()["status"] == "cancelling"
    done = {"job_id": "j1", "status": "completed"}
    with patch.object(db, "get_vulnerability_passport_detail_job", return_value=done):
        assert client.post("/api/vulnerability-passports/detail-jobs/j1/cancel").json() == done


def test_passport_detail_fetch_update_delete(client, container):
    with patch.object(db, "list_asset_card_links_for_vulnerability_passport", return_value=[{"asset_id": "a"}]):
        assert client.get("/api/vulnerability-passports/p1/asset-links").json()["rows"] == [{"asset_id": "a"}]

    container.services.passports.get.return_value = {"raw_detail": {"id": "p1"}}
    assert client.get("/api/vulnerability-passports/p1").json()["source"] == "db"

    container.services.passports.get.return_value = None
    mp_client = MagicMock()
    mp_client.get_vulnerability_passport.return_value = {"id": "p1"}
    with patch.object(main, "require_mpvm", return_value=(mp_client, "t")), patch.object(db, "upsert_vulnerability_passport_detail", return_value={"saved": True}):
        fetched = client.get("/api/vulnerability-passports/p1").json()
        assert fetched["source"] == "mpvm" and fetched["passport"] == {"saved": True}
        mp_client.get_vulnerability_passport.side_effect = MpVmApiError("boom")
        assert client.get("/api/vulnerability-passports/p1").status_code >= 400

    with patch.object(db, "get_vulnerability_passport", return_value=None):
        assert client.put("/api/vulnerability-passports/p1").status_code == 404
    mp_client.get_vulnerability_passport.side_effect = None
    with (
        patch.object(db, "get_vulnerability_passport", return_value={"id": "p1"}),
        patch.object(main, "require_mpvm", return_value=(mp_client, "t")),
        patch.object(db, "upsert_vulnerability_passport_detail", return_value={"saved": True}),
    ):
        assert client.put("/api/vulnerability-passports/p1").json()["updated"] is True
        mp_client.get_vulnerability_passport.side_effect = requests.Timeout("slow")
        assert client.put("/api/vulnerability-passports/p1").status_code >= 400

    with patch.object(db, "delete_vulnerability_passport", return_value=True):
        assert client.delete("/api/vulnerability-passports/p1").json() == {"id": "p1", "deleted": True}
    with patch.object(db, "delete_vulnerability_passport", return_value=False):
        assert client.delete("/api/vulnerability-passports/p1").status_code == 404


def test_passport_query_delegates(client):
    with patch("app.api.passports._execute_vulnerability_passport_query", return_value={"rows": []}) as query:
        response = client.post("/api/vulnerability-passports/query", json={"pdql": "select()"})
    assert response.json() == {"rows": []}
    assert query.call_args.args[0].pdql == "select()"


_ = SimpleNamespace  # keep the import for future fixtures
