"""Handler-level tests for the asset card routes in ``app/api/asset_cards.py``."""

from __future__ import annotations

from concurrent.futures import Future
from unittest.mock import MagicMock, patch

import psycopg.errors
import pytest
import requests
from fastapi.testclient import TestClient

from app import auth, db, main
from app.api import asset_cards
from app.mpvm_client import MpVmApiError

ADMIN = {"id": 1, "username": "admin", "display_name": "Admin", "role": "admin", "is_active": True}


@pytest.fixture
def client():
    with patch.object(auth, "get_session_user", return_value=ADMIN), patch.object(auth, "audit_event"):
        yield TestClient(main.app)


@pytest.fixture
def container():
    fake = MagicMock(name="CONTAINER")
    with patch.object(main, "CONTAINER", fake):
        yield fake


@pytest.fixture
def mpvm():
    remote = MagicMock(name="MpVmClient")
    with patch.object(main, "require_mpvm", return_value=(remote, "token")):
        yield remote


# ------------------------------------------------------------------- read-only routes


def test_local_listing_and_sections(client, container):
    container.services.asset_cards.list.return_value = {"rows": []}
    assert client.get("/api/asset-cards/local?q=web").json() == {"rows": []}
    container.services.asset_cards.list.side_effect = ValueError("bad sort")
    assert client.get("/api/asset-cards/local?sort_by=x").json()["detail"]["code"] == "INVALID_SORT"

    container.services.asset_cards.get.return_value = None
    assert client.get("/api/asset-cards/a1").status_code == 404
    container.services.asset_cards.get.return_value = {"asset_id": "a1"}
    assert client.get("/api/asset-cards/a1?section=summary").json() == {"asset_id": "a1"}
    container.services.asset_cards.get.assert_called_with("a1", section="summary")


@pytest.mark.parametrize(
    ("path", "function", "value"),
    [
        ("/api/asset-cards/a1/summary", "get_asset_card_summary", {"asset_id": "a1"}),
        ("/api/asset-cards/a1/configuration/tree", "list_asset_card_configuration_tree", {"nodes": []}),
        ("/api/asset-cards/a1/configuration/detail?path=asset", "get_asset_card_configuration_detail", {"rows": []}),
        ("/api/asset-cards/a1/vulnerabilities/groups", "list_asset_card_vulnerability_groups", {"groups": []}),
        (
            "/api/asset-cards/a1/vulnerabilities/findings?source=os&collection_id=c1",
            "list_asset_card_vulnerability_findings",
            {"rows": []},
        ),
    ],
)
def test_card_sections_return_404_when_the_card_is_missing(client, path, function, value):
    with patch.object(db, function, return_value=value):
        assert client.get(path).json() == value
    with patch.object(db, function, return_value=None):
        assert client.get(path).status_code == 404


def test_history_and_invalid_findings_query(client):
    with patch.object(db, "get_asset_card_history", return_value=[{"id": 1}]):
        assert client.get("/api/asset-cards/a1/history?limit=5").json() == {"asset_id": "a1", "items": [{"id": 1}]}
    with patch.object(db, "list_asset_card_vulnerability_findings", side_effect=ValueError("unknown source")):
        invalid = client.get("/api/asset-cards/a1/vulnerabilities/findings?source=zzz&collection_id=c")
    assert invalid.status_code == 422 and invalid.json()["detail"]["code"] == "INVALID_ASSET_CARD_FINDINGS_QUERY"


# ------------------------------------------------------------------- query / build


def test_query_assets_normalises_and_maps_errors(client, mpvm):
    mpvm.create_pdql_token.return_value = "tok"
    records = [{"@Host": {"id": "a1", "displayName": "one"}}, {"@Host": {"id": "a1", "displayName": "one"}}]
    with patch.object(main, "fetch_asset_grid_records", return_value=(records, {"raw": True})):
        body = client.post("/api/asset-cards/query-assets", json={"limit": 10}).json()
    assert body["pdql_token"] == "tok" and body["raw"] == {"raw": True}
    assert body["total"] == len(body["records"]) <= 1

    mpvm.create_pdql_token.side_effect = MpVmApiError("rejected")
    assert client.post("/api/asset-cards/query-assets", json={}).status_code >= 400


def test_build_card_saves_reconciles_and_snapshots(client, mpvm, container):
    card = {"asset_id": "a1", "stats": {}}
    with (
        patch.object(main, "build_asset_card", return_value=card) as build,
        patch.object(db, "upsert_asset_card", return_value={"asset_id": "a1"}) as upsert,
        patch.object(main, "capture_vulnerability_snapshot") as snapshot,
    ):
        saved = client.post("/api/asset-cards/build", json={"asset_id": " a1 "}).json()
        unsaved = client.post("/api/asset-cards/build", json={"asset_id": "a1", "save_to_db": False}).json()
    assert saved["saved"] is True and build.call_args.kwargs["asset_id"] == "a1"
    assert unsaved["saved"] is False and unsaved["saved_card"] is None
    upsert.assert_called_once()
    container.services.remediation.reconcile_asset.assert_called_once_with("a1")
    snapshot.assert_called_once()
    assert snapshot.call_args.args[0] == "asset_card_build"


def test_build_card_validation_and_remote_errors(client, mpvm):
    assert client.post("/api/asset-cards/build", json={"asset_id": "   "}).status_code == 422
    with patch.object(main, "build_asset_card", side_effect=requests.ConnectionError("down")):
        assert client.post("/api/asset-cards/build", json={"asset_id": "a1"}).status_code >= 400


def test_update_and_delete_local_card(client, mpvm, container):
    with patch.object(db, "asset_card_exists", return_value=False):
        assert client.put("/api/asset-cards/a1", json={}).status_code == 404

    with patch.object(db, "asset_card_exists", return_value=True):
        with patch.object(main, "build_asset_card", side_effect=MpVmApiError("down")):
            assert client.put("/api/asset-cards/a1", json={}).status_code >= 400
        with patch.object(main, "build_asset_card", return_value={"asset_id": "a1"}):
            with patch.object(db, "upsert_asset_card", return_value=None):
                assert client.put("/api/asset-cards/a1", json={}).status_code == 500
            with patch.object(db, "upsert_asset_card", return_value={"asset_id": "a1"}), patch.object(main, "capture_vulnerability_snapshot") as snapshot:
                assert client.put("/api/asset-cards/a1", json={}).json()["updated"] is True
    assert snapshot.call_args.args[0] == "asset_card_update"
    container.services.remediation.reconcile_asset.assert_called_once_with("a1")

    with patch.object(db, "delete_asset_card", return_value=False):
        assert client.delete("/api/asset-cards/a1").status_code == 404
    with patch.object(db, "delete_asset_card", return_value=True), patch.object(main, "capture_vulnerability_snapshot") as snapshot:
        assert client.delete("/api/asset-cards/a1").json() == {"asset_id": "a1", "deleted": True}
    assert snapshot.call_args.args[0] == "asset_card_delete"


# --------------------------------------------------------------------- build jobs


@pytest.fixture
def job_runtime():
    with (
        patch.object(main, "run_asset_card_build_job"),
        patch.object(main, "run_asset_card_build_jobs"),
        patch("app.api.asset_cards.register_asset_card_build_job", return_value=MagicMock()),
    ):
        yield


def test_single_build_job_replay_guards_and_creation(client, mpvm, job_runtime):
    with patch.object(db, "get_operation_by_idempotency_key", return_value={"kind": "asset_card_build", "source_id": "j0"}), patch.object(db, "get_asset_card_build_job", return_value={"job_id": "j0"}):
        replay = client.post("/api/asset-cards/build-jobs", json={"asset_id": "a1"}, headers={"X-Idempotency-Key": "k"})
    assert replay.json()["idempotent_replay"] is True

    with patch.object(db, "get_operation_by_idempotency_key", return_value=None):
        assert client.post("/api/asset-cards/build-jobs", json={"asset_id": "  "}).status_code == 422
        with patch.object(db, "get_active_asset_card_build_job", return_value={"job_id": "busy"}):
            busy = client.post("/api/asset-cards/build-jobs", json={"asset_id": "a1"})
        assert busy.status_code == 409 and busy.json()["detail"]["context"]["job"] == {"job_id": "busy"}

        with patch.object(db, "get_active_asset_card_build_job", return_value=None), patch.object(db, "asset_card_exists", return_value=True):
            with patch.object(db, "create_asset_card_build_job", side_effect=psycopg.errors.UniqueViolation("busy")):
                assert client.post("/api/asset-cards/build-jobs", json={"asset_id": "a1"}).status_code == 409
            with patch.object(db, "create_asset_card_build_job", return_value=None):
                assert client.post("/api/asset-cards/build-jobs", json={"asset_id": "a1"}).status_code == 409
            with patch.object(db, "create_asset_card_build_job", return_value={"operation": "refresh"}) as create:
                created = client.post("/api/asset-cards/build-jobs", json={"asset_id": "a1"})
    assert created.status_code == 202 and created.json()["job"] == {"operation": "refresh"}
    assert create.call_args.kwargs["operation"] == "refresh"


def test_batch_build_jobs(client, mpvm, job_runtime):
    body = {"asset_ids": ["a1", "a2"]}
    replay_operation = {"kind": "asset_card_build_batch", "result": {"job_ids": ["j1", "j2"]}}
    with patch.object(db, "get_operation_by_idempotency_key", return_value=replay_operation), patch.object(db, "get_asset_card_build_job", return_value={"job_id": "x"}):
        assert client.post("/api/asset-cards/build-jobs/batch", json=body, headers={"X-Idempotency-Key": "k"}).json()["idempotent_replay"] is True

    with patch.object(db, "asset_card_exists", return_value=False):
        with patch.object(db, "get_operation_by_idempotency_key", return_value=None):
            with patch.object(db, "create_asset_card_build_jobs", return_value=[]):
                assert client.post("/api/asset-cards/build-jobs/batch", json=body).json()["detail"]["code"] == "ASSET_CARD_BUILD_CAPACITY_EXCEEDED"
            with patch.object(db, "create_asset_card_build_jobs", return_value=[{"job_id": "j1"}, {"job_id": "j2"}]):
                created = client.post("/api/asset-cards/build-jobs/batch", json=body)
        assert created.status_code == 202 and len(created.json()["jobs"]) == 2

        # a unique violation caused by an earlier identical request is replayed
        sequence = iter([None, replay_operation])
        with (
            patch.object(db, "get_operation_by_idempotency_key", side_effect=lambda _key: next(sequence)),
            patch.object(db, "create_asset_card_build_jobs", side_effect=psycopg.errors.UniqueViolation("dup")),
            patch.object(db, "get_asset_card_build_job", return_value={"job_id": "x"}),
        ):
            assert client.post("/api/asset-cards/build-jobs/batch", json=body, headers={"X-Idempotency-Key": "k"}).json()["idempotent_replay"] is True

        # ...and a violation without a replayable operation is a capacity conflict
        with (
            patch.object(db, "get_operation_by_idempotency_key", return_value=None),
            patch.object(db, "create_asset_card_build_jobs", side_effect=psycopg.errors.UniqueViolation("dup")),
        ):
            assert client.post("/api/asset-cards/build-jobs/batch", json=body).status_code == 409


def test_build_job_status_active_and_cancel(client, container):
    with patch.object(db, "get_active_asset_card_build_job", return_value=None):
        assert client.get("/api/asset-cards/build-jobs/active").json() == {"job": None}

    with patch.object(db, "get_asset_card_build_job", return_value=None):
        assert client.get("/api/asset-cards/build-jobs/j1").status_code == 404
        assert client.post("/api/asset-cards/build-jobs/j1/cancel").status_code == 404
    with patch.object(db, "get_asset_card_build_job", return_value={"job_id": "j1", "status": "running"}):
        assert client.get("/api/asset-cards/build-jobs/j1").json()["job_id"] == "j1"
        with patch.object(db, "request_asset_card_build_job_cancel", return_value={"job_id": "j1", "status": "cancelling", "asset_id": "a1"}):
            assert client.post("/api/asset-cards/build-jobs/j1/cancel").json()["status"] == "cancelling"
        container.operation_runner.cancellations.cancel.assert_called_with("asset-card", "j1")
    finished = {"job_id": "j1", "status": "completed"}
    with patch.object(db, "get_asset_card_build_job", return_value=finished):
        assert client.post("/api/asset-cards/build-jobs/j1/cancel").json() == finished


# ------------------------------------------------------------- refresh-by-scan templates


def test_refresh_templates_merge_local_and_remote(client, mpvm):
    local = [
        {"mp_task_id": "t1", "payload": {"scope": "s", "profile": "p", "name": "Local"}},
        {"mp_task_id": "t2", "payload": {"scope": "s"}},
        {"mp_task_id": "t3", "payload": {"scope": "s", "profile": "p"}, "deleted_at": "2026-01-01"},
    ]
    remote = [
        {"mp_task_id": "t1", "name": "dup", "source": "remote"},
        {"mp_task_id": "t9", "name": "Remote", "source": "remote"},
    ]
    with patch.object(db, "list_scan_tasks", return_value=local), patch.object(asset_cards, "remote_scanner_task_templates", return_value=remote):
        body = client.get("/api/asset-cards/refresh-scan/templates").json()
    assert [row["mp_task_id"] for row in body["rows"]] == ["t1", "t9"] and body["recommended_task_id"] == "t1"

    with patch.object(db, "list_scan_tasks", return_value=local), patch.object(asset_cards, "remote_scanner_task_templates", side_effect=MpVmApiError("down")):
        assert [row["mp_task_id"] for row in client.get("/api/asset-cards/refresh-scan/templates").json()["rows"]] == ["t1"]
    with patch.object(db, "list_scan_tasks", return_value=[]), patch.object(asset_cards, "remote_scanner_task_templates", side_effect=requests.ConnectionError("down")):
        assert client.get("/api/asset-cards/refresh-scan/templates").status_code >= 400
    with patch.object(db, "list_scan_tasks", return_value=[]), patch.object(asset_cards, "remote_scanner_task_templates", return_value=[]):
        assert client.get("/api/asset-cards/refresh-scan/templates").json()["recommended_task_id"] is None


# -------------------------------------------------------------------- bulk refresh


def test_bulk_refresh_replay_conflict_and_queueing(client, container):
    with patch.object(db, "get_operation_by_idempotency_key", return_value={"kind": "something_else"}):
        conflict = client.post("/api/asset-cards/refresh-scan/bulk", json={}, headers={"X-Idempotency-Key": "k"})
    assert conflict.status_code == 409 and conflict.json()["detail"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"

    replay = {"kind": "asset_card_bulk_refresh", "operation_id": "op-0"}
    with patch.object(db, "get_operation_by_idempotency_key", return_value=replay):
        assert client.post("/api/asset-cards/refresh-scan/bulk", json={}, headers={"X-Idempotency-Key": "k"}).json()["idempotent_replay"] is True

    future: Future = Future()
    container.operation_runner.submit.return_value = future
    with (
        patch.object(db, "get_operation_by_idempotency_key", return_value=None),
        patch.object(main, "resolve_asset_card_refresh_template", return_value={"mp_task_id": "tpl-1"}),
        patch.object(db, "register_operation", return_value={"operation_id": "op-1"}) as register,
    ):
        queued = client.post("/api/asset-cards/refresh-scan/bulk", json={"selection": "stale"})
    assert queued.status_code == 202 and queued.json()["operation"] == {"operation_id": "op-1"}
    assert register.call_args.kwargs["subject_label"] == "Карточки старше порога свежести"
    assert register.call_args.kwargs["request"]["template_task_id"] == "tpl-1"
    future.set_result(None)  # done-callback removes the cancellation token
    container.operation_runner.cancellations.remove.assert_called_once()


# ---------------------------------------------------------------- refresh by scan


CARD = {"asset_id": "a1", "ip_address": "10.0.0.5", "display_name": "web-01"}
TEMPLATE = {"mp_task_id": "tpl-1", "payload": {"name": "tpl", "scope": "s", "profile": "p"}}


@pytest.fixture
def refresh_env(mpvm):
    mpvm.auth = MagicMock()
    mpvm.create_scanner_task.return_value = "new-task"
    with (
        patch.object(db, "get_operation_by_idempotency_key", return_value=None),
        patch.object(db, "get_asset_card", return_value=CARD),
        patch.object(db, "get_active_asset_card_refresh", return_value=None),
        patch.object(db, "record_scan_task"),
        patch.object(main, "resolve_asset_card_refresh_template", return_value=TEMPLATE),
        patch.object(main, "schedule_scan_postprocess"),
        patch.object(main, "DOCKER_DYNAMIC_GROUP_ITERATIONS", 0),
    ):
        yield mpvm


def test_refresh_by_scan_replay_and_precondition_failures(client, refresh_env):
    run = {"mp_task_id": "t-old"}
    with patch.object(db, "get_operation_by_idempotency_key", return_value={"kind": "scan_postprocess", "source_id": "pp-1"}), patch.object(db, "get_scan_postprocess_run", return_value=run):
        replay = client.post("/api/asset-cards/a1/refresh-scan", json={}, headers={"X-Idempotency-Key": "k"}).json()
    assert replay["idempotent_replay"] is True and replay["task_id"] == "t-old"
    with patch.object(db, "get_operation_by_idempotency_key", return_value={"kind": "scan_postprocess", "source_id": "pp-1"}), patch.object(db, "get_scan_postprocess_run", return_value=None):
        assert client.post("/api/asset-cards/a1/refresh-scan", json={}).json()["task_id"] is None

    with patch.object(db, "get_asset_card", return_value=None):
        assert client.post("/api/asset-cards/a1/refresh-scan", json={}).status_code == 404
    with patch.object(db, "get_asset_card", return_value={**CARD, "ip_address": "not-an-ip"}):
        assert client.post("/api/asset-cards/a1/refresh-scan", json={}).json()["detail"]["code"] == "ASSET_CARD_IP_REQUIRED"
    with patch.object(db, "get_active_asset_card_refresh", return_value={"run": "active"}):
        busy = client.post("/api/asset-cards/a1/refresh-scan", json={})
    assert busy.status_code == 409 and busy.json()["detail"]["code"] == "ASSET_CARD_REFRESH_ACTIVE"


def test_refresh_by_scan_started_flow_schedules_postprocess(client, refresh_env):
    created = {}

    def start_impl(**kwargs):
        kwargs["before_remote_start"]("2026-01-01T00:00:00+00:00")  # creates the provisional run
        return {"status": "started", "started_from": "2026-01-01T00:00:00+00:00"}

    def create_run(run_id, **kwargs):
        created.update(kwargs)
        return {"run_id": run_id}

    with (
        patch.object(main, "start_scanner_task_impl", side_effect=start_impl),
        patch.object(db, "create_scan_postprocess_run", side_effect=create_run),
        patch.object(db, "get_scan_postprocess_run", return_value={"run_id": "reloaded"}),
    ):
        body = client.post("/api/asset-cards/a1/refresh-scan", json={}, headers={"X-Idempotency-Key": "k"}).json()
    assert body["task_id"] == "new-task" and body["target_ip"] == "10.0.0.5"
    assert body["postprocess"] == {"run_id": "reloaded"} and body["operation_id"] == body["postprocess_run_id"]
    assert created["options"]["refresh_asset_id"] == "a1" and created["idempotency_key"] == "k"
    main.schedule_scan_postprocess.assert_called_once_with(body["postprocess_run_id"], refresh_env.auth, "token")


def test_refresh_by_scan_creates_run_after_start_and_keeps_docker_group(client, refresh_env):
    with (
        patch.object(main, "DOCKER_DYNAMIC_GROUP_ITERATIONS", 2),
        patch.object(main, "start_scanner_task_impl", return_value={"status": "started", "started_from": "t0", "docker_dynamic_group": {"name": "g", "state": "ready"}}),
        patch.object(db, "create_scan_postprocess_run", return_value={"run_id": "created"}) as create,
    ):
        body = client.post("/api/asset-cards/a1/refresh-scan", json={}).json()
    assert body["postprocess"] == {"run_id": "created"}
    assert create.call_args.kwargs["options"]["docker_dynamic_group"] == {"name": "g", "state": "ready"}


def test_refresh_by_scan_returns_non_started_results_untouched(client, refresh_env):
    with patch.object(main, "start_scanner_task_impl", return_value={"status": "precheck_failed"}):
        body = client.post("/api/asset-cards/a1/refresh-scan", json={}).json()
    assert body["status"] == "precheck_failed" and body["template_task_id"] == "tpl-1" and "postprocess" not in body


def test_refresh_by_scan_failures_finalise_the_provisional_run(client, refresh_env):
    def failing_start(**kwargs):
        kwargs["before_remote_start"]("t0")
        raise MpVmApiError("start rejected")

    with patch.object(main, "start_scanner_task_impl", side_effect=failing_start), patch.object(db, "create_scan_postprocess_run", return_value={"run_id": "r"}), patch.object(main, "finish_provisional_scan_start_failure") as finish:
        assert client.post("/api/asset-cards/a1/refresh-scan", json={}).status_code >= 400
    finish.assert_called_once()

    with patch.object(main, "start_scanner_task_impl", side_effect=failing_start), patch.object(db, "create_scan_postprocess_run", return_value={"run_id": "r"}), patch.object(main, "finish_provisional_scan_start_failure", side_effect=RuntimeError("cleanup failed")):
        assert client.post("/api/asset-cards/a1/refresh-scan", json={}).status_code >= 400

    with patch.object(main, "start_scanner_task_impl", side_effect=RuntimeError("unexpected")):
        with pytest.raises(RuntimeError):
            client.post("/api/asset-cards/a1/refresh-scan", json={})

    # no provisional run: the helper is never reached and a missing task id is a programming error
    refresh_env.create_scanner_task.return_value = ""
    with patch.object(main, "start_scanner_task_impl", side_effect=lambda **kw: kw["before_remote_start"]("t0")):
        with pytest.raises(RuntimeError, match="task id"):
            client.post("/api/asset-cards/a1/refresh-scan", json={})
