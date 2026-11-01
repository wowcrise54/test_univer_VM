"""Handler-level tests for asset queries, scanner tasks, imports/exports and middleware."""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import psycopg
import pytest
import requests
from fastapi.testclient import TestClient

from app import auth, db, main
from app.api import imports_exports, scanner_tasks
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


@pytest.fixture(autouse=True)
def no_backfill():
    with patch.object(main, "start_asset_search_backfill"):
        yield


# ------------------------------------------------------------------------ asset queries


def test_asset_query_fields_and_presets(client, container):
    container.services.asset_query.fields.return_value = {"fields": []}
    assert client.get("/api/asset-card-query/fields?q=os").json() == {"fields": []}
    container.services.asset_query.fields.assert_called_once_with(q="os", limit=100)

    with patch.object(db, "list_asset_card_query_presets", return_value=[{"id": "p"}]):
        assert client.get("/api/asset-card-query/presets").json() == {
            "rows": [{"id": "p"}], "execution": "local", "source": "asset_cards",
        }


@pytest.mark.parametrize(
    ("path", "function", "invalid_code"),
    [
        ("/api/asset-card-query/presets/software", "query_asset_card_preset", "INVALID_ASSET_QUERY_PRESET"),
        ("/api/asset-card-query/presets/software/assets", "query_asset_card_preset_assets", "INVALID_ASSET_QUERY_PRESET_ASSETS"),
    ],
)
def test_asset_query_presets_map_errors(client, path, function, invalid_code):
    with patch.object(db, function, return_value={"rows": []}) as query:
        ok = client.post(path, json={"software_name": "nginx", "limit": 5})
    assert ok.json() == {"rows": []}
    assert query.call_args.args[0] == "software"

    with patch.object(db, function, side_effect=KeyError("software")):
        missing = client.post(path, json={})
    assert missing.status_code == 404 and missing.json()["detail"]["code"] == "ASSET_QUERY_PRESET_NOT_FOUND"

    with patch.object(db, function, side_effect=ValueError("bad filter")):
        invalid = client.post(path, json={})
    assert invalid.status_code == 422 and invalid.json()["detail"]["code"] == invalid_code


def test_asset_card_query(client, container):
    body = {"query": {"all": []}, "sort_by": "display_name", "limit": 10}
    container.services.asset_query.query.return_value = {"rows": [], "total": 0}
    assert client.post("/api/asset-card-query", json=body).json() == {"rows": [], "total": 0}
    container.services.asset_query.query.side_effect = ValueError("no such field")
    failed = client.post("/api/asset-card-query", json=body)
    assert failed.status_code == 422 and failed.json()["detail"]["code"] == "INVALID_ASSET_QUERY"


def test_asset_card_query_export_streams_every_page_as_csv(client):
    page_one = {"total": 3, "rows": [
        {"asset_id": "a1", "display_name": "one", "matches": [{"entity_path": "p", "field_path": "f", "value": "v"}]},
        {"asset_id": "a2", "display_name": "two"},
    ]}
    page_two = {"total": 3, "rows": [{"asset_id": "a3", "display_name": "three", "matches": []}]}
    with patch.object(db, "query_asset_cards_by_fields", side_effect=[page_one, page_two]) as query:
        response = client.post("/api/asset-card-query/export", json={"query": {"all": []}})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=\"asset-query-" in response.headers["content-disposition"]
    lines = response.content.decode("utf-8-sig").splitlines()
    assert lines[0].startswith("asset_id,display_name") and len(lines) == 4
    assert lines[1].endswith(",p,f,v")
    assert [call.kwargs["offset"] for call in query.call_args_list] == [0, 2]

    with patch.object(db, "query_asset_cards_by_fields", side_effect=ValueError("bad")):
        assert client.post("/api/asset-card-query/export", json={"query": {}}).status_code == 422


def test_asset_card_query_export_stops_on_empty_page(client):
    with patch.object(db, "query_asset_cards_by_fields", return_value={"total": 10, "rows": []}) as query:
        response = client.post("/api/asset-card-query/export", json={"query": {}})
    assert response.status_code == 200 and len(response.content.decode("utf-8-sig").splitlines()) == 1
    query.assert_called_once()


# ---------------------------------------------------------------------- scanner tasks


@pytest.fixture
def mpvm():
    remote = MagicMock(name="MpVmClient")
    with patch.object(main, "require_mpvm", return_value=(remote, "token")):
        yield remote


def test_remote_and_local_task_lists(client, container, mpvm):
    mpvm.list_remote_scanner_tasks.return_value = {"items": []}
    assert client.get("/api/mpvm/scanner-tasks/remote?limit=5").json() == {"items": []}
    mpvm.list_remote_scanner_tasks.side_effect = MpVmApiError("down")
    assert client.get("/api/mpvm/scanner-tasks/remote").status_code >= 400

    container.services.tasks.list.return_value = [{"id": "t"}]
    assert client.get("/api/scanner-tasks").json() == [{"id": "t"}]


def test_task_results_cover_every_branch(client, mpvm):
    with patch.object(db, "get_scan_task", return_value=None):
        assert client.get("/api/scanner-tasks/t1/results").status_code == 404

    task = {"name": "Audit", "status": "precheck_done"}
    with patch.object(db, "get_scan_task", return_value=task):
        mpvm.get_task_runs.return_value = []
        empty = client.get("/api/scanner-tasks/t1/results").json()
        assert empty["items"] == [] and empty["is_precheck"] is True

        mpvm.get_task_runs.return_value = [{"id": " "}]
        assert client.get("/api/scanner-tasks/t1/results").status_code == 502

        mpvm.get_task_runs.return_value = [{"id": "run-1"}]
        mpvm.get_all_run_jobs.return_value = [{"runMode": "connectionCheck"}, {"runMode": "default"}]
        full = client.get("/api/scanner-tasks/t1/results").json()
        assert full["total"] == 2 and full["run"] == {"id": "run-1"}

        mpvm.get_task_runs.side_effect = requests.ConnectionError("down")
        assert client.get("/api/scanner-tasks/t1/results").status_code >= 400

    with patch.object(db, "get_scan_task", return_value={"name": None, "status": "created"}):
        mpvm.get_task_runs.side_effect = None
        mpvm.get_task_runs.return_value = [{"id": "run-1"}]
        mpvm.get_all_run_jobs.return_value = [{"runMode": "default"}]
        plain = client.get("/api/scanner-tasks/t1/results").json()
        assert plain["is_precheck"] is False and plain["task_name"] == "t1"


TASK_BODY = {"name": "Audit", "scope_id": "s", "profile_id": "p", "include_targets": ["10.0.0.1"]}


def test_create_update_validate_stop_tasks(client, mpvm):
    with patch.object(scanner_tasks, "scanner_task_payload", return_value={"name": "Audit"}), patch.object(db, "record_scan_task", return_value={"id": "t1"}) as record:
        mpvm.create_scanner_task.return_value = "t1"
        assert client.post("/api/scanner-tasks", json=TASK_BODY).json() == {"id": "t1"}
        assert record.call_args.kwargs["status"] == "created"
        mpvm.update_scanner_task.return_value = {"ok": True}
        assert client.put("/api/scanner-tasks/t1", json=TASK_BODY).json() == {"id": "t1"}
        assert record.call_args.kwargs["status"] == "updated"
        mpvm.create_scanner_task.side_effect = MpVmApiError("rejected")
        assert client.post("/api/scanner-tasks", json=TASK_BODY).status_code >= 400
        mpvm.update_scanner_task.side_effect = requests.Timeout("slow")
        assert client.put("/api/scanner-tasks/t1", json=TASK_BODY).status_code >= 400

    with patch.object(db, "update_scan_task_status") as status:
        mpvm.validate_scanner_task.return_value = (False, "no scope")
        assert client.post("/api/scanner-tasks/t1/validate").json() == {"id": "t1", "valid": False, "error": "no scope"}
        status.assert_called_with("t1", "validation_failed", {"error": "no scope"})
        mpvm.validate_scanner_task.side_effect = MpVmApiError("down")
        assert client.post("/api/scanner-tasks/t1/validate").status_code >= 400

        mpvm.stop_scanner_task.return_value = {"stopped": True}
        assert client.post("/api/scanner-tasks/t1/stop").json() == {"stopped": True}
        status.assert_called_with("t1", "stop_requested", {"stopped": True})
        mpvm.stop_scanner_task.side_effect = MpVmApiError("down")
        assert client.post("/api/scanner-tasks/t1/stop").status_code >= 400


def test_start_task_tracks_workflow_and_survives_tracking_failure(client, container):
    container.services.vm_workflows.track_scan.return_value = {"workflow_id": "wf-1"}
    with patch.object(scanner_tasks, "_start_scanner_task_request", return_value={"operation_id": "op-1"}) as start:
        started = client.post("/api/scanner-tasks/t1/start", json={"precheck_enabled": True}, headers={"X-Idempotency-Key": "k"})
    assert started.status_code == 202
    assert started.json()["workflow_id"] == "wf-1"
    assert start.call_args.args[2] == "k" and start.call_args.args[1].precheck_enabled is True

    container.services.vm_workflows.track_scan.side_effect = psycopg.OperationalError("db down")
    with patch.object(scanner_tasks, "_start_scanner_task_request", return_value={"postprocess_run_id": "pp-1"}), patch.object(main, "log_exception") as log:
        degraded = client.post("/api/scanner-tasks/t1/start")
    assert degraded.status_code == 202 and "workflow_id" not in degraded.json()
    log.assert_called_once()

    with patch.object(scanner_tasks, "_start_scanner_task_request", return_value={"started": True}):
        assert client.post("/api/scanner-tasks/t1/start").json() == {"started": True}
    container.services.vm_workflows.track_scan.assert_called()


def test_retry_false_precheck_latest_run_and_delete(client, mpvm):
    with patch.object(scanner_tasks, "run_false_targets_precheck", return_value={"retried": 2}) as retry:
        assert client.post("/api/scanner-tasks/t1/retry-false").json() == {"retried": 2}
        assert retry.call_args.kwargs["source_precheck_task_id"] == "t1"
    with patch.object(scanner_tasks, "run_false_targets_precheck", side_effect=requests.ConnectionError("down")):
        assert client.post("/api/scanner-tasks/t1/retry-false").status_code >= 400

    with patch.object(db, "get_latest_scan_postprocess_run", return_value=None):
        assert client.get("/api/scanner-tasks/t1/postprocess-runs/latest").status_code == 404
    with patch.object(db, "get_latest_scan_postprocess_run", return_value={"run_id": "r"}):
        assert client.get("/api/scanner-tasks/t1/postprocess-runs/latest").json() == {"run_id": "r"}

    with patch.object(scanner_tasks, "delete_scanner_task_idempotent", return_value={"deleted": True}) as delete:
        assert client.post("/api/scanner-tasks/t1/delete", json={"mode": "local_only"}, headers={"X-Idempotency-Key": "k"}).json() == {"deleted": True}
        assert client.delete("/api/scanner-tasks/t1").json() == {"deleted": True}
    assert delete.call_args_list[0].args[1].mode == "local_only" and delete.call_args_list[0].args[2] == "k"
    assert delete.call_args_list[1].args[1].mode == "delete_v3"


# ---------------------------------------------------------------------- imports/exports


def test_pdql_export_without_import_or_removal(client, mpvm, tmp_path):
    mpvm.create_pdql_token.return_value = "pdql-token"
    mpvm.fetch_csv.return_value = "a;b\n1;2\n"
    with patch.object(main, "EXPORTS_DIR", tmp_path):
        result = client.post("/api/exports/pdql", json={"import_results": False, "delete_assets_after_export": False}).json()
    assert result["pdql_token"] == "pdql-token" and result["import"] is None and result["removal"] is None
    assert (tmp_path / result["csv_filename"]).read_text(encoding="utf-8-sig") == "a;b\n1;2\n"
    assert result["csv_bytes"] > 0


def test_pdql_export_imports_then_removes_assets_in_order(client, mpvm, tmp_path):
    order: list[str] = []
    mpvm.create_pdql_token.return_value = "tok"
    mpvm.fetch_csv.return_value = "csv"
    with (
        patch.object(main, "EXPORTS_DIR", tmp_path),
        patch.object(db, "import_csv_text", side_effect=lambda *a, **k: order.append("import") or {"run_id": 7}),
        patch.object(imports_exports, "remove_assets_after_export", side_effect=lambda **k: order.append("remove") or {"removed": 1}) as remove,
    ):
        result = client.post("/api/exports/pdql", json={"delete_assets_after_export": True}).json()
    assert order == ["import", "remove"], "assets must only be removed after the local import"
    assert remove.call_args.kwargs["import_run_id"] == 7 and result["removal"] == {"removed": 1}


def test_pdql_export_maps_remote_failures(client, mpvm, tmp_path):
    mpvm.create_pdql_token.side_effect = MpVmApiError("rejected")
    with patch.object(main, "EXPORTS_DIR", tmp_path):
        assert client.post("/api/exports/pdql", json={}).status_code >= 400
    assert list(tmp_path.iterdir()) == []


def test_csv_imports(client, tmp_path):
    with patch.object(db, "import_csv_text", return_value={"run_id": 1}) as imported:
        assert client.post("/api/import/csv-text", json={"csv_text": "a;b"}).json() == {"run_id": 1}
        upload = client.post("/api/import/csv-file", files={"file": ("hosts.csv", io.BytesIO("a;b\n".encode()), "text/csv")})
    assert upload.json() == {"run_id": 1}
    assert imported.call_args.kwargs["source"] == "uploaded_csv" and imported.call_args.kwargs["csv_filename"] == "hosts.csv"

    with patch.object(main, "SETTINGS", MagicMock(import_max_upload_mb=0)):
        too_big = client.post("/api/import/csv-file", files={"file": ("big.csv", io.BytesIO(b"x"), "text/csv")})
    assert too_big.status_code == 413 and too_big.json()["detail"]["code"] == "IMPORT_TOO_LARGE"

    missing = tmp_path / "missing.csv"
    with patch.object(main, "SAMPLE_CSV", missing):
        assert client.post("/api/import/sample").status_code == 404
    sample = tmp_path / "sample.csv"
    sample.write_text("a;b\n", encoding="utf-8")
    with patch.object(main, "SAMPLE_CSV", sample), patch.object(db, "import_csv_text", return_value={"run_id": 2}) as imported:
        assert client.post("/api/import/sample").json() == {"run_id": 2}
    assert imported.call_args.kwargs["source"] == "sample_csv"


@pytest.mark.parametrize("report_type", ["os", "software", "docker"])
def test_vulnerability_csv_reports_pick_the_right_row_source(client, report_type):
    with (
        patch.object(db, "iter_vulnerability_report_rows", return_value=iter([])) as rows,
        patch.object(db, "iter_docker_vulnerability_report_rows", return_value=iter([])) as docker_rows,
    ):
        response = client.post(f"/api/reports/vulnerabilities/{report_type}/csv", json={"asset_ids": [" a1 ", "a1", ""]})
    assert response.status_code == 200
    assert f"host_{report_type}_vulnerabilities_" in response.headers["content-disposition"]
    assert (docker_rows.call_count, rows.call_count) == ((1, 0) if report_type == "docker" else (0, 1))
    used = docker_rows if report_type == "docker" else rows
    assert used.call_args.args[-1] == ["a1"]


def test_vulnerability_xlsx_report_and_export_download(client, tmp_path):
    with patch.object(db, "get_asset_card", return_value=None):
        assert client.post("/api/reports/vulnerabilities/xlsx", json={"asset_id": "a1"}).status_code == 404

    with (
        patch.object(db, "get_asset_card", return_value={"asset_id": "a1"}),
        patch.object(db, "iter_vulnerability_report_rows", return_value=iter([])),
        patch.object(db, "iter_docker_vulnerability_report_rows", return_value=iter([])),
        patch("app.api.imports_exports.render_vulnerability_xlsx", return_value=b"PK-xlsx") as render,
    ):
        response = client.post("/api/reports/vulnerabilities/xlsx", json={"asset_id": " a1 "})
    assert response.content == b"PK-xlsx" and "asset_a1_vulnerabilities_" in response.headers["content-disposition"]
    assert render.call_args.args[0] == {"asset_id": "a1"}

    (tmp_path / "ok.csv").write_text("x", encoding="utf-8")
    with patch.object(main, "EXPORTS_DIR", tmp_path):
        assert client.get("/api/exports/ok.csv").content == b"x"
        assert client.get("/api/exports/nope.csv").status_code == 404
        # path components are stripped, so traversal cannot leave the exports directory
        assert client.get("/api/exports/..%2Fsecret.csv").status_code in {403, 404}


# -------------------------------------------------------------------------- middleware


def test_cross_site_mutation_without_allowed_origin_is_rejected(client):
    response = client.post(
        "/api/operations/clear-history",
        headers={"sec-fetch-site": "cross-site", "origin": "https://evil.example"},
    )
    assert response.status_code == 403 and response.json()["detail"]["code"] == "CROSS_SITE_REQUEST"


def test_auth_database_outage_is_reported_as_503():
    with patch.object(auth, "get_session_user", side_effect=psycopg.OperationalError("down")):
        response = TestClient(main.app).get("/api/operations")
    assert response.status_code == 503 and response.json()["detail"]["code"] == "AUTH_DATABASE_UNAVAILABLE"


def test_audited_write_is_recorded_and_failures_are_not(client):
    with patch.object(auth, "audit_event") as audit, patch.object(main, "CONTAINER") as fake:
        fake.services.operations.clear_history.return_value = {"cleared": 0}
        client.post("/api/operations/clear-history")
    assert audit.call_args.kwargs["event_type"] == "critical_action"
    assert audit.call_args.kwargs["permission_key"] == "operations.clear"


def test_request_headers_carry_trace_ids_and_failures_are_logged(client):
    ok = client.get("/api/operations/summary", headers={"X-Trace-ID": "trace-123456", "X-Request-ID": "req-123456"})
    assert ok.headers["X-Trace-ID"] == "trace-123456" and ok.headers["X-Request-ID"] == "req-123456"
    assert ok.headers["Server-Timing"].startswith("app;dur=")

    with patch.object(main, "CONTAINER") as fake, patch.object(main, "log_exception") as log:
        fake.services.operations.summary.side_effect = RuntimeError("boom")
        with pytest.raises(RuntimeError):
            client.get("/api/operations/summary")
    assert log.call_args.args[:2] == ("app", "api.request.failed")


def test_error_handlers_shape_validation_database_and_http_errors(client):
    invalid = client.post("/api/scanner-tasks", json={"name": "only a name"})
    assert invalid.status_code == 422 and invalid.json()["detail"]["code"] == "VALIDATION_FAILED"

    with patch.object(main, "CONTAINER") as fake:
        fake.services.operations.summary.side_effect = psycopg.OperationalError("down")
        unavailable = client.get("/api/operations/summary")
        assert unavailable.status_code == 503 and unavailable.json()["detail"]["code"] == "DATABASE_UNAVAILABLE"
        fake.services.operations.summary.side_effect = psycopg.ProgrammingError("syntax")
        broken = client.get("/api/operations/summary")
        assert broken.status_code == 500 and broken.json()["detail"]["code"] == "INTERNAL_DATABASE_QUERY_ERROR"


@pytest.mark.parametrize(
    ("path", "component"),
    [
        ("/api/session", "mpvm"),
        ("/api/mpvm/lookups", "mpvm"),
        ("/api/asset-cards/x", "asset_cards"),
        ("/api/vulnerability-passports/x", "vulnerability_passports"),
        ("/api/vulnerabilities", "vulnerabilities"),
        ("/api/scanner-tasks", "scanner_tasks"),
        ("/api/operations", "operations"),
        ("/api/other", "application"),
    ],
)
def test_error_component_and_operator_messages(path, component):
    from app.api.middleware import error_component, operator_error_message

    assert error_component(path) == component
    assert "PostgreSQL" in operator_error_message(503, component, "m")
    assert "MP VM" in operator_error_message(502, component, "m")
    assert operator_error_message(409, component, "m").startswith("Операция")
    assert operator_error_message(404, component, "m").startswith("Запрошенный")
    assert operator_error_message(422, component, "m").startswith("Проверьте")
    assert operator_error_message(500, component, "boom") == "boom"
    assert component in operator_error_message(500, component, "")
