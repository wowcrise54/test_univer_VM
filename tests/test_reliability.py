from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psycopg
from fastapi import BackgroundTasks, HTTPException
from fastapi.testclient import TestClient

from app import db, main


class QueryResult:
    def __init__(self, *, one=None, rows=None):
        self._one = one
        self._rows = rows or []

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._rows


class ScriptedConnection:
    def __init__(self, results):
        self.results = iter(results)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params=None):
        self.queries.append((sql, params))
        return next(self.results)


class SystemStatusTests(unittest.TestCase):
    def test_database_outage_is_reported_as_degraded_without_leaking_dsn(self):
        session = SimpleNamespace(client=None, access_token=None, api_url="https://fixture")
        with patch.object(main, "SESSION", session), patch.object(main, "DATABASE_STARTUP_ERROR", None), patch.object(
            main.db, "connect", side_effect=psycopg.OperationalError("secret-host failed")
        ):
            result = main.system_status()

        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["components"]["database"]["state"], "down")
        self.assertEqual(result["components"]["database"]["reason"], "OperationalError")
        self.assertNotIn("secret-host", str(result))

    def test_http_errors_use_the_normalized_contract(self):
        with (
            patch.object(main.db, "init_db"),
            patch.object(main.db, "interrupt_active_vulnerability_passport_detail_jobs"),
            patch.object(main.db, "interrupt_active_asset_card_build_jobs"),
            patch.object(main.db, "release_scan_postprocess_leases"),
            patch.object(main.db, "sync_operations_from_sources"),
            patch.object(main, "start_asset_search_backfill"),
            patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}),
            TestClient(main.app) as client,
        ):
            response = client.get("/api/not-found")

        self.assertEqual(response.status_code, 404)
        detail = response.json()["detail"]
        self.assertEqual(detail["code"], "HTTP_404")
        self.assertEqual(detail["component"], "application")
        self.assertIn("trace_id", detail)
        self.assertIn("request_id", detail)


class OperationsApiTests(unittest.TestCase):
    def test_operation_search_includes_operation_id(self):
        connection = ScriptedConnection([
            QueryResult(one={"count": 0}),
            QueryResult(rows=[]),
        ])
        with patch.object(db, "connect", return_value=connection):
            result = db.list_operations(q="OP-123")

        self.assertEqual(result["total"], 0)
        count_sql, count_params = connection.queries[0]
        self.assertIn("LOWER(COALESCE(operation_id, '')) LIKE %s", count_sql)
        self.assertEqual(count_params, ["%op-123%"] * 4)

    def test_summary_aggregates_all_operation_statuses_and_kinds(self):
        connection = ScriptedConnection([
            QueryResult(one={"total": 7, "active": 2, "attention": 3, "updated_at": "2026-07-12T10:00:00+00:00"}),
            QueryResult(rows=[{"status": "failed", "count": 3}, {"status": "running", "count": 2}]),
            QueryResult(rows=[{"kind": "asset_card_build", "count": 5}, {"kind": "automation_run", "count": 2}]),
        ])
        with patch.object(db, "connect", return_value=connection):
            result = db.get_operations_summary()

        self.assertEqual(result, {
            "total": 7,
            "active": 2,
            "attention": 3,
            "by_status": {"failed": 3, "running": 2},
            "by_kind": {"asset_card_build": 5, "automation_run": 2},
            "updated_at": "2026-07-12T10:00:00+00:00",
        })

    def test_summary_endpoint_uses_container_service(self):
        expected = {
            "total": 4,
            "active": 1,
            "attention": 2,
            "by_status": {"running": 1, "failed": 2, "completed": 1},
            "by_kind": {"automation_run": 4},
            "updated_at": "2026-07-12T10:00:00+00:00",
        }
        service = main.CONTAINER.services.operations
        with patch.object(service, "summary", return_value=expected) as summary, patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}
        ):
            response = TestClient(main.app).get("/api/operations/summary")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        summary.assert_called_once_with()

    def test_operations_repository_refreshes_source_jobs_before_reads(self):
        repository = main.CONTAINER.repositories.operations
        with (
            patch.object(main.db, "list_operations", return_value={"rows": [], "total": 0}) as list_operations,
            patch.object(main.db, "get_operations_summary", return_value={"total": 0}) as summary,
            patch.object(main.db, "get_operation", return_value=None) as get_operation,
        ):
            repository.list(limit=25)
            repository.summary()
            repository.get("operation-1")

        list_operations.assert_called_once_with(limit=25, sync_sources=True)
        summary.assert_called_once_with(sync_sources=True)
        get_operation.assert_called_once_with("operation-1", sync_sources=True)

    def test_cancel_refreshes_operation_after_source_job_changes(self):
        queued = {
            "operation_id": "operation-1",
            "source_id": "job-1",
            "kind": "asset_card_build",
            "status": "queued",
            "can_cancel": True,
        }
        cancelling = {**queued, "status": "cancelling"}
        with (
            patch.object(main.db, "get_operation", side_effect=[queued, cancelling]) as get_operation,
            patch.object(main, "cancel_asset_card_build_job") as cancel,
        ):
            result = main.cancel_operation("operation-1")

        self.assertEqual(result, cancelling)
        cancel.assert_called_once_with("job-1")
        self.assertEqual(
            get_operation.call_args_list,
            [
                unittest.mock.call("operation-1", sync_sources=True),
                unittest.mock.call("operation-1", sync_sources=True),
            ],
        )

    def test_scan_postprocess_operation_is_cancellable_from_operations_center(self):
        queued = {
            "operation_id": "postprocess-1",
            "source_id": "postprocess-1",
            "kind": "scan_postprocess",
            "status": "processing",
            "can_cancel": True,
        }
        cancelling = {**queued, "status": "cancelling"}
        with (
            patch.object(main.db, "get_operation", side_effect=[queued, cancelling]),
            patch.object(main, "cancel_scan_postprocess_run") as cancel,
        ):
            result = main.cancel_operation("postprocess-1")

        self.assertEqual(result, cancelling)
        cancel.assert_called_once_with("postprocess-1")

    def test_scan_postprocess_cancel_stops_remote_scanner_task(self):
        client = unittest.mock.MagicMock()
        run = {
            "run_id": "postprocess-1",
            "mp_task_id": "refresh-task-1",
            "status": "cancelling",
            "cancel_requested": True,
        }
        with (
            patch.object(main.db, "request_scan_postprocess_cancel", return_value=run),
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main.db, "list_scan_postprocess_items", return_value=[]),
            patch.object(main.db, "get_scan_postprocess_run", return_value=run),
        ):
            result = main.cancel_scan_postprocess_run("postprocess-1")

        self.assertEqual(result["status"], "cancelling")
        client.stop_scanner_task_best_effort.assert_called_once_with("token", "refresh-task-1")
        self.assertTrue(main.SCAN_POSTPROCESS_CANCEL_EVENTS["postprocess-1"].is_set())
        main.SCAN_POSTPROCESS_CANCEL_EVENTS.pop("postprocess-1", None)

    def test_cancel_of_terminal_operation_is_idempotent(self):
        operation = {
            "operation_id": "operation-1",
            "source_id": "job-1",
            "kind": "asset_card_build",
            "status": "completed",
            "can_cancel": False,
        }
        with patch.object(main.db, "get_operation", return_value=operation) as get_operation:
            result = main.cancel_operation("operation-1")
        self.assertIs(result, operation)
        get_operation.assert_called_once_with("operation-1", sync_sources=True)

    def test_retry_replays_existing_idempotency_key(self):
        existing = {"operation_id": "operation-new", "kind": "asset_card_build"}
        with patch.object(main.db, "get_operation_by_idempotency_key", return_value=existing):
            result = main.retry_operation(
                "operation-old",
                BackgroundTasks(),
                idempotency_key="retry:key",
            )
        self.assertTrue(result["idempotent_replay"])
        self.assertEqual(result["operation"], existing)

    def test_missing_operation_returns_404(self):
        with patch.object(main.db, "get_operation", return_value=None):
            with self.assertRaises(HTTPException) as raised:
                main.operation_detail("missing")
        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
