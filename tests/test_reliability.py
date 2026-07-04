from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import psycopg
from fastapi import BackgroundTasks, HTTPException
from fastapi.testclient import TestClient

from app import main


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
    def test_cancel_of_terminal_operation_is_idempotent(self):
        operation = {
            "operation_id": "operation-1",
            "source_id": "job-1",
            "kind": "asset_card_build",
            "status": "completed",
            "can_cancel": False,
        }
        with patch.object(main.db, "get_operation", return_value=operation):
            result = main.cancel_operation("operation-1")
        self.assertIs(result, operation)

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
