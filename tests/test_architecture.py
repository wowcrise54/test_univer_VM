from __future__ import annotations

import threading
import unittest
from pathlib import Path

from app import db, main
from app.core.config import Settings
from app.core.runtime import CancellationRegistry, OperationRunner

EXPECTED_API_PATHS = {
    "/api/health",
    "/api/system/status",
    "/api/session",
    "/api/session/connect",
    "/api/scanner-tasks",
    "/api/operations",
    "/api/operations/summary",
    "/api/exports/pdql",
    "/api/reports/vulnerabilities/{report_type}/csv",
    "/api/assets",
    "/api/asset-cards/local",
    "/api/asset-card-query",
    "/api/vulnerability-passports/local",
    "/api/vulnerabilities/summary",
    "/api/vulnerabilities",
    "/api/vulnerabilities/hosts",
    "/api/diagnostics/frontend",
    "/api/automations/runbooks",
    "/api/automations/schedules",
    "/api/automations/runs",
    "/api/notifications",
    "/api/remediation/cases",
    "/api/remediation/summary",
    "/api/remediation/policy",
    "/api/coverage/summary",
    "/api/coverage/assets",
}


class ContractTests(unittest.TestCase):
    def test_runtime_image_includes_alembic_assets(self):
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY alembic.ini ./alembic.ini", dockerfile)
        self.assertIn("COPY migrations ./migrations", dockerfile)

    def test_openapi_keeps_public_domain_paths(self):
        schema = main.app.openapi()
        self.assertTrue(EXPECTED_API_PATHS.issubset(schema["paths"]))

    def test_routes_are_grouped_by_domain_tags(self):
        schema = main.app.openapi()
        self.assertEqual(schema["paths"]["/api/session"]["get"]["tags"], ["session"])
        self.assertEqual(schema["paths"]["/api/operations"]["get"]["tags"], ["operations"])
        self.assertEqual(schema["paths"]["/api/asset-card-query"]["post"]["tags"], ["asset-query"])

    def test_baseline_schema_is_idempotent_and_non_destructive(self):
        statements = db.schema_statements()
        sql = "\n".join(statements).upper()
        self.assertIn("CREATE TABLE IF NOT EXISTS OPERATIONS", sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS ASSET_CARDS", sql)
        self.assertNotIn("DROP TABLE", sql)


class RuntimeTests(unittest.TestCase):
    def test_cancellation_registry_owns_tokens(self):
        registry = CancellationRegistry()
        token = registry.register("asset-card", "job-1")
        self.assertIsInstance(token, threading.Event)
        self.assertTrue(registry.cancel("asset-card", "job-1"))
        self.assertTrue(token.is_set())
        registry.remove("asset-card", "job-1")
        self.assertFalse(registry.cancel("asset-card", "job-1"))

    def test_operation_runner_can_restart_after_shutdown(self):
        runner = OperationRunner({"test": 1})
        self.assertEqual(runner.submit("test", lambda: 42).result(timeout=2), 42)
        runner.shutdown()
        runner.start()
        self.assertEqual(runner.submit("test", lambda: 43).result(timeout=2), 43)
        runner.shutdown()

    def test_settings_reject_invalid_worker_limits(self):
        with self.assertRaises(ValueError):
            Settings(background_request_limit=0)


if __name__ == "__main__":
    unittest.main()
