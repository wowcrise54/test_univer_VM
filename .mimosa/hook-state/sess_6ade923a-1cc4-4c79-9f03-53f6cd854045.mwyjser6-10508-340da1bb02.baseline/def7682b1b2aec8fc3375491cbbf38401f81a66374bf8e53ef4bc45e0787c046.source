from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app import diagnostics


class DiagnosticLoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.temp_dir.name) / "logs"

    def tearDown(self) -> None:
        diagnostics.shutdown_diagnostics()
        self.temp_dir.cleanup()

    def configure(
        self,
        *,
        max_bytes: int = 4096,
        backup_count: int = 3,
        debug_payloads: bool = False,
        payload_max_bytes: int = 512,
    ) -> diagnostics.DiagnosticsConfig:
        config = diagnostics.DiagnosticsConfig(
            level="DEBUG",
            log_dir=self.log_dir,
            max_bytes=max_bytes,
            backup_count=backup_count,
            retention_days=14,
            debug_payloads=debug_payloads,
            payload_max_bytes=payload_max_bytes,
            payload_retention_hours=24,
        )
        diagnostics.configure_diagnostics(config, force=True)
        return config

    def test_context_stack_trace_rotation_and_secret_redaction(self):
        self.configure(max_bytes=1024, backup_count=2)
        with diagnostics.diagnostic_context(
            trace_id="trace-1",
            request_id="request-1",
            job_id="job-1",
            asset_id="asset-1",
            stage="collecting",
        ):
            diagnostics.log_event(
                "app",
                "diagnostic.test",
                password="plain-password",
                authorization="Bearer raw-token",
                database="postgresql://user:super-secret@localhost:5432/mpvm",
                nested={"clientSecret": "client-value", "safe": "visible"},
            )
            try:
                raise RuntimeError("fixture failure")
            except RuntimeError:
                diagnostics.log_exception("app", "diagnostic.failed")
            for index in range(100):
                diagnostics.log_event("app", "diagnostic.rotation", level=logging.INFO, index=index, text="x" * 180)
            diagnostics.log_event(
                "app",
                "diagnostic.redaction.final",
                password="plain-password",
                authorization="Bearer raw-token",
                database="postgresql://user:super-secret@localhost:5432/mpvm",
                nested={"clientSecret": "client-value", "safe": "visible"},
            )

        diagnostics.flush_diagnostics()
        diagnostics.shutdown_diagnostics()
        paths = sorted(self.log_dir.glob("app.jsonl*"))
        self.assertGreaterEqual(len(paths), 2)
        self.assertLessEqual(len(paths), 3)
        content = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertNotIn("plain-password", content)
        self.assertNotIn("raw-token", content)
        self.assertNotIn("super-secret", content)
        self.assertNotIn("client-value", content)
        self.assertIn("[REDACTED]", content)
        self.assertIn("trace-1", content)
        self.assertIn("request-1", content)
        errors = (self.log_dir / "errors.jsonl").read_text(encoding="utf-8")
        self.assertIn("fixture failure", errors)
        self.assertIn("Traceback", errors)

    def test_debug_payload_is_sanitized_and_truncated(self):
        self.configure(debug_payloads=True, payload_max_bytes=256)
        diagnostics.capture_debug_payload(
            direction="request",
            payload={"access_token": "raw-token", "body": "z" * 2000},
            trace_id="trace-payload",
        )
        diagnostics.flush_diagnostics()
        diagnostics.shutdown_diagnostics()
        content = (self.log_dir / "debug-payloads.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("raw-token", content)
        self.assertIn("[REDACTED]", content)
        self.assertIn('"truncated":true', content)
        safe_url = diagnostics.sanitize_url("https://user:pass@example.test/api/tree?token=timeline-secret&offset=0")
        self.assertNotIn("timeline-secret", safe_url)
        self.assertNotIn("user:pass", safe_url)

    def test_archive_filters_events_by_trace_and_job(self):
        self.configure()
        diagnostics.log_event("asset-card-build", "build.started", trace_id="trace-a", job_id="job-a")
        diagnostics.log_event("asset-card-build", "build.completed", trace_id="trace-a", job_id="job-a")
        diagnostics.log_event("asset-card-build", "build.started", trace_id="trace-b", job_id="job-b")
        diagnostics.flush_diagnostics()
        output = Path(self.temp_dir.name) / "bundle.zip"
        archive_path = diagnostics.build_diagnostic_archive(trace_id="trace-a", job_id="job-a", output_path=output)
        diagnostics.flush_diagnostics()

        self.assertEqual(archive_path, output)
        with zipfile.ZipFile(output) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            events = archive.read("events.jsonl").decode("utf-8")
        self.assertEqual(manifest["trace_id"], "trace-a")
        self.assertEqual(manifest["job_id"], "job-a")
        self.assertEqual(manifest["event_count"], 2)
        self.assertIn("build.completed", events)
        self.assertNotIn("trace-b", events)

    def test_frontend_endpoint_returns_trace_headers_and_redacts_event(self):
        self.configure()
        from fastapi.testclient import TestClient
        from app import main

        with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}):
            response = TestClient(main.app).post(
                "/api/diagnostics/frontend",
                headers={"X-Trace-ID": "trace-client", "X-Request-ID": "request-client"},
                json={
                    "events": [{
                        "event": "ui.test.failed",
                        "level": "error",
                        "trace_id": "trace-ui",
                        "url": "/asset-cards",
                        "stack": "Error: fixture",
                        "fields": {"password": "plain-password", "status": 500},
                    }],
                },
            )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.headers["x-trace-id"], "trace-client")
        self.assertEqual(response.headers["x-request-id"], "request-client")
        self.assertIn("app;dur=", response.headers["server-timing"])
        diagnostics.flush_diagnostics()
        content = (self.log_dir / "frontend.jsonl").read_text(encoding="utf-8")
        self.assertIn("ui.test.failed", content)
        self.assertIn("trace-ui", content)
        self.assertNotIn("plain-password", content)


    def test_archive_without_logs_contains_safe_operation_and_events(self):
        self.configure()
        from app import main

        diagnostics.log_event("app", "unrelated", job_id="other-job", message="unrelated-secret")
        diagnostics.flush_diagnostics()
        operation = {
            "operation_id": "operation-1",
            "kind": "automation_run", "status": "failed",
            "message": "Failed with Bearer top-secret",
            "request": {"password": "request-secret"},
            "result": {"unsafe": "result-secret"},
            "events": [{
                "id": "event-1", "stage": "failed", "message": "Bearer event-secret",
                "status": "failed", "details": {"password": "nested-secret"},
            }],
        }
        with patch.object(main.db, "get_operation", return_value=operation):
            response = main.operation_diagnostics("operation-1")
        with zipfile.ZipFile(response.path) as archive:
            snapshot = json.loads(archive.read("operation.json"))
            event_lines = archive.read("operation-events.jsonl").decode("utf-8")
            manifest = json.loads(archive.read("manifest.json"))
            readme = archive.read("README.txt").decode("utf-8")
            all_content = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
        self.assertEqual(snapshot["operation_id"], "operation-1")
        self.assertEqual(snapshot["status"], "failed")
        self.assertNotIn("request", snapshot)
        self.assertNotIn("result", snapshot)
        self.assertIn("event-1", event_lines)
        self.assertEqual(manifest["event_count"], 0)
        self.assertEqual(manifest["logs_available"], False)
        self.assertIn("отсутствуют", readme)
        for secret in ("top-secret", "event-secret", "request-secret", "result-secret", "nested-secret", "unrelated-secret"):
            self.assertNotIn(secret, all_content)

    def test_archive_download_preserves_permission_and_missing_operation(self):
        self.configure()
        from fastapi.testclient import TestClient
        from app import main
        client = TestClient(main.app)
        for role in ("viewer", "operator"):
            with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": role}), patch.object(main.db, "get_operation") as get_operation:
                response = client.get("/api/operations/missing/diagnostics")
                self.assertEqual(response.status_code, 403)
                get_operation.assert_not_called()
        with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}), patch.object(main.db, "get_operation", return_value=None):
            response = client.get("/api/operations/missing/diagnostics")
            self.assertEqual(response.status_code, 404)
    def test_authorized_download_returns_a_usable_zip_without_log_identifiers(self):
        self.configure()
        from fastapi.testclient import TestClient
        from app import main

        operation = {"operation_id": "operation-ok", "status": "completed", "events": []}
        user = {"id": 1, "role": "custom", "permissions": ["diagnostics.read"]}
        with patch.object(main.app_auth, "get_session_user", return_value=user), patch.object(main.db, "get_operation", return_value=operation):
            response = TestClient(main.app).get("/api/operations/operation-ok/diagnostics")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertIn(".zip", response.headers["content-disposition"])
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(json.loads(archive.read("operation.json"))["operation_id"], "operation-ok")
    def test_default_archives_with_a_shared_trace_never_overwrite_each_other(self):
        self.configure()
        with patch.object(diagnostics.time, "time", return_value=1790770000):
            first = diagnostics.build_diagnostic_archive(
                trace_id="shared-trace", operation_snapshot={"operation_id": "operation-first"},
            )
            second = diagnostics.build_diagnostic_archive(
                trace_id="shared-trace", operation_snapshot={"operation_id": "operation-second"},
            )
        self.assertNotEqual(first, second)
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(json.loads(archive.read("operation.json"))["operation_id"], "operation-first")
        with zipfile.ZipFile(second) as archive:
            self.assertEqual(json.loads(archive.read("operation.json"))["operation_id"], "operation-second")
        explicit = Path(self.temp_dir.name) / "requested.zip"
        returned = diagnostics.build_diagnostic_archive(
            trace_id="shared-trace", output_path=explicit,
            operation_snapshot={"operation_id": "operation-explicit"},
        )
        self.assertEqual(returned, explicit)
        with zipfile.ZipFile(explicit) as archive:
            self.assertEqual(json.loads(archive.read("operation.json"))["operation_id"], "operation-explicit")


if __name__ == "__main__":
    unittest.main()
