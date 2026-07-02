from __future__ import annotations

import json
import logging
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import diagnostics
from app.mpvm_client import AuthConfig, MpVmClient


class CountingJsonResponse:
    def __init__(self) -> None:
        self.ok = True
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self.raw = SimpleNamespace(retries=SimpleNamespace(history=()))
        self.content = b'{"value": 1}'
        self.json_calls = 0
        self.text_calls = 0

    @property
    def text(self):
        self.text_calls += 1
        return self.content.decode("utf-8")

    def json(self):
        self.json_calls += 1
        return {"value": 1}


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

    def test_disabled_debug_payload_does_not_parse_response_twice(self):
        self.configure(debug_payloads=False)
        response = CountingJsonResponse()
        auth = AuthConfig(api_url="https://fixture", token_url="https://fixture/token", access_token="token")
        client = MpVmClient(auth)
        with patch.object(diagnostics.requests.Session, "request", return_value=response):
            value = client.get_json("token", "/api/fixture")
        client.session.close()

        self.assertEqual(value, {"value": 1})
        self.assertEqual(response.json_calls, 1)
        self.assertEqual(response.text_calls, 0)

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


if __name__ == "__main__":
    unittest.main()
