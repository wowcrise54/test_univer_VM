"""MPVM_DEBUG_MODE records full HTTP exchanges while keeping secrets out of the logs."""
import json
import zipfile
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests
from fastapi.testclient import TestClient

from app import diagnostics


@pytest.fixture()
def debug_config(tmp_path):
    config = diagnostics.DiagnosticsConfig(
        level="DEBUG", log_dir=tmp_path / "logs", max_bytes=1024 * 1024,
        backup_count=2, retention_days=2, debug_payloads=True,
        payload_max_bytes=2048, payload_retention_hours=1, debug_mode=True,
    )
    diagnostics.configure_diagnostics(config, force=True)
    yield config
    diagnostics.shutdown_diagnostics()


def read_events(config, name):
    diagnostics.flush_diagnostics()
    diagnostics.shutdown_diagnostics()
    path = config.log_dir / name
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def post_frontend_event(**kwargs):
    from app import main

    with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}):
        return TestClient(main.app).post("/api/diagnostics/frontend", **kwargs)


def test_debug_mode_env_forces_debug_level_and_payload_capture(monkeypatch, tmp_path):
    monkeypatch.setenv("MPVM_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("MPVM_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("MPVM_DEBUG_PAYLOADS", "false")
    monkeypatch.setenv("MPVM_DEBUG_MODE", "true")
    config = diagnostics.DiagnosticsConfig.from_env()
    assert (config.debug_mode, config.level, config.debug_payloads) == (True, "DEBUG", True)


def test_debug_mode_is_off_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("MPVM_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("MPVM_DEBUG_MODE", raising=False)
    monkeypatch.delenv("MPVM_DEBUG_PAYLOADS", raising=False)
    monkeypatch.setenv("MPVM_LOG_LEVEL", "info")
    config = diagnostics.DiagnosticsConfig.from_env()
    assert (config.debug_mode, config.level, config.debug_payloads) == (False, "INFO", False)


def test_enabling_debug_mode_announces_itself(debug_config):
    events = read_events(debug_config, "app.jsonl")
    announced = [event for event in events if event["event"] == "diagnostics.debug_mode.enabled"]
    assert announced and announced[0]["level"] == "WARNING"


def test_inbound_request_and_response_are_captured_with_redaction(debug_config):
    response = post_frontend_event(
        headers={
            "X-Trace-ID": "trace-debug", "Authorization": "Bearer raw-bearer",
            "Cookie": "mpvm_session=raw-cookie", "X-Api-Key": "raw-api-key",
        },
        json={"events": [{"event": "ui.debug", "level": "info", "fields": {"password": "plain-password", "ok": 1}}]},
    )
    assert response.status_code == 202  # the handler still received the body

    events = read_events(debug_config, "debug-payloads.jsonl")
    inbound = {event["event"]: event for event in events if event["event"].startswith("http.inbound.")}
    request, reply = inbound["http.inbound.request"], inbound["http.inbound.response"]
    assert request["trace_id"] == reply["trace_id"] == "trace-debug"
    assert request["method"] == "POST" and request["path"] == "/api/diagnostics/frontend"
    assert request["body"]["events"][0]["event"] == "ui.debug"
    assert request["body"]["events"][0]["fields"]["ok"] == 1
    assert reply["status"] == 202 and reply["headers"]["x-trace-id"] == "trace-debug"
    assert reply["duration_ms"] >= 0

    content = (debug_config.log_dir / "debug-payloads.jsonl").read_text(encoding="utf-8")
    for secret in ("plain-password", "raw-bearer", "raw-cookie", "raw-api-key"):
        assert secret not in content
    assert request["headers"]["authorization"] == diagnostics.REDACTED
    assert request["headers"]["cookie"] == diagnostics.REDACTED


def test_inbound_bodies_are_bounded_and_uploads_are_not_recorded(debug_config):
    post_frontend_event(json={"events": [{"event": "ui.big", "level": "info", "fields": {"blob": "z" * 6000}}]})
    from app import main

    with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "admin"}):
        TestClient(main.app).post(
            "/api/debug-mode-upload-fixture", files={"file": ("upload.csv", b"secret,csv\n1,2\n", "text/csv")}
        )
    events = read_events(debug_config, "debug-payloads.jsonl")
    requests_logged = [event for event in events if event["event"] == "http.inbound.request"]
    big = next(event for event in requests_logged if event["body_truncated"])
    assert len(json.dumps(big["body"])) <= 2048 + 256
    upload = next(event for event in requests_logged if event.get("body_skipped") == "non_text_content_type")
    assert upload["content_type"].startswith("multipart/form-data")
    assert "secret,csv" not in json.dumps(events)


def test_inbound_traffic_is_not_recorded_without_debug_mode(debug_config):
    diagnostics.configure_diagnostics(replace(debug_config, debug_mode=False, debug_payloads=False), force=True)
    response = post_frontend_event(json={"events": [{"event": "ui.quiet", "level": "info"}]})
    assert response.status_code == 202
    events = read_events(debug_config, "debug-payloads.jsonl")
    assert not [event for event in events if event["event"].startswith("http.inbound.")]


def test_outbound_mpvm_exchange_includes_redacted_headers_and_form_body(debug_config):
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"access_token": "raw-access", "items": [1, 2]}'
    response.headers["content-type"] = "application/json"
    response.headers["Set-Cookie"] = "sid=raw-set-cookie"
    response.raw = SimpleNamespace(retries=None)
    session = diagnostics.DiagnosticSession()
    session.headers["Authorization"] = "Bearer raw-session-token"
    with patch.object(requests.Session, "request", return_value=response):
        session.post(
            "https://vm.example/connect/token",
            data="grant_type=password&username=ops&password=raw-form-password",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    session.close()

    events = read_events(debug_config, "debug-payloads.jsonl")
    sent = next(event for event in events if event.get("direction") == "request")
    received = next(event for event in events if event.get("direction") == "response")
    assert sent["payload"]["grant_type"] == "password"
    assert sent["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert received["payload"]["items"] == [1, 2]
    assert received["status"] == 200 and received["attempts"] == 1
    content = (debug_config.log_dir / "debug-payloads.jsonl").read_text(encoding="utf-8")
    for secret in ("raw-form-password", "raw-session-token", "raw-access", "raw-set-cookie"):
        assert secret not in content


def test_sql_statement_and_parameters_are_logged_but_sensitive_statements_hide_values(debug_config):
    safe = describe_params("SELECT * FROM assets WHERE id = %s", ("asset-1",))
    assert safe == ["asset-1"]
    assert describe_params("UPDATE users SET password_hash = %s WHERE id = %s", ("hash", 1)) == diagnostics.REDACTED
    named = describe_params("SELECT 1 WHERE a = %(a)s", {"a": 1, "api_key": "k"})
    assert named == {"a": 1, "api_key": diagnostics.REDACTED}
    many = describe_params("SELECT 1", list(range(80)))
    assert many["omitted"] == 30 and len(many["items"]) == 50
    assert describe_params("SELECT 1", None) is None


def describe_params(statement, params):
    return diagnostics.describe_sql_parameters(statement, params)


@pytest.mark.parametrize(
    "body, content_type, expected",
    [
        (b'{"a": 1}', "application/json", {"a": 1}),
        (b"a=1&b=two", "application/x-www-form-urlencoded", {"a": "1", "b": "two"}),
        ("{broken", "application/json", "{broken"),
        ("   ", "application/json", None),
        (None, None, None),
        (b"plain text", "text/plain", "plain text"),
        (b'[1, 2]', None, [1, 2]),
    ],
)
def test_parse_http_body(body, content_type, expected):
    assert diagnostics.parse_http_body(body, content_type) == expected


def test_debug_files_use_the_short_payload_retention(debug_config):
    import os
    import time

    logs = debug_config.log_dir
    old = logs / "debug-payloads.jsonl.1"
    old.write_text("{}\n", encoding="utf-8")
    regular = logs / "app.jsonl.1"
    regular.write_text("{}\n", encoding="utf-8")
    stale = time.time() - 3 * 3600
    os.utime(old, (stale, stale))
    os.utime(regular, (stale, stale))
    diagnostics.configure_diagnostics(debug_config, force=True)
    assert not old.exists() and regular.exists()


def test_archive_records_debug_mode(debug_config):
    diagnostics.log_event("app", "debug.archive", trace_id="trace-archive")
    archive_path = diagnostics.build_diagnostic_archive(trace_id="trace-archive")
    with zipfile.ZipFile(archive_path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        readme = archive.read("README.txt").decode("utf-8")
    assert manifest["debug_mode"] is True
    assert manifest["configuration"]["debug_mode"] is True
    assert "MPVM_DEBUG_MODE" in readme
