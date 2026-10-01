"""Diagnostic output remains useful and safe under malformed input and transport failures."""
import json
import logging
import os
import queue
import runpy
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

from app import diagnostics
from app.services.operation_diagnostics import build_operation_diagnostic_archive


@pytest.fixture()
def logging_config(tmp_path):
    config = diagnostics.DiagnosticsConfig(
        level="DEBUG", log_dir=tmp_path / "logs", max_bytes=8192,
        backup_count=2, retention_days=2, debug_payloads=True,
        payload_max_bytes=256, payload_retention_hours=1,
    )
    diagnostics.configure_diagnostics(config, force=True)
    yield config
    diagnostics.shutdown_diagnostics()


@pytest.mark.parametrize("raw, expected", [(None, 7), ("garbage", 7), ("-5", 1), ("99", 20), ("12", 12)])
def test_integer_configuration_defaults_and_bounds(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("MPVM_TEST_BOUND", raising=False)
    else:
        monkeypatch.setenv("MPVM_TEST_BOUND", raw)
    assert diagnostics._env_int("MPVM_TEST_BOUND", 7, 1, 20) == expected


@pytest.mark.parametrize("raw, expected", [(None, True), (" TRUE ", True), ("yes", True), ("off", False), ("0", False)])
def test_boolean_configuration(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("MPVM_TEST_BOOL", raising=False)
    else:
        monkeypatch.setenv("MPVM_TEST_BOOL", raw)
    assert diagnostics._env_bool("MPVM_TEST_BOOL", True) is expected


@pytest.mark.parametrize("value", [None, "", "../escape", "x" * 129, "line\nbreak"])
def test_correlation_id_rejects_unsafe_values_and_can_generate_fallback(value):
    assert diagnostics.normalize_correlation_id(value, fallback=False) is None
    generated = diagnostics.normalize_correlation_id(value)
    assert diagnostics.ID_PATTERN.fullmatch(generated)


def test_nested_context_restores_after_exception():
    diagnostics.set_diagnostic_context(trace_id=None, job_id=None, stage=None)
    with diagnostics.diagnostic_context(trace_id="outer", unknown="ignored", stage="started"):
        with pytest.raises(RuntimeError), diagnostics.diagnostic_context(trace_id="inner", job_id="job"):
            assert diagnostics.current_trace_id() == "inner"
            assert diagnostics.current_context()["job_id"] == "job"
            raise RuntimeError("fixture")
        assert diagnostics.current_context() == {"trace_id": "outer", "stage": "started"}
        diagnostics.set_diagnostic_context(stage=None, unsupported="ignored")
        assert "stage" not in diagnostics.current_context()
    assert diagnostics.current_context() == {}
    assert diagnostics.normalize_correlation_id(" valid-id ") == "valid-id"


def test_redaction_handles_primitives_depth_binary_and_env_secrets(monkeypatch):
    monkeypatch.setenv("MPVM_PASSWORD", "fixture-private")
    assert diagnostics.redact({"visible": [True, 3, 1.5, None, b"123"]}) == {
        "visible": [True, 3, 1.5, None, "<bytes:3>"],
    }
    assert diagnostics.redact(Path("fixture-private")) == "[REDACTED]"
    assert diagnostics.redact({}, depth=11) == "[MAX_DEPTH]"
    assert diagnostics.sanitize_text("abcdef", max_length=3) == "abc...[TRUNCATED 3 chars]"
    assert diagnostics.redact({"client-secret": "fixture-private", 3: "safe"}) == {
        "client-secret": "[REDACTED]", "3": "safe",
    }


def test_url_redaction_handles_ports_opaque_paths_and_invalid_urls():
    value = diagnostics.sanitize_url("https://user:pass@example.test:8443/api/" + "a" * 40 + "?token=private&empty=#fragment")
    assert value.startswith("https://example.test:8443/api/{id}?")
    assert "private" not in value and "fragment" not in value and "empty=" in value
    invalid = diagnostics.sanitize_url("https://example.test:invalid/path?token=private")
    assert "private" not in invalid


def test_expired_logs_and_payloads_use_separate_retention_windows(logging_config):
    logs = logging_config.log_dir
    old = logs / "app.jsonl.1"
    expired_payload = logs / "debug-payloads.jsonl.1"
    fresh = logs / "database.jsonl"
    for path in (old, expired_payload, fresh):
        path.write_text("{}", encoding="utf-8")
    now = time.time()
    os.utime(old, (now - 3 * 86400, now - 3 * 86400))
    os.utime(expired_payload, (now - 7200, now - 7200))
    diagnostics._cleanup_old_logs(logging_config)
    assert not old.exists() and not expired_payload.exists() and fresh.exists()
    with patch.object(Path, "stat", side_effect=OSError("fixture")):
        diagnostics._cleanup_old_logs(logging_config)
    assert fresh.exists()


def make_response(status=200, content=b'{"safe":true}', content_type="application/json"):
    response = requests.Response()
    response.status_code = status
    response._content = content
    response.headers["content-type"] = content_type
    response.raw = SimpleNamespace(retries=SimpleNamespace(history=(object(), object())))
    return response


@pytest.mark.parametrize("status, payload, stream", [(200, b'{"safe":true}', False), (429, b'Bearer fixture-token', False), (200, b'not-json', False), (200, b'content', True)])
def test_http_telemetry_counts_status_retries_and_redacts_response(logging_config, status, payload, stream):
    response = make_response(status, payload)
    with patch.object(requests.Session, "request", return_value=response) as transport:
        session = diagnostics.DiagnosticSession()
        assert session.request("get", "https://example.test/api?token=fixture-token", stream=stream) is response
    transport.assert_called_once()
    assert session.telemetry() == {"requests": 1, "retries": 2, "errors": int(status >= 400), "rate_limited": int(status == 429)}
    diagnostics.shutdown_diagnostics()
    content = (logging_config.log_dir / "mpvm-http.jsonl").read_text(encoding="utf-8")
    assert "fixture-token" not in content
    assert ("mpvm.request.failed" if status >= 400 else "mpvm.request.completed") in content


def test_http_transport_exception_remains_visible_and_counted(logging_config):
    with patch.object(requests.Session, "request", side_effect=requests.Timeout("fixture timeout")):
        session = diagnostics.DiagnosticSession()
        with pytest.raises(requests.Timeout, match="fixture timeout"):
            session.get("https://example.test/api")
    assert session.telemetry() == {"requests": 1, "retries": 0, "errors": 1, "rate_limited": 0}
    diagnostics.shutdown_diagnostics()
    assert "mpvm.request.failed" in (logging_config.log_dir / "mpvm-http.jsonl").read_text(encoding="utf-8")


def test_response_size_and_sql_descriptions_do_not_require_readable_bodies():
    assert diagnostics._response_size(make_response(content=b"123")) == 3
    response = make_response()
    response.headers["content-length"] = "99"
    assert diagnostics._response_size(response) == 99
    unreadable = MagicMock()
    unreadable.headers = {"content-length": "invalid"}
    type(unreadable).content = property(lambda _self: (_ for _ in ()).throw(RuntimeError("fixture")))
    assert diagnostics._response_size(unreadable) is None
    assert diagnostics.describe_sql(' SELECT  id FROM "users" ') == diagnostics.describe_sql('SELECT id FROM "users"')
    assert diagnostics.describe_sql("VACUUM")["operation"] == "SQL unknown"


def test_bundle_skips_corrupt_lines_and_filters_job_without_trace(logging_config):
    logs = logging_config.log_dir
    (logs / "custom.jsonl").write_text('broken\n' + json.dumps({"job_id": "job", "safe": True}) + '\n' + json.dumps({"job_id": "other"}), encoding="utf-8")
    (logs / "directory.jsonl").mkdir()
    archive = diagnostics.build_diagnostic_archive(job_id="job")
    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["event_count"] == 1
        assert manifest["event_counts"] == {"unknown": 1}
    with pytest.raises(ValueError, match="required"):
        diagnostics.build_diagnostic_archive()


@pytest.mark.parametrize("trace, source, expected_trace, expected_job", [
    ("trace", "source", "trace", None), (None, "job", None, "job"),
    ("../unsafe", "../unsafe", None, None), (None, None, None, None),
])
def test_operation_bundle_sanitizes_identifiers_and_ignores_arbitrary_payloads(trace, source, expected_trace, expected_job):
    operation = {"operation_id": "operation", "trace_id": trace, "source_id": source,
                 "events": [{"id": "event", "message": "Bearer fixture-secret", "unsafe": "omit"}, None, "malformed"],
                 "request": {"password": "omit"}, "result": {"token": "omit"}}
    with patch("app.services.operation_diagnostics.build_diagnostic_archive", return_value=Path("bundle.zip")) as archive:
        assert build_operation_diagnostic_archive(operation) == Path("bundle.zip")
    exported = archive.call_args.kwargs
    assert exported["trace_id"] == expected_trace and exported["job_id"] == expected_job
    assert "request" not in exported["operation_snapshot"] and "result" not in exported["operation_snapshot"]
    assert exported["operation_events"] == [{"id": "event", "message": "Bearer [REDACTED]"}]


def test_disabled_debug_payload_does_not_create_a_payload_log(logging_config):
    diagnostics.configure_diagnostics(replace(logging_config, debug_payloads=False), force=True)
    diagnostics.capture_debug_payload(direction="request", payload={"safe": True})
    diagnostics.shutdown_diagnostics()
    assert not (logging_config.log_dir / "debug-payloads.jsonl").exists()


def test_configuration_is_reused_and_can_be_replaced(logging_config):
    assert diagnostics.configure_diagnostics() is logging_config
    replacement = replace(logging_config, retention_days=5)
    assert diagnostics.configure_diagnostics(replacement, force=True) is replacement


def test_queue_timeout_and_absent_logger_do_not_block(monkeypatch):
    diagnostics.shutdown_diagnostics()
    monkeypatch.setattr(diagnostics, "_QUEUE", queue.Queue())
    diagnostics._QUEUE.put(logging.makeLogRecord({"msg": "fixture"}))
    diagnostics.flush_diagnostics(timeout=0)
    monkeypatch.setattr(diagnostics, "_QUEUE", None)
    diagnostics.flush_diagnostics()


def test_cli_builds_the_requested_bundle(logging_config, monkeypatch, capsys):
    output = logging_config.log_dir.parent / "cli.zip"
    monkeypatch.setattr("sys.argv", ["diagnostics", "bundle", "--job-id", "job", "--output", str(output)])
    assert diagnostics._main() == 0
    assert output.exists() and str(output) in capsys.readouterr().out


def test_formatter_ignores_non_mapping_fields():
    record = logging.makeLogRecord({"msg": "safe message", "fields": ["untrusted"], "levelno": logging.INFO})
    payload = json.loads(diagnostics.JsonLinesFormatter().format(record))
    assert payload["event"] == "safe message"
    assert "untrusted" not in payload


def test_log_exception_initializes_missing_configuration(monkeypatch):
    diagnostics.shutdown_diagnostics()
    configure = MagicMock()
    logger = MagicMock()
    monkeypatch.setattr(diagnostics, "configure_diagnostics", configure)
    monkeypatch.setattr(diagnostics, "_LOGGER", logger)
    try:
        raise ValueError("fixture")
    except ValueError:
        diagnostics.log_exception("app", "fixture.failed", empty=None, safe="value")
    configure.assert_called_once_with()
    logger.error.assert_called_once()
    assert logger.error.call_args.kwargs["exc_info"] is True
    assert logger.error.call_args.kwargs["extra"]["fields"] == {"safe": "value"}


def test_http_plain_text_response_is_captured_without_attempting_json(logging_config):
    response = requests.Response()
    response.status_code = 200
    response._content = b"fixture plain text"
    response.headers["content-type"] = "text/plain"
    response.raw = SimpleNamespace(retries=None)
    session = diagnostics.DiagnosticSession()
    with patch.object(requests.Session, "request", return_value=response), patch.object(response, "json") as parse, patch.object(diagnostics, "capture_debug_payload") as capture:
        assert session.get("https://vm.example/plain") is response
    parse.assert_not_called()
    assert capture.call_args.kwargs["payload"] == "fixture plain text"
    session.close()


def test_archive_deduplicates_mirrored_errors_and_skips_unreadable_logs(logging_config, monkeypatch):
    event = {"trace_id": "trace", "event": "fixture.failed"}
    logs = logging_config.log_dir
    for name in ("custom.jsonl", "errors.jsonl.1", "unreadable.jsonl"):
        (logs / name).write_text(json.dumps(event) + "\n", encoding="utf-8")
    original_open = Path.open

    def open_log(path, *args, **kwargs):
        if path.name == "unreadable.jsonl":
            raise PermissionError("fixture permissions")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_log)
    archive = diagnostics.build_diagnostic_archive(trace_id="trace")
    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["event_count"] == 1
        assert manifest["event_counts"] == {"fixture.failed": 1}

@pytest.mark.parametrize("arguments", [[], ["unknown-command"]])
def test_cli_rejects_missing_or_unsupported_command(monkeypatch, arguments):
    monkeypatch.setattr("sys.argv", ["diagnostics", *arguments])
    with pytest.raises(SystemExit) as result:
        diagnostics._main()
    assert result.value.code == 2


def test_module_cli_entry_builds_archive_and_shuts_down_its_own_listener(tmp_path, monkeypatch, capsys):
    diagnostics.shutdown_diagnostics()
    output = tmp_path / "module-cli.zip"
    monkeypatch.setenv("MPVM_LOG_DIR", str(tmp_path / "module-logs"))
    monkeypatch.setattr("sys.argv", ["diagnostics", "bundle", "--trace-id", "cli-trace", "--output", str(output)])
    registered = []
    monkeypatch.setattr("atexit.register", lambda callback: registered.append(callback))
    try:
        with pytest.warns(RuntimeWarning, match="app.diagnostics.*found in sys.modules"), pytest.raises(SystemExit) as result:
            runpy.run_module("app.diagnostics", run_name="__main__")
        assert result.value.code == 0
        assert output.exists() and str(output) in capsys.readouterr().out
        with zipfile.ZipFile(output) as bundle:
            assert json.loads(bundle.read("manifest.json"))["trace_id"] == "cli-trace"
    finally:
        for shutdown in registered:
            shutdown()