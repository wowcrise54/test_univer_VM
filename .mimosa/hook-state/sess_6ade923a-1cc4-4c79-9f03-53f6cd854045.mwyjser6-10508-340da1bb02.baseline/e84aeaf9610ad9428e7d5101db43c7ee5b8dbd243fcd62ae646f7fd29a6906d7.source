"""scripts/collect-container-logs.sh against a stubbed ``docker`` binary."""
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect-container-logs.sh"
pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX shell is required")

FAKE_DOCKER = """#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_CALLS"
case "$1" in
    version) echo "Docker fake" ;;
    compose)
        case "$2" in
            ps) if [ "$3" = "-q" ]; then [ -n "$FAKE_NO_CONTAINER" ] || echo cid123; else echo "mpvm-client up"; fi ;;
            logs) echo "container log line" ;;
        esac ;;
    inspect)
        case "$3" in
            *json*) echo '{"Status":"running"}' ;;
            *Config.Image*) echo "mpvm:test" ;;
            *) printf '%s\\n' "MPVM_PASSWORD=super-secret-password" "MPVM_DEBUG_MODE=${FAKE_DEBUG_MODE:-true}" \\
                   "MPVM_LOG_LEVEL=DEBUG" "MPVM_LOG_DIR=${FAKE_LOG_DIR:-output/logs}" "PATH=/usr/bin" ;;
        esac ;;
    stats) echo "stats" ;;
    cp) cp -R "$FAKE_LOG_SRC/." "$3" ;;
esac
exit 0
"""


def event(timestamp, trace, name="app.event"):
    # Same compact spelling as the application's JsonLinesFormatter.
    record = {"timestamp": timestamp, "level": "DEBUG", "event": name, "trace_id": trace}
    return json.dumps(record, separators=(",", ":")) + "\n"


@pytest.fixture()
def sandbox(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8", newline="\n")
    docker.chmod(0o755)
    source = tmp_path / "container-logs"
    source.mkdir()
    (source / "app.jsonl").write_text(
        event("2026-09-01T10:00:00.000+00:00", "trace-a")
        + event("2026-09-01T10:05:00.000+00:00", "trace-b")
        + event("2026-09-01T12:00:00.000+00:00", "trace-a", "late"),
        encoding="utf-8",
    )
    (source / "debug-payloads.jsonl").write_text(
        event("2026-09-01T10:01:00.000+00:00", "trace-a", "http.inbound.request")
        + event("2026-09-01T10:02:00.000+00:00", "trace-b", "http.inbound.request"),
        encoding="utf-8",
    )
    compose = tmp_path / "compose"
    compose.mkdir()
    return SimpleNamespace(tmp_path=tmp_path, bin=bin_dir, source=source, compose=compose,
                            calls=tmp_path / "calls.txt", out=tmp_path / "out")




def run_script(box, *arguments, **env):
    environment = {
        **os.environ,
        "PATH": f"{box.bin}{os.pathsep}{os.environ['PATH']}",
        "FAKE_LOG_SRC": str(box.source),
        "FAKE_DOCKER_CALLS": str(box.calls),
        **env,
    }
    return subprocess.run(
        ["sh", str(SCRIPT), "--compose-dir", str(box.compose), "--output-dir", str(box.out), *arguments],
        capture_output=True, text=True, env=environment, timeout=60,
    )


def extract(result, destination):
    archive = Path(result.stdout.strip().splitlines()[-1])
    assert archive.is_file()
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination)  # noqa: S202 - archive built by the script under test
    return destination


def test_collects_debug_logs_and_logging_settings_without_secrets(sandbox):
    result = run_script(sandbox)
    assert result.returncode == 0, result.stderr
    root = extract(result, sandbox.tmp_path / "extracted")
    logs = root / "app-logs"
    assert (logs / "app.jsonl").exists() and (logs / "debug-payloads.jsonl").exists()
    config = (root / "logging-config.txt").read_text(encoding="utf-8")
    assert "MPVM_DEBUG_MODE=true" in config and "MPVM_LOG_LEVEL=DEBUG" in config
    assert "super-secret-password" not in config and "PATH=" not in config
    manifest = (root / "manifest.txt").read_text(encoding="utf-8")
    assert "debug_mode_setting=true" in manifest
    assert "debug_log_files_found=true" in manifest and "debug_logs_excluded=false" in manifest
    assert "debug-payloads.jsonl" in (root / "app-logs-inventory.txt").read_text(encoding="utf-8")
    assert (root / "log-directory.txt").read_text(encoding="utf-8").strip() == "/app/output/logs"
    everything = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in root.rglob("*") if p.is_file())
    assert "super-secret-password" not in everything


def test_trace_id_filters_every_log_file_including_debug_payloads(sandbox):
    result = run_script(sandbox, "--trace-id", "trace-a")
    assert result.returncode == 0, result.stderr
    root = extract(result, sandbox.tmp_path / "extracted")
    for name in ("app.jsonl", "debug-payloads.jsonl"):
        content = (root / "app-logs" / name).read_text(encoding="utf-8")
        assert "trace-a" in content and "trace-b" not in content
    assert "application_logs_trace_id=trace-a" in (root / "manifest.txt").read_text(encoding="utf-8")


def test_time_window_and_trace_filter_combine(sandbox):
    result = run_script(sandbox, "--from", "2026-09-01T10:00:00Z", "--to", "2026-09-01T11:00:00Z", "--trace-id", "trace-a")
    assert result.returncode == 0, result.stderr
    root = extract(result, sandbox.tmp_path / "extracted")
    app_log = (root / "app-logs" / "app.jsonl").read_text(encoding="utf-8")
    assert "trace-a" in app_log and "late" not in app_log and "trace-b" not in app_log


def test_exclude_debug_drops_payload_files_only(sandbox):
    result = run_script(sandbox, "--exclude-debug")
    assert result.returncode == 0, result.stderr
    root = extract(result, sandbox.tmp_path / "extracted")
    assert (root / "app-logs" / "app.jsonl").exists()
    assert not list((root / "app-logs").glob("debug-*"))
    manifest = (root / "manifest.txt").read_text(encoding="utf-8")
    assert "debug_logs_excluded=true" in manifest and "debug_log_files_found=true" in manifest


def test_custom_log_directory_from_container_environment_is_used(sandbox):
    result = run_script(sandbox, FAKE_LOG_DIR="/var/log/mpvm")
    assert result.returncode == 0, result.stderr
    assert "cp cid123:/var/log/mpvm/. " in sandbox.calls.read_text(encoding="utf-8")
    relative = run_script(sandbox, FAKE_LOG_DIR="data/logs")
    assert "cp cid123:/app/data/logs/. " in sandbox.calls.read_text(encoding="utf-8")
    assert relative.returncode == 0


def test_host_log_directory_is_the_fallback_when_no_container_exists(sandbox):
    host_logs = sandbox.compose / "output" / "logs"
    host_logs.mkdir(parents=True)
    (host_logs / "app.jsonl").write_text(event("2026-09-01T10:00:00.000+00:00", "trace-host"), encoding="utf-8")
    result = run_script(sandbox, FAKE_NO_CONTAINER="1")
    assert result.returncode == 0, result.stderr
    root = extract(result, sandbox.tmp_path / "extracted")
    assert "trace-host" in (root / "app-logs" / "app.jsonl").read_text(encoding="utf-8")
    assert (root / "container-not-found.txt").exists() and (root / "host-log-fallback.txt").exists()


@pytest.mark.parametrize("value", ["bad id", "x;rm -rf", "a" * 129, "../etc"])
def test_invalid_trace_id_is_rejected(sandbox, value):
    result = run_script(sandbox, "--trace-id", value)
    assert result.returncode == 2
    assert "trace-id" in result.stderr
