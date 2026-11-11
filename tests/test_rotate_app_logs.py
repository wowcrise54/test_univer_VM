"""scripts/rotate-app-logs.py — ротация, очистка и оценка размеров логов."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "rotate-app-logs.py"

DAY = 86400.0
HOUR = 3600.0


def run_script(log_dir: Path, *args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        # Стабильные пороги независимо от окружения хоста/контейнера.
        "MPVM_LOG_RETENTION_DAYS": "7",
        "MPVM_LOG_BACKUP_COUNT": "2",
        "MPVM_DEBUG_PAYLOAD_RETENTION_HOURS": "24",
        **(extra_env or {}),
    }
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--log-dir", str(log_dir), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def make_file(log_dir: Path, name: str, size: int, age_seconds: float) -> Path:
    path = log_dir / name
    path.write_bytes(b"x" * size)
    stamp = time.time() - age_seconds
    os.utime(path, (stamp, stamp))
    return path


def put_text(log_dir: Path, name: str, content: str, age_seconds: float) -> Path:
    path = log_dir / name
    path.write_text(content, encoding="utf-8")
    stamp = time.time() - age_seconds
    os.utime(path, (stamp, stamp))
    return path


def test_report_shows_per_component_sizes(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    make_file(log, "app.jsonl", 2048, HOUR)
    make_file(log, "database.jsonl", 1024, HOUR)
    make_file(log, "database.jsonl.1", 3072, 2 * DAY)
    result = run_script(log, "report")
    assert result.returncode == 0, result.stderr
    assert "app" in result.stdout and "database" in result.stdout
    assert "6.0 КБ" in result.stdout  # 2048 + 1024 + 3072
    assert "Всего в журнале" in result.stdout


def test_report_json_breakdown(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    make_file(log, "app.jsonl", 2048, HOUR)
    make_file(log, "database.jsonl", 1024, HOUR)
    make_file(log, "database.jsonl.1", 3072, 2 * DAY)
    result = run_script(log, "report", "--json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["total_bytes"] == 6144
    by_name = {component["name"]: component for component in data["components"]}
    assert by_name["app"]["total_bytes"] == 2048
    assert by_name["database"]["active_bytes"] == 1024
    assert by_name["database"]["rotated_bytes"] == 3072
    assert by_name["database"]["files"][0]["name"] in {"database.jsonl", "database.jsonl.1"}


def test_report_groups_unknown_files_as_other(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    make_file(log, "mystery.jsonl", 512, HOUR)
    result = run_script(log, "report", "--json")
    data = json.loads(result.stdout)
    by_name = {component["name"]: component for component in data["components"]}
    assert by_name["other"]["total_bytes"] == 512


def test_cleanup_removes_stale_and_excess_backups(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    stale = make_file(log, "app.jsonl", 100, 30 * DAY)  # старше retention 7 д
    fresh = make_file(log, "database.jsonl", 100, HOUR)
    make_file(log, "database.jsonl.1", 100, 2 * DAY)
    make_file(log, "database.jsonl.2", 100, 3 * DAY)
    excess = make_file(log, "database.jsonl.3", 100, 4 * DAY)  # больше 2 копий

    dry = run_script(log, "cleanup", "--dry-run")
    assert dry.returncode == 0, dry.stderr
    assert "Было бы удалено: 2 файла" in dry.stdout
    assert stale.exists() and excess.exists() and fresh.exists()

    real = run_script(log, "cleanup")
    assert real.returncode == 0, real.stderr
    assert not stale.exists()
    assert not excess.exists()
    assert fresh.exists()
    assert (log / "database.jsonl.1").exists()
    assert (log / "database.jsonl.2").exists()
    assert "Удалено: 2 файла" in real.stdout


def test_cleanup_payload_retention(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    keep = make_file(log, "debug-payloads.jsonl", 100, 2 * HOUR)
    drop = make_file(log, "debug-payloads.jsonl.1", 100, 30 * HOUR)
    result = run_script(log, "cleanup")
    assert result.returncode == 0, result.stderr
    assert keep.exists()
    assert not drop.exists()


def test_cleanup_nothing_to_do(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    make_file(log, "app.jsonl", 100, HOUR)
    result = run_script(log, "cleanup")
    assert result.returncode == 0
    assert "Очищать нечего" in result.stdout


def test_rotate_shifts_and_caps_backups(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    put_text(log, "app.jsonl", "A", 0)
    put_text(log, "app.jsonl.1", "B", DAY)
    put_text(log, "app.jsonl.2", "C", 2 * DAY)  # выпадает при лимите 2 копии

    result = run_script(log, "rotate")
    assert result.returncode == 0, result.stderr
    active = log / "app.jsonl"
    assert active.exists() and active.read_text(encoding="utf-8") == ""
    assert (log / "app.jsonl.1").read_text(encoding="utf-8") == "A"
    assert (log / "app.jsonl.2").read_text(encoding="utf-8") == "B"
    assert not (log / "app.jsonl.3").exists()
    assert "app:" in result.stdout


def test_rotate_dry_run_keeps_files(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    put_text(log, "app.jsonl", "A", 0)
    result = run_script(log, "rotate", "--dry-run")
    assert result.returncode == 0, result.stderr
    assert (log / "app.jsonl").read_text(encoding="utf-8") == "A"
    assert not (log / "app.jsonl.1").exists()
    assert "→" in result.stdout


def test_rotate_warns_when_app_running(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    put_text(log, "app.jsonl", "A", 0)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\necho test_univer_vm-mpvm-client-1\n", encoding="utf-8")
    docker.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--log-dir", str(log), "rotate"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "приложение запущено" in result.stdout
    assert "docker compose restart mpvm-client" in result.stdout
    # Ротация всё равно выполнена.
    assert (log / "app.jsonl.1").read_text(encoding="utf-8") == "A"


def test_maintain_frees_stale_files(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    make_file(log, "app.jsonl", 2048, 30 * DAY)
    make_file(log, "database.jsonl", 1024, HOUR)
    result = run_script(log, "maintain")
    assert result.returncode == 0, result.stderr
    assert not (log / "app.jsonl").exists()
    assert (log / "database.jsonl").exists()
    assert "Освобождено" in result.stdout


def test_missing_log_dir_is_graceful(tmp_path):
    missing = tmp_path / "nope"
    for command in ("report", "cleanup", "rotate", "maintain"):
        result = run_script(missing, command)
        assert result.returncode == 0, (command, result.stderr)
    assert "не найден" in run_script(missing, "report").stdout
