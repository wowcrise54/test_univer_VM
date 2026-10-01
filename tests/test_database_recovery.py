from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest


def coordinator(probe, steps):
    # Import lazily so the baseline fails on the behaviour's missing component.
    from app.services.recovery import DatabaseRecovery

    return DatabaseRecovery(probe=probe, steps=steps)


def test_late_database_recovery_runs_initialization_once():
    available = False
    calls = []

    def probe():
        if not available:
            raise ConnectionError("private database endpoint")
        return True

    recovery = coordinator(probe, [("bootstrap", lambda: calls.append("bootstrap")),
                                   ("resume", lambda: calls.append("resume"))])
    assert recovery.check()["ready"] is False
    assert calls == []
    available = True
    assert recovery.check()["ready"] is True
    assert recovery.check()["ready"] is True
    assert calls == ["bootstrap", "resume"]


def test_recovery_retries_only_unfinished_steps_and_redacts_error():
    attempts = 0
    calls = []

    def resume():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectionError("password=must-not-leak")
        calls.append("resumed")

    recovery = coordinator(lambda: True, [("bootstrap", lambda: calls.append("bootstrap")), ("resume", resume)])
    failed = recovery.check()
    assert failed["ready"] is False
    assert "must-not-leak" not in str(failed)
    assert recovery.check()["ready"] is True
    assert calls == ["bootstrap", "resumed"]


def test_database_returns_after_outage_without_duplicate_jobs():
    available = True
    calls = []

    def probe():
        if not available:
            raise ConnectionError()
        return True

    recovery = coordinator(probe, [("scheduler", lambda: calls.append("started"))])
    assert recovery.check()["ready"] is True
    available = False
    assert recovery.check()["ready"] is False
    available = True
    assert recovery.check()["ready"] is True
    assert calls == ["started"]


def test_database_loss_during_final_probe_is_not_reported_connected():
    probes = 0

    def probe():
        nonlocal probes
        probes += 1
        if probes == 2:
            raise ConnectionError("private database endpoint")
        return True

    recovery = coordinator(probe, [("bootstrap", lambda: None)])
    result = recovery.check()
    assert result["ready"] is False
    assert result["database_ready"] is False


def test_monitor_recovers_without_readiness_requests():
    from app.services.recovery import DatabaseRecovery

    available, initialized = Event(), Event()

    def probe():
        if not available.is_set():
            raise ConnectionError()
        return True

    recovery = DatabaseRecovery(probe=probe, steps=[("bootstrap", initialized.set)], interval_seconds=0.01)
    try:
        recovery.start()
        available.set()
        assert initialized.wait(5)
    finally:
        recovery.stop()


def test_process_is_not_ready_before_startup_is_configured():
    from app.services.recovery import DatabaseRecovery

    recovery = DatabaseRecovery(probe=lambda: True)
    assert recovery.check()["reason"] == "startup_pending"


@pytest.mark.parametrize("stage", ["snapshot", "backfill", "postprocess_resume"])
def test_startup_stages_retry_database_errors_instead_of_checkpointing(stage, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    import psycopg

    from app import main
    from app.services.startup import database_startup_steps

    failure = psycopg.OperationalError("private connection failure")
    if stage == "snapshot":
        operation = Mock(side_effect=[failure, {}])
        monkeypatch.setattr(main.CONTAINER.services.vulnerabilities, "ensure_baseline", operation)
    elif stage == "backfill":
        operation = Mock(side_effect=[failure, {
            "total_cards": 0, "indexed_cards": 0,
            "software_inventory_total_cards": 0, "software_inventory_indexed_cards": 0,
        }])
        monkeypatch.setattr(main.db, "asset_card_search_index_coverage", operation)
        monkeypatch.setattr(main, "ASSET_SEARCH_BACKFILL_RUNNING", False)
    else:
        operation = Mock(side_effect=[failure, []])
        monkeypatch.setattr(main, "SESSION", SimpleNamespace(client=object(), access_token="test"))
        monkeypatch.setattr(main.db, "list_pending_asset_refresh_task_cleanups", operation)
        monkeypatch.setattr(main.db, "list_pending_docker_group_cleanups", lambda: [])
        monkeypatch.setattr(main.db, "list_resumable_scan_postprocess_runs", lambda: [])
    selected = [step for step in database_startup_steps(main) if step[0] == stage]
    recovery = coordinator(lambda: True, selected)
    assert recovery.check()["ready"] is False
    assert recovery.check()["ready"] is True
    assert operation.call_count == 2


def test_ready_waits_for_schema_and_completed_recovery():
    schema_current = False
    recovery = coordinator(lambda: schema_current, [("migration", lambda: None)])
    assert recovery.check()["ready"] is False
    schema_current = True
    assert recovery.check()["ready"] is True


def test_concurrent_readiness_checks_do_not_duplicate_initialization():
    started, finish = Event(), Event()
    calls = []

    def initialize():
        calls.append("initialized")
        started.set()
        assert finish.wait(5)

    recovery = coordinator(lambda: True, [("initialize", initialize)])
    with ThreadPoolExecutor(max_workers=2) as executor:
        running = executor.submit(recovery.check)
        assert started.wait(5)
        assert recovery.check()["ready"] is False
        finish.set()
        assert running.result()["ready"] is True
    assert calls == ["initialized"]


@pytest.mark.parametrize("path", ["/api/live", "/api/ready"])
def test_health_probes_are_public_and_sanitized(path):
    from fastapi.testclient import TestClient
    from unittest.mock import patch
    from app import main

    with patch.object(main.app_auth, "get_session_user", side_effect=AssertionError("must not require login")):
        response = TestClient(main.app).get(path)
    assert response.status_code in {200, 503}
    assert "database_url" not in response.text
    assert "database_error" not in response.text
    assert "api_url" not in response.text
