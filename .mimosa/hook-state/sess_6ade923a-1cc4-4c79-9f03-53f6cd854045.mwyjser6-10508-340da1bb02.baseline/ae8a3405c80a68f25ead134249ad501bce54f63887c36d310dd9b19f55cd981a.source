from unittest.mock import patch

import psycopg
from fastapi.testclient import TestClient

from app import db, main
from app.core.container import AppContainer
from app.repositories.readiness import ReadinessRepository


def test_readiness_requires_revision_table(test_db):
    with db.connect() as conn:
        conn.execute("ALTER TABLE alembic_version RENAME TO readiness_saved_version")
    try:
        assert ReadinessRepository().probe() is False
    finally:
        with db.connect() as conn:
            conn.execute("ALTER TABLE readiness_saved_version RENAME TO alembic_version")


def test_readiness_detects_an_unapplied_revision(test_db):
    repository = ReadinessRepository()
    assert repository.probe() is True
    with db.connect() as conn:
        original = conn.execute("SELECT version_num FROM alembic_version").fetchone()["version_num"]
    try:
        with db.connect() as conn:
            conn.execute("UPDATE alembic_version SET version_num=%s", ("older-schema",))
        assert repository.probe() is False
    finally:
        with db.connect() as conn:
            conn.execute("UPDATE alembic_version SET version_num=%s", (original,))


def test_startup_recovers_bootstrap_and_scheduler_after_database_returns(test_db, monkeypatch):
    settings = main.SETTINGS.model_copy(update={
        "bootstrap_admin_username": "recovery-admin",
        "bootstrap_admin_password": "recovery-test-password",
    })
    container = AppContainer(settings)
    monkeypatch.setattr(main, "SETTINGS", settings)
    monkeypatch.setattr(main, "CONTAINER", container)
    monkeypatch.setattr(main, "SESSION", container.session)
    monkeypatch.setattr(main, "AUTOMATION_SERVICE", None)
    monkeypatch.setattr(main, "DATABASE_STARTUP_ERROR", None)
    monkeypatch.setattr(main, "configure_session_from_env", lambda: None)
    monkeypatch.setattr(main.app.state, "container", container)
    try:
        with patch.object(db, "connect", side_effect=psycopg.OperationalError("private connection failure")):
            main.startup()
            response = TestClient(main.app).get("/api/ready")
            assert response.status_code == 503
            assert "private connection failure" not in response.text
            assert TestClient(main.app).get("/api/live").json() == {"ok": True}
            legacy = TestClient(main.app).get("/api/health")
            assert legacy.status_code == 200
            assert legacy.json()["ok"] is True
            assert legacy.json()["database_ready"] is False

        response = TestClient(main.app).get("/api/ready")
        assert response.status_code == 200
        assert response.json()["mpvm"] == "degraded"
        assert main.app_auth.authenticate("recovery-admin", "recovery-test-password") is not None
        scheduler = main.get_automation_service()._scheduler_future
        assert scheduler is not None and not scheduler.done()
        assert TestClient(main.app).get("/api/ready").status_code == 200
        assert main.get_automation_service()._scheduler_future is scheduler
        with db.connect() as conn:
            assert conn.execute("SELECT COUNT(*) n FROM app_users WHERE username='recovery-admin'").fetchone()["n"] == 1
    finally:
        main.shutdown()
