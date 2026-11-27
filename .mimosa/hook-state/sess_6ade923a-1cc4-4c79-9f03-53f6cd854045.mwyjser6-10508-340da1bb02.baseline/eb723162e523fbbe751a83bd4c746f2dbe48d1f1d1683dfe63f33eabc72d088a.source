from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app import db
from app.automations.repository import AutomationRepository
from app.automations.service import AutomationService
from app.core.config import Settings


def _definition(*step_ids: str) -> dict:
    return {
        "steps": [{"step_id": step_id, "type": "asset_query", "config": {"query": step_id}} for step_id in step_ids]
    }


def _published_runbook(repository: AutomationRepository, name: str = "Nightly inventory") -> dict:
    runbook = repository.create_runbook(name=name, description="Inventory", definition=_definition("query"))
    repository.publish_runbook(
        runbook["runbook_id"],
        definition=_definition("query"),
        definition_hash="hash-v1",
        destructive_approved=False,
    )
    return runbook


def test_runbook_drafts_publish_as_immutable_numbered_versions(test_db):
    repository = AutomationRepository()
    runbook = repository.create_runbook(name="Inventory", description="First", definition=_definition("one"))
    assert repository.get_runbook(runbook["runbook_id"])["draft"] == _definition("one")
    assert [item["name"] for item in repository.list_runbooks()] == ["Inventory"]

    published = repository.publish_runbook(
        runbook["runbook_id"],
        definition=_definition("one"),
        definition_hash="first-hash",
        destructive_approved=True,
    )
    assert published["published_version"] == 1
    assert published["allow_destructive"] is True
    assert published["approved_hash"] == "first-hash"
    assert repository.get_version(runbook["runbook_id"], 1)["definition"] == _definition("one")

    edited = repository.update_runbook(
        runbook["runbook_id"], name="Inventory v2", description="Updated", definition=_definition("two")
    )
    assert edited["draft"] == _definition("two")
    assert edited["allow_destructive"] is False
    assert edited["approved_hash"] is None
    assert repository.get_version(runbook["runbook_id"], 1)["definition"] == _definition("one")

    repository.publish_runbook(
        runbook["runbook_id"],
        definition=_definition("two"),
        definition_hash="second-hash",
        destructive_approved=False,
    )
    assert repository.get_version(runbook["runbook_id"])["version"] == 2
    assert repository.get_version(runbook["runbook_id"], 2)["definition"] == _definition("two")
    assert repository.get_version("missing") is None
    assert repository.get_version("missing", 1) is None
    assert repository.update_runbook("missing", name="x", description="", definition={}) is None


def test_run_steps_persist_progress_and_cancellation_for_recovery(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    definition = _definition("first", "second")
    run = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=definition,
        trigger_type="manual",
        dry_run=True,
        idempotency_key="manual:stable-key",
    )
    assert run["status"] == "queued"
    assert repository.get_run_by_idempotency_key("manual:stable-key")["run_id"] == run["run_id"]
    assert repository.get_run_by_idempotency_key(None) is None
    assert repository.get_run_by_idempotency_key("missing") is None
    assert repository.has_active_run(runbook["runbook_id"])

    run_with_steps = repository.get_run(run["run_id"])
    assert [step["step_id"] for step in run_with_steps["steps"]] == ["first", "second"]
    assert [step["input"] for step in run_with_steps["steps"]] == [definition["steps"][0], definition["steps"][1]]
    assert repository.get_run(run["run_id"], include_steps=False)["steps"] == []
    assert repository.get_run("missing") is None
    assert len(repository.list_runs(limit=10)) == 1
    assert [item["run_id"] for item in repository.resumable_runs()] == [run["run_id"]]

    repository.set_run_status(run["run_id"], "running", current_step=1)
    repository.set_step_status(
        run["run_id"],
        0,
        "completed",
        attempts=2,
        output={"count": 7},
        child_operation_id="child-op-7",
    )
    current = repository.get_run(run["run_id"])
    assert current["current_step"] == 1
    assert current["started_at"] is not None
    assert current["steps"][0]["attempts"] == 2
    assert current["steps"][0]["output"] == {"count": 7}
    assert current["steps"][0]["child_operation_id"] == "child-op-7"
    assert current["steps"][0]["finished_at"] is not None

    assert repository.request_cancel(run["run_id"]) is True
    cancelling = repository.get_run(run["run_id"])
    assert cancelling["cancel_requested"] is True
    assert cancelling["status"] == "cancelling"
    assert repository.resumable_runs()[0]["run_id"] == run["run_id"]
    repository.set_run_status(run["run_id"], "needs_attention", result={"steps": {}}, error="ambiguous")
    final = repository.get_run(run["run_id"])
    assert final["result"] == {"steps": {}}
    assert final["error"] == "ambiguous"
    assert final["finished_at"] is not None
    assert repository.request_cancel(run["run_id"]) is False
    assert repository.has_active_run(runbook["runbook_id"]) is False


def test_queued_cancel_and_schedule_due_advancement_are_durable(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository, "Scheduled inventory")
    scheduled = repository.create_schedule(
        runbook_id=runbook["runbook_id"],
        name="Nightly",
        cron_expression="0 2 * * *",
        timezone="Asia/Yekaterinburg",
        enabled=True,
        next_run_at="2026-01-01T02:00:00+00:00",
    )
    disabled = repository.create_schedule(
        runbook_id=runbook["runbook_id"],
        name="Paused",
        cron_expression="0 3 * * *",
        timezone="UTC",
        enabled=False,
        next_run_at="2025-01-01T00:00:00+00:00",
    )
    assert [item["name"] for item in repository.list_schedules()] == ["Nightly", "Paused"]
    assert [item["schedule_id"] for item in repository.due_schedules("2026-02-01T00:00:00+00:00")] == [
        scheduled["schedule_id"]
    ]
    assert (
        repository.update_schedule(
            scheduled["schedule_id"],
            name="Nightly v2",
            cron_expression="30 2 * * *",
            timezone="UTC",
            enabled=True,
            next_run_at="2026-01-02T02:30:00+00:00",
        )["name"]
        == "Nightly v2"
    )
    assert (
        repository.update_schedule(
            "missing", name="x", cron_expression="* * * * *", timezone="UTC", enabled=False, next_run_at="x"
        )
        is None
    )
    repository.advance_schedule(
        scheduled["schedule_id"],
        scheduled_at="2026-01-02T02:30:00+00:00",
        next_run_at="2026-01-03T02:30:00+00:00",
        status="queued",
    )
    due = repository.due_schedules("2026-01-02T23:00:00+00:00")
    assert due == []
    with db.connect() as conn:
        row = conn.execute(
            "SELECT last_scheduled_at, last_status, next_run_at FROM automation_schedules WHERE schedule_id=%s",
            (scheduled["schedule_id"],),
        ).fetchone()
    assert row["last_scheduled_at"] == "2026-01-02T02:30:00+00:00"
    assert row["last_status"] == "queued"
    assert row["next_run_at"] == "2026-01-03T02:30:00+00:00"

    queued = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=_definition("one"),
        trigger_type="schedule",
        dry_run=False,
        schedule_id=scheduled["schedule_id"],
    )
    assert repository.request_cancel(queued["run_id"]) is True
    cancelled = repository.get_run(queued["run_id"])
    assert cancelled["status"] == "cancelled"
    assert cancelled["cancel_requested"] is True
    assert cancelled["finished_at"] is None
    assert repository.request_cancel(queued["run_id"]) is False
    assert repository.delete_schedule("missing") is False
    assert repository.delete_schedule(disabled["schedule_id"]) is True


def test_notifications_audit_and_webhook_retry_state_round_trip(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository, "Notifications")
    run = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=_definition("one"),
        trigger_type="manual",
        dry_run=True,
    )
    repository.audit("run.test", runbook_id=runbook["runbook_id"], run_id=run["run_id"], details={"source": "test"})
    notification = repository.create_notification(
        level="warning",
        title="Retry required",
        message="The webhook will retry.",
        event_type="automation.test",
        runbook_id=runbook["runbook_id"],
        run_id=run["run_id"],
        details={"attempt": 1},
    )
    assert notification["details"] == {"attempt": 1}
    assert repository.list_notifications(unread_only=True)["unread"] == 1
    assert (
        repository.list_notifications(unread_only=True)["rows"][0]["notification_id"] == notification["notification_id"]
    )
    assert repository.mark_notification_read(notification["notification_id"]) is True
    assert repository.mark_notification_read("missing") is False
    assert repository.list_notifications(unread_only=True) == {"rows": [], "unread": 0}
    assert repository.list_notifications()["rows"][0]["is_read"] is True

    repository.queue_webhook(notification["notification_id"])
    delivery = repository.due_webhooks("9999-01-01T00:00:00+00:00")[0]
    assert delivery["details"] == {"attempt": 1}
    repository.finish_webhook_attempt(
        delivery["delivery_id"],
        attempt=1,
        status="pending",
        next_attempt_at="9999-01-02T00:00:00+00:00",
        response_status=503,
        error="HTTP 503",
    )
    assert repository.due_webhooks("9999-01-01T12:00:00+00:00") == []
    retry = repository.due_webhooks("9999-01-03T00:00:00+00:00")[0]
    assert retry["attempt"] == 1
    assert retry["response_status"] == 503
    assert retry["error"] == "HTTP 503"
    repository.finish_webhook_attempt(delivery["delivery_id"], attempt=2, status="delivered", response_status=204)
    assert repository.due_webhooks("9999-01-04T00:00:00+00:00") == []

    with db.connect() as conn:
        audit = conn.execute(
            "SELECT event_type, details_json FROM automation_audit_events WHERE run_id=%s", (run["run_id"],)
        ).fetchone()
        hook = conn.execute(
            "SELECT status, attempt, response_status FROM webhook_deliveries WHERE delivery_id=%s",
            (delivery["delivery_id"],),
        ).fetchone()
    assert audit["event_type"] == "run.test"
    assert audit["details_json"] == '{"source": "test"}'
    assert (hook["status"], hook["attempt"], hook["response_status"]) == ("delivered", 2, 204)


@pytest.mark.parametrize(
    "changed",
    [
        {"runbook_id": "other-runbook"},
        {"dry_run": True},
        {"trigger_type": "schedule"},
        {"schedule_id": "other-schedule"},
        {"scheduled_for": "2026-07-01T00:00:00+00:00"},
    ],
)
def test_automation_replay_key_cannot_silently_reuse_a_different_request(test_db, changed):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    runner = MagicMock()
    service = AutomationService(repository, runner, Settings(_env_file=None), MagicMock(), lambda: True)
    service.start_run(runbook["runbook_id"], idempotency_key="request-key")
    values = {"runbook_id": runbook["runbook_id"], "idempotency_key": "request-key", **changed}
    with pytest.raises(ValueError, match="different automation run request"):
        service.start_run(**values)
    assert len(repository.list_runs()) == 1
    assert runner.submit.call_count == 1


def test_run_deleted_between_loading_definition_and_starting_step_never_executes_remote_work(test_db, monkeypatch):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    run = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=_definition("query"),
        trigger_type="manual",
        dry_run=False,
    )
    get_run = repository.get_run

    def delete_before_step(run_id, *, include_steps=True):
        if not include_steps:
            with db.connect() as conn:
                conn.execute("DELETE FROM automation_runs WHERE run_id=%s", (run_id,))
        return get_run(run_id, include_steps=include_steps)

    monkeypatch.setattr(repository, "get_run", delete_before_step)
    handler = MagicMock()
    service = AutomationService(repository, MagicMock(), Settings(_env_file=None), handler, lambda: True)
    service.execute_run(run["run_id"])
    handler.assert_not_called()
    operation = db.get_operation(run["run_id"], sync_sources=False)
    assert operation["status"] == "cancelled"
    assert operation["finished_at"] is not None
    assert operation["progress_percent"] == 100
    assert get_run(run["run_id"]) is None
    assert repository.list_notifications()["rows"] == []


def test_resume_ignores_a_run_deleted_after_candidate_selection(test_db, monkeypatch):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    removed = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=_definition("query"),
        trigger_type="manual",
        dry_run=True,
    )
    get_run = repository.get_run

    def delete_selected_run(run_id):
        with db.connect() as conn:
            conn.execute("DELETE FROM automation_runs WHERE run_id=%s", (run_id,))
        return get_run(run_id)

    monkeypatch.setattr(repository, "get_run", delete_selected_run)
    assert repository.resumable_runs() == []
    assert get_run(removed["run_id"]) is None


def test_scheduler_queues_a_due_run_once_and_skips_the_next_occurrence_while_it_is_active(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    current = datetime(2026, 1, 1, 12, tzinfo=UTC)
    schedule = repository.create_schedule(
        runbook_id=runbook["runbook_id"],
        name="Hourly",
        cron_expression="0 * * * *",
        timezone="UTC",
        enabled=True,
        next_run_at=current.isoformat(),
    )
    runner = MagicMock()
    service = AutomationService(repository, runner, Settings(_env_file=None), MagicMock(), lambda: True)
    service.scheduler_tick(current)
    service.scheduler_tick(current)
    runs = repository.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "queued"
    assert runs[0]["trigger_type"] == "schedule"
    assert runs[0]["schedule_id"] == schedule["schedule_id"]
    assert runs[0]["scheduled_for"] == current.isoformat()
    assert runs[0]["idempotency_key"] == f"schedule:{schedule['schedule_id']}:{current.isoformat()}"
    runner.submit.assert_called_once_with("automation-run", service.execute_run, runs[0]["run_id"])
    saved_schedule = repository.list_schedules()[0]
    assert saved_schedule["next_run_at"] == (current + timedelta(hours=1)).isoformat()
    assert saved_schedule["last_status"] == "queued"
    service.scheduler_tick(current + timedelta(hours=1))
    assert sorted(run["status"] for run in repository.list_runs()) == ["queued", "skipped"]
    assert repository.list_schedules()[0]["last_status"] == "skipped:overlap"
    assert runner.submit.call_count == 1


def test_identical_automation_replay_after_restart_keeps_original_published_version(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    runner = MagicMock()
    service = AutomationService(repository, runner, Settings(_env_file=None), MagicMock(), lambda: True)
    first = service.start_run(runbook["runbook_id"], idempotency_key="restart-key", dry_run=True)
    repository.publish_runbook(
        runbook["runbook_id"], definition=_definition("new-step"), definition_hash="hash-v2", destructive_approved=False
    )
    restarted = AutomationService(AutomationRepository(), runner, Settings(_env_file=None), MagicMock(), lambda: True)
    replay = restarted.start_run(runbook["runbook_id"], idempotency_key="restart-key", dry_run=True)
    assert replay["run_id"] == first["run_id"]
    assert replay["version"] == 1
    assert replay["definition"] == _definition("query")
    assert replay["idempotent_replay"] is True
    assert len(repository.list_runs()) == 1
    assert runner.submit.call_count == 1


def test_deleting_a_runbook_cascades_versions_schedules_runs_steps_and_audit(test_db):
    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    schedule = repository.create_schedule(
        runbook_id=runbook["runbook_id"],
        name="Nightly",
        cron_expression="0 2 * * *",
        timezone="UTC",
        enabled=True,
        next_run_at=db.now_utc(),
    )
    run = repository.create_run(
        runbook_id=runbook["runbook_id"],
        version=1,
        definition=_definition("query"),
        trigger_type="schedule",
        dry_run=True,
        schedule_id=schedule["schedule_id"],
    )
    repository.audit("run.created", runbook_id=runbook["runbook_id"], run_id=run["run_id"])
    assert repository.delete_runbook(runbook["runbook_id"]) is True
    assert repository.delete_runbook(runbook["runbook_id"]) is False
    assert repository.get_runbook(runbook["runbook_id"]) is None
    assert repository.get_run(run["run_id"]) is None
    assert repository.get_version(runbook["runbook_id"]) is None
    assert repository.list_schedules() == []
    assert repository.list_runs() == []
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS count FROM automation_audit_events").fetchone()["count"] == 0
    assert (
        repository.publish_runbook("missing", definition={}, definition_hash="none", destructive_approved=False) is None
    )


def test_http_automation_replay_keeps_202_and_reports_changed_request_as_409(test_db, monkeypatch):
    from fastapi.testclient import TestClient

    from app import auth, main

    repository = AutomationRepository()
    runbook = _published_runbook(repository)
    runner = MagicMock()
    service = AutomationService(repository, runner, Settings(_env_file=None), MagicMock(), lambda: True)
    monkeypatch.setattr(main, "get_automation_service", lambda: service)
    monkeypatch.setattr(auth, "get_session_user", lambda _token: {"id": 1, "username": "operator", "role": "admin"})
    client = TestClient(main.app)
    url = f"/api/automations/runbooks/{runbook['runbook_id']}/run"
    headers = {"X-Idempotency-Key": "http-click"}
    first = client.post(url, json={"dry_run": True}, headers=headers)
    replay = client.post(url, json={"dry_run": True}, headers=headers)
    changed = client.post(url, json={"dry_run": False}, headers=headers)
    assert first.status_code == replay.status_code == 202
    assert replay.json()["run_id"] == first.json()["run_id"]
    assert changed.status_code == 409
    assert "different automation run request" in changed.json()["detail"]["message"]
    assert changed.json()["detail"]["code"] == "HTTP_409"
    assert len(repository.list_runs()) == 1
    assert runner.submit.call_count == 1
