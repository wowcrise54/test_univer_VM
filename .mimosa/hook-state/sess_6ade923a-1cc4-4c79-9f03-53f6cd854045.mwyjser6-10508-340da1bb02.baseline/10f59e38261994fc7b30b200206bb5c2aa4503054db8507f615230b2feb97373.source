import psycopg
import pytest

from app import db
from app.repositories import passport_refresh


def test_refresh_lookup_rejects_other_operation_kinds_and_unknown_ids(test_db):
    assert passport_refresh.latest() is None
    assert passport_refresh.get("missing") is None
    db.register_operation("unrelated", kind="asset_card_build", source_id="unrelated", status="running")
    assert passport_refresh.get("unrelated") is None
    assert passport_refresh.request_cancel("unrelated") is None
    assert passport_refresh.request_cancel("missing") is None
    with pytest.raises(ValueError, match="missing"):
        passport_refresh.update("missing", status="running", stage="save", percent=20, message="Saving")


@pytest.mark.parametrize("status", ["completed", "completed_with_errors", "failed", "cancelled", "interrupted"])
def test_terminal_refresh_is_not_overwritten_by_late_progress_or_cancellation(test_db, status):
    queued = passport_refresh.create("refresh", {"batch_size": 20})
    assert queued["request"] == {"batch_size": 20}
    running = passport_refresh.update("refresh", status="running", stage="fetch", percent=60, message="Fetching")
    assert running["started_at"] is not None
    if status == "interrupted":
        assert passport_refresh.interrupt_active() == 1
    else:
        passport_refresh.update(
            "refresh", status=status, stage=status, percent=100, message="Finished", result={"total": 4}
        )
    terminal = passport_refresh.get("refresh")
    assert terminal["finished_at"] is not None
    late = passport_refresh.update("refresh", status="running", stage="save", percent=70, message="Late")
    assert late == terminal
    assert passport_refresh.request_cancel("refresh") == terminal


@pytest.mark.parametrize("status", ["queued", "running", "cancelling"])
def test_latest_prioritizes_an_active_refresh_over_a_newer_completed_refresh(test_db, status):
    passport_refresh.create("active", {})
    if status == "running":
        passport_refresh.update("active", status=status, stage="fetch", percent=50, message="Fetching")
    elif status == "cancelling":
        assert passport_refresh.request_cancel("active")["status"] == "cancelling"
    db.register_operation(
        "finished", kind=passport_refresh.KIND, source_id="finished", status="completed", finished_at=db.now_utc()
    )
    with db.connect() as conn:
        conn.execute("UPDATE operations SET created_at='2025-01-01T00:00:00+00:00' WHERE operation_id='active'")
        conn.execute("UPDATE operations SET created_at='2026-01-01T00:00:00+00:00' WHERE operation_id='finished'")
    assert passport_refresh.latest()["operation_id"] == "active"
    assert passport_refresh.interrupt_active() == 1
    assert passport_refresh.latest()["operation_id"] == "finished"
    assert passport_refresh.interrupt_active() == 0


@pytest.mark.parametrize("status", passport_refresh.ACTIVE)
def test_restart_interrupts_only_active_catalog_refreshes(test_db, status):
    passport_refresh.create("active", {})
    if status != "queued":
        passport_refresh.update("active", status=status, stage=status, percent=30, message="In progress")
    db.register_operation(
        "finished", kind=passport_refresh.KIND, source_id="finished", status="completed", finished_at=db.now_utc()
    )
    terminal = passport_refresh.get("finished")
    db.register_operation("other", kind="asset_card_build", source_id="other", status="running")
    assert passport_refresh.interrupt_active() == 1
    assert db.get_operation("other", sync_sources=False)["status"] == "running"
    operation = passport_refresh.get("active")
    assert operation["status"] == "interrupted"
    assert operation["finished_at"] is not None
    assert passport_refresh.get("finished") == terminal


def test_only_one_active_catalog_refresh_can_be_created(test_db):
    first = passport_refresh.create("active", {"batch_size": 20})
    with pytest.raises(psycopg.errors.UniqueViolation):
        passport_refresh.create("duplicate", {"batch_size": 50})
    assert passport_refresh.get("duplicate") is None
    assert passport_refresh.get("active") == first
    assert passport_refresh.latest()["operation_id"] == "active"
