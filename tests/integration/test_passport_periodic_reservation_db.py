from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from app import db
from app.repositories import passport_refresh

pytestmark = pytest.mark.integration

NOW = datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
REQUEST = {"pdql": "safe", "save_to_db": True}


def test_first_periodic_reservation_is_queued_and_second_is_skipped(test_db):
    first = passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600)
    second = passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600)
    assert first["status"] == "queued"
    assert first["request"]["trigger"] == "periodic"
    assert second is None


def test_periodic_reservation_uses_finish_time_and_ignores_manual_history(test_db):
    db.register_operation("manual", kind=passport_refresh.KIND, source_id="manual", status="completed",
                          finished_at=(NOW + timedelta(seconds=3599)).isoformat())
    previous = db.register_operation("periodic-old", kind=passport_refresh.KIND, source_id="periodic-old",
                                     status="completed", request={"trigger": "periodic"},
                                     created_at=NOW.isoformat(), finished_at=NOW.isoformat())
    assert previous["operation_id"] == "periodic-old"
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW + timedelta(seconds=3599), interval_seconds=3600) is None
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW + timedelta(seconds=3600), interval_seconds=3600) is not None


def test_interrupted_periodic_refresh_is_immediately_retryable(test_db):
    db.register_operation("interrupted", kind=passport_refresh.KIND, source_id="interrupted",
                          status="interrupted", request={"trigger": "periodic"},
                          created_at=NOW.isoformat(), finished_at=NOW.isoformat())
    reserved = passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600)
    assert reserved is not None
    assert reserved["request"]["trigger"] == "periodic"


def test_active_detail_job_blocks_periodic_reservation(test_db):
    db.init_db()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO vulnerability_passport_detail_jobs "
            "(job_id, status, created_at, updated_at) VALUES (%s, %s, %s, %s)",
            ("detail", "running", NOW.isoformat(), NOW.isoformat()),
        )
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600) is None


def test_concurrent_ticks_reserve_exactly_one_operation(test_db):
    barrier = Barrier(2)

    def reserve():
        barrier.wait(timeout=5)
        return passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: reserve(), range(2)))
    assert sum(result is not None for result in results) == 1


def test_busy_reservation_lock_returns_without_waiting(test_db):
    with db.connect() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("mpvm.passport-periodic-reservation",))
        assert passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600) is None


@pytest.mark.parametrize("status", ["failed", "cancelled", "completed_with_errors"])
def test_unsuccessful_attempts_observe_the_same_backoff(test_db, status):
    db.register_operation(
        "previous", kind=passport_refresh.KIND, source_id="previous", status=status,
        request={"trigger": "periodic"}, created_at=NOW.isoformat(), finished_at=NOW.isoformat(),
    )
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600) is None
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW + timedelta(hours=1), interval_seconds=3600)


def test_manual_catalog_conflict_rolls_back_reservation(test_db, monkeypatch):
    import psycopg

    def conflicting(*args, **kwargs):
        raise psycopg.errors.UniqueViolation("another catalog won")

    monkeypatch.setattr(db, "register_operation", conflicting)
    assert passport_refresh.reserve_periodic(REQUEST, now=NOW, interval_seconds=3600) is None
    assert passport_refresh.latest() is None
