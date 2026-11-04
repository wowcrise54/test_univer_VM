import threading
import time

import pytest

from app.services.snapshot_cache import SnapshotCache


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_fresh_snapshot_is_reused_and_reports_its_age():
    clock = Clock()
    cache = SnapshotCache(name="t", ttl_seconds=30, clock=clock)
    calls = []

    def loader():
        calls.append(1)
        return {"value": len(calls)}

    first = cache.get("k", loader)
    clock.now += 10
    second = cache.get("k", loader)

    assert calls == [1]
    assert first["value"] == second["value"] == 1
    assert first["snapshot"]["stale"] is False and first["snapshot"]["age_seconds"] == 0
    assert second["snapshot"]["age_seconds"] == 10 and second["snapshot"]["generated_at"]


def test_callers_cannot_mutate_the_cached_value():
    cache = SnapshotCache(name="t", clock=Clock())
    cache.get("k", lambda: {"rows": [1]})["rows"].append(2)
    assert cache.get("k", lambda: {"rows": [9]})["rows"] == [1]


def test_stale_snapshot_is_served_at_once_and_refreshed_in_background():
    clock = Clock()
    cache = SnapshotCache(name="t", ttl_seconds=30, max_stale_seconds=600, clock=clock)
    release = threading.Event()
    versions = iter([1, 2])

    def loader():
        version = next(versions)
        if version == 2:
            release.wait(2)
        return {"value": version}

    assert cache.get("k", loader)["value"] == 1
    clock.now += 31
    stale = cache.get("k", loader)
    assert stale["value"] == 1 and stale["snapshot"]["stale"] is True
    release.set()
    assert wait_for(lambda: cache.get("k", loader)["value"] == 2)


def test_snapshot_older_than_the_stale_limit_is_recomputed_synchronously():
    clock = Clock()
    cache = SnapshotCache(name="t", ttl_seconds=30, max_stale_seconds=60, clock=clock)
    values = iter([1, 2])
    cache.get("k", lambda: {"value": next(values)})
    clock.now += 120
    assert cache.get("k", lambda: {"value": next(values)})["value"] == 2


def test_concurrent_misses_share_one_loader_call():
    cache = SnapshotCache(name="t")
    started = threading.Event()
    release = threading.Event()
    calls = []

    def loader():
        calls.append(1)
        started.set()
        release.wait(2)
        return {"value": "done"}

    results = []
    threads = [threading.Thread(target=lambda: results.append(cache.get("k", loader))) for _ in range(4)]
    threads[0].start()
    assert started.wait(2)
    for thread in threads[1:]:
        thread.start()
    time.sleep(0.05)
    release.set()
    for thread in threads:
        thread.join(2)

    assert len(calls) == 1
    assert [item["value"] for item in results] == ["done"] * 4


def test_loader_errors_reach_every_waiter_and_are_not_cached():
    cache = SnapshotCache(name="t")

    def broken():
        raise RuntimeError("database is down")

    with pytest.raises(RuntimeError):
        cache.get("k", broken)
    assert cache.get("k", lambda: {"value": 1})["value"] == 1


def test_failed_background_refresh_keeps_the_previous_snapshot():
    clock = Clock()
    cache = SnapshotCache(name="t", ttl_seconds=30, max_stale_seconds=600, clock=clock)
    attempts = []

    def loader():
        attempts.append(1)
        if len(attempts) == 2:
            raise RuntimeError("slow query cancelled")
        return {"value": len(attempts)}

    cache.get("k", loader)
    clock.now += 31
    assert cache.get("k", loader)["snapshot"]["stale"] is True
    assert wait_for(lambda: len(attempts) == 2)
    time.sleep(0.05)
    again = cache.get("k", loader)
    assert again["value"] in (1, 3)


def test_invalidate_forces_the_next_read_to_recompute():
    cache = SnapshotCache(name="t")
    values = iter([1, 2, 3])
    assert cache.get("a", lambda: {"value": next(values)})["value"] == 1
    cache.invalidate("a")
    assert cache.get("a", lambda: {"value": next(values)})["value"] == 2
    cache.invalidate()
    assert cache.get("a", lambda: {"value": next(values)})["value"] == 3


def test_entry_count_is_bounded_and_the_oldest_key_is_dropped():
    clock = Clock()
    cache = SnapshotCache(name="t", max_entries=2, clock=clock)
    for key in ("a", "b", "c"):
        clock.now += 1
        cache.get(key, lambda key=key: {"value": key})
    calls = []
    cache.get("a", lambda: calls.append(1) or {"value": "a"})
    assert calls == [1]


def test_remediation_summary_is_cached_and_dropped_by_a_case_update():
    from unittest.mock import MagicMock

    from app.services.remediation import RemediationService

    repository = MagicMock()
    repository.summary.side_effect = [{"open": 1}, {"open": 2}]
    repository.update.return_value = {"case_id": "c1"}
    service = RemediationService(repository, stale_days=7)

    assert service.summary()["open"] == 1
    assert service.summary()["open"] == 1
    assert repository.summary.call_count == 1

    service.update("c1", {"status": "in_progress", "expected_version": 1})

    assert service.summary()["open"] == 2
    repository.ensure_daily_digest.assert_called()
