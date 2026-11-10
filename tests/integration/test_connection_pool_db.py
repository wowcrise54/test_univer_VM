"""Real PostgreSQL checks for the shared psycopg connection pool behind ``db.connect()``."""

import time
from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from app import db
from app.persistence import connection as db_conn

pytestmark = pytest.mark.integration


@pytest.fixture()
def pooled(test_db, monkeypatch):
    monkeypatch.setattr(db_conn, "DATABASE_POOL_MAX_SIZE", 3)
    monkeypatch.setattr(db_conn, "DATABASE_POOL_MIN_SIZE", 1)
    monkeypatch.setattr(db_conn, "DATABASE_POOL_TIMEOUT_SECONDS", 1.0)
    db.close_connection_pool()
    yield
    db.close_connection_pool()


def test_connections_are_reused_after_leaving_the_with_block(pooled):
    pids = []
    for _ in range(6):
        with db.connect() as conn:
            pids.append(conn.info.backend_pid)
            assert not conn.closed
    # Without a pool every checkout would open a new backend (6 distinct pids).
    assert len(set(pids)) <= 2


def test_with_block_commits_on_success_and_rolls_back_on_error(pooled):
    with db.connect() as conn:
        conn.execute("CREATE TEMP TABLE pool_probe(value INT) ON COMMIT DROP")
    with db.connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS pool_probe_committed(value INT)")
        conn.execute("TRUNCATE pool_probe_committed")
        conn.execute("INSERT INTO pool_probe_committed VALUES (1)")
    with pytest.raises(RuntimeError):
        with db.connect() as conn:
            conn.execute("INSERT INTO pool_probe_committed VALUES (2)")
            raise RuntimeError("boom")
    with db.connect() as conn:
        values = [row["value"] for row in conn.execute("SELECT value FROM pool_probe_committed").fetchall()]
        conn.execute("DROP TABLE pool_probe_committed")
    assert values == [1]


def test_pool_size_is_bounded_under_concurrency(pooled):
    def backend_pid(_index: int) -> int:
        with db.connect() as conn:
            conn.execute("SELECT pg_sleep(0.05)")
            return conn.info.backend_pid

    with ThreadPoolExecutor(max_workers=8) as executor:
        pids = set(executor.map(backend_pid, range(24)))
    assert len(pids) <= 3


def test_saturated_pool_raises_operational_error_without_opening_circuit(pooled):
    held = [db.connect() for _ in range(3)]
    try:
        with pytest.raises(psycopg.OperationalError, match="pool timeout"):
            db.connect()
        assert not db.database_circuit_status()["open"]
    finally:
        for conn in held:
            conn.__exit__(None, None, None)
    with db.connect() as conn:
        assert conn.execute("SELECT 1 AS one").fetchone()["one"] == 1


def test_pool_can_be_disabled(test_db, monkeypatch):
    monkeypatch.setattr(db_conn, "DATABASE_POOL_MAX_SIZE", 0)
    db.close_connection_pool()
    with db.connect() as conn:
        conn.execute("SELECT 1")
    assert conn.closed


def test_unreachable_database_opens_the_circuit_breaker_through_the_pool(test_db, monkeypatch):
    monkeypatch.setattr(db_conn, "DATABASE_URL", "postgresql://nobody:***@127.0.0.1:1/none")
    monkeypatch.setattr(db_conn, "DATABASE_POOL_MAX_SIZE", 2)
    monkeypatch.setattr(db_conn, "DATABASE_POOL_MIN_SIZE", 0)
    monkeypatch.setattr(db_conn, "DATABASE_POOL_TIMEOUT_SECONDS", 1.0)
    db.close_connection_pool()
    db._close_database_circuit()
    try:
        with pytest.raises(psycopg.OperationalError):
            db.connect()
        assert db.database_circuit_status()["open"]
        started = time.perf_counter()
        with pytest.raises(psycopg.OperationalError, match="circuit is open"):
            db.connect()
        assert time.perf_counter() - started < 0.1
    finally:
        db._close_database_circuit()
        db.close_connection_pool()
