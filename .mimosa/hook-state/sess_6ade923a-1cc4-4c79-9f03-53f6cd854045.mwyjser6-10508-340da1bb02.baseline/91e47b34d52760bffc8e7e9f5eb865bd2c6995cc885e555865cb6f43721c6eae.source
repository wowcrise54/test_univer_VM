"""Shared PostgreSQL connection pool and the ``connect()`` entry point.

``connect()`` returns a connection with ``with``-block commit/rollback
semantics (pooled or direct). Connection failures feed the process-global
circuit breaker in :mod:`app.persistence.circuit_breaker`."""

from __future__ import annotations

import atexit
import os
import threading
import time
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

from app.diagnostics import DiagnosticConnection, DiagnosticCursor, log_event, log_exception

from .circuit_breaker import _close_database_circuit, _open_database_circuit, _raise_if_database_circuit_open
from .transactions import PooledConnection

DATABASE_URL = (
    os.getenv("MPVM_DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or "postgresql://mpvm:mpvm@localhost:5432/mpvm"
)

DATABASE_CONNECT_TIMEOUT_SECONDS = max(1, min(10, int(os.getenv("MPVM_DATABASE_CONNECT_TIMEOUT_SECONDS", "2"))))

DATABASE_POOL_MAX_SIZE = max(0, min(200, int(os.getenv("MPVM_DATABASE_POOL_MAX_SIZE", "32"))))

DATABASE_POOL_MIN_SIZE = max(0, int(os.getenv("MPVM_DATABASE_POOL_MIN_SIZE", "2")))

DATABASE_POOL_TIMEOUT_SECONDS = max(1.0, float(os.getenv("MPVM_DATABASE_POOL_TIMEOUT_SECONDS", "10")))

_DB_POOL: ConnectionPool | None = None

_DB_POOL_URL: str | None = None

_DB_POOL_LOCK = threading.Lock()

def database_label() -> str:
    if "@" not in DATABASE_URL:
        return DATABASE_URL
    scheme, rest = DATABASE_URL.split("://", 1)
    _, host_part = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host_part}"

def _pool_connection_kwargs() -> dict[str, Any]:
    return {
        "row_factory": dict_row,
        "cursor_factory": DiagnosticCursor,
        "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
    }

def _get_connection_pool() -> ConnectionPool | None:
    """Return the shared pool for the current DATABASE_URL (None when disabled)."""
    global _DB_POOL, _DB_POOL_URL
    if DATABASE_POOL_MAX_SIZE <= 0:
        return None
    with _DB_POOL_LOCK:
        if _DB_POOL is not None and _DB_POOL_URL == DATABASE_URL:
            return _DB_POOL
        previous = _DB_POOL
        _DB_POOL = ConnectionPool(
            DATABASE_URL,
            connection_class=PooledConnection,
            kwargs=_pool_connection_kwargs(),
            min_size=max(0, min(DATABASE_POOL_MIN_SIZE, DATABASE_POOL_MAX_SIZE)),
            max_size=DATABASE_POOL_MAX_SIZE,
            timeout=DATABASE_POOL_TIMEOUT_SECONDS,
            check=ConnectionPool.check_connection,
            open=False,
            name="mpvm-db",
        )
        _DB_POOL.open(wait=False)
        _DB_POOL_URL = DATABASE_URL
        pool = _DB_POOL
    if previous is not None:
        previous.close(timeout=1)
    return pool

def close_connection_pool() -> None:
    """Close the shared pool (application shutdown, tests)."""
    global _DB_POOL, _DB_POOL_URL
    with _DB_POOL_LOCK:
        pool, _DB_POOL, _DB_POOL_URL = _DB_POOL, None, None
    if pool is not None:
        pool.close(timeout=2)

def _checkout_pooled_connection(pool: ConnectionPool) -> psycopg.Connection[dict[str, Any]]:
    started = time.perf_counter()
    errors_before = pool.get_stats().get("connections_errors", 0)
    try:
        connection = pool.getconn()
    except PoolTimeout as exc:
        # New connection errors while waiting mean the database is unreachable
        # (the pool's workers cannot connect); a plain timeout is only
        # saturation and must not trip the circuit breaker.
        if pool.get_stats().get("connections_errors", 0) > errors_before:
            _open_database_circuit(exc)
        log_exception("database", "db.connection.failed", database=database_label())
        raise psycopg.OperationalError(f"Database connection pool timeout: {exc}") from exc
    except Exception as exc:
        _open_database_circuit(exc)
        log_exception("database", "db.connection.failed", database=database_label())
        raise
    _close_database_circuit()
    connection._mpvm_checkout_pool = pool  # type: ignore[attr-defined]
    log_event(
        "database",
        "db.connection.checked_out",
        level=10,
        database=database_label(),
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    return connection  # type: ignore[return-value]

def connect() -> psycopg.Connection[dict[str, Any]]:
    _raise_if_database_circuit_open()
    pool = _get_connection_pool()
    if pool is not None:
        return _checkout_pooled_connection(pool)
    return _connect_direct()

def _connect_direct() -> psycopg.Connection[dict[str, Any]]:
    started = time.perf_counter()
    try:
        connection = DiagnosticConnection.connect(
            DATABASE_URL,
            row_factory=dict_row,
            cursor_factory=DiagnosticCursor,
            connect_timeout=DATABASE_CONNECT_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        _open_database_circuit(exc)
        log_exception("database", "db.connection.failed", database=database_label())
        raise
    _close_database_circuit()
    elapsed_ms = (time.perf_counter() - started) * 1000
    log_event(
        "database",
        "db.connection.opened",
        level=10,
        database=database_label(),
        duration_ms=round(elapsed_ms, 2),
    )
    return connection

atexit.register(close_connection_pool)
