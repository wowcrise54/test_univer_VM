"""PostgreSQL connection circuit breaker (process-global).

A transient connect failure opens the circuit for
``DATABASE_CIRCUIT_BREAKER_SECONDS``; while it is open ``connect()`` raises
immediately instead of stacking timeouts."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import psycopg

DATABASE_CIRCUIT_BREAKER_SECONDS = max(1, min(60, int(os.getenv("MPVM_DATABASE_CIRCUIT_BREAKER_SECONDS", "10"))))

_DB_CIRCUIT_LOCK = threading.Lock()

_DB_CIRCUIT_OPEN_UNTIL = 0.0

_DB_CIRCUIT_ERROR: str | None = None

_DB_CIRCUIT_REASON: str | None = None

def database_circuit_status() -> dict[str, Any]:
    with _DB_CIRCUIT_LOCK:
        remaining_seconds = max(0.0, _DB_CIRCUIT_OPEN_UNTIL - time.monotonic())
        return {
            "open": remaining_seconds > 0,
            "retry_ready": remaining_seconds <= 0,
            "retry_after_seconds": round(remaining_seconds, 2),
            "message": _DB_CIRCUIT_ERROR,
            "reason": _DB_CIRCUIT_REASON,
        }

def _open_database_circuit(exc: Exception) -> None:
    global _DB_CIRCUIT_OPEN_UNTIL, _DB_CIRCUIT_ERROR, _DB_CIRCUIT_REASON
    with _DB_CIRCUIT_LOCK:
        _DB_CIRCUIT_OPEN_UNTIL = time.monotonic() + DATABASE_CIRCUIT_BREAKER_SECONDS
        _DB_CIRCUIT_ERROR = str(exc)
        _DB_CIRCUIT_REASON = type(exc).__name__

def _close_database_circuit() -> None:
    global _DB_CIRCUIT_OPEN_UNTIL, _DB_CIRCUIT_ERROR, _DB_CIRCUIT_REASON
    with _DB_CIRCUIT_LOCK:
        _DB_CIRCUIT_OPEN_UNTIL = 0.0
        _DB_CIRCUIT_ERROR = None
        _DB_CIRCUIT_REASON = None

def _raise_if_database_circuit_open() -> None:
    status = database_circuit_status()
    if not status["open"]:
        return
    raise psycopg.OperationalError(
        f"Database connection circuit is open for {status['retry_after_seconds']}s after: {status['message']}"
    )
