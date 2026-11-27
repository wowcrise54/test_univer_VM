"""PostgreSQL advisory locks shared by writers.

Passport, finding and link writers must take the passport write lock
before row locks: link rebuilds lock links before FK KEY SHARE on findings,
while card replacement/deletion locks findings before cascading to links."""

from __future__ import annotations

import os
from typing import Any

import psycopg

# Passport, finding and link writers must take this transaction-scoped lock
# before row locks: link rebuilds lock links before FK KEY SHARE on findings,
# while card replacement/deletion locks findings before cascading to links.
_VULNERABILITY_PASSPORT_WRITE_LOCK = (1297106509, 1448301139)

_ASSET_CARD_BUILD_ADMISSION_LOCK = (1297106509, 1094927172)

class _AssetCardBuildAdmissionConflict(Exception):
    pass

# How long a writer waits for the passport write lock while a catalog refresh
# holds it. Longer than the server statement_timeout on purpose (see
# _lock_vulnerability_passport_writes).
PASSPORT_LOCK_WAIT_SECONDS = max(1, int(os.getenv("MPVM_PASSPORT_LOCK_WAIT_SECONDS", "3600")))

def _lock_vulnerability_passport_writes(
    conn: psycopg.Connection[dict[str, Any]],
) -> None:
    """Take the passport write lock, waiting out a long catalog refresh.

    A full catalog refresh holds this lock for as long as it saves the catalog,
    which is far longer than the server ``statement_timeout``. Waiting under that
    timeout cancelled the queued asset card saves (``QueryCanceled``), so the
    wait gets its own, longer limit that applies to the lock statement only. The
    lock stays a blocking one, so PostgreSQL still detects deadlocks.
    """
    previous = conn.execute("SHOW statement_timeout").fetchone()
    previous_value = next(iter(previous.values())) if previous else "0"
    wait_ms = int(PASSPORT_LOCK_WAIT_SECONDS * 1000)
    conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(wait_ms),))
    # No try/finally: if the wait fails the transaction is aborted, and the
    # transaction-local setting disappears with the rollback.
    conn.execute(
        "SELECT pg_advisory_xact_lock(%s, %s)",
        _VULNERABILITY_PASSPORT_WRITE_LOCK,
    )
    conn.execute("SELECT set_config('statement_timeout', %s, true)", (previous_value,))
