"""Shared pytest fixtures.

Unit tests never request these fixtures, so a missing PostgreSQL is harmless
for them. Integration tests (``tests/integration/``) opt in explicitly via
``test_db`` / ``scratch_database``.

The test database URL comes from the ``MPVM_DATABASE_URL`` environment
variable that ``compose.test.yml`` injects; ``app.db`` reads it at import time.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest

from app import db


def _host_from_url(url: str) -> tuple[str, int]:
    rest = url.split("://", 1)[1]
    host_part = rest.rsplit("@", 1)[-1]
    hostport, _, _ = host_part.partition("/")
    host, _, port = hostport.partition(":")
    return host, int(port or 5432)


def _db_reachable() -> bool:
    try:
        host, port = _host_from_url(db.DATABASE_URL)
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def truncate_all_state() -> None:
    """Wipe every application table (keeps ``alembic_version``).

    The schema of the shared test database is built once by the session-scoped
    ``migrated_db`` fixture; each test starts from an empty data state.  The
    shared database is disposable (tmpfs in ``compose.test.yml``) and is never
    a production volume.
    """
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'alembic_version'"
        ).fetchall()
        tables = [row["tablename"] for row in rows]
        if tables:
            conn.execute(
                f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE"
            )


def reset_process_wide_db_state() -> None:
    """Reset module-global DB state that TRUNCATE cannot reach.

    The database circuit breaker in :mod:`app.db` is a process-global.  A
    transient connect failure in any earlier test (under the load of a full
    suite) opens it for ``DATABASE_CIRCUIT_BREAKER_SECONDS``; while open,
    ``db.connect()`` raises immediately and :func:`app.auth.audit_event`
    silently drops the audit row (it swallows exceptions).  Closing the
    circuit and reaping idle connections per test keeps each test isolated.
    """
    db._close_database_circuit()
    try:
        with db.connect() as conn:
            conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname=current_database() AND pid<>pg_backend_pid() "
                "AND state='idle'"
            )
    except Exception:
        # Best effort: the next test's connection will succeed on a healthy DB.
        pass


@pytest.fixture(scope="session")
def migrated_db():
    """Apply the Alembic migrations once per session (idempotent)."""
    if not _db_reachable():
        pytest.skip("PostgreSQL test database is not reachable")
    db.init_db()
    yield


@pytest.fixture()
def test_db(migrated_db):
    """A clean PostgreSQL data state for a single test."""
    truncate_all_state()
    # Ensure the RBAC catalog exists (auth unit tests seed it via mocks, but
    # integration tests exercise the real tables).
    from app import auth

    auth.ensure_rbac_catalog()
    # The login rate limiter is a module-level global keyed by
    # ``{host}:{username}`` and is NOT wiped by the TRUNCATE above.  Failed
    # logins from other tests (e.g. repeated wrong-password attempts for the
    # same username) accumulate across the session and can trip a later test's
    # *successful* login into a 429 before its audit event is written.  Reset
    # it per test for isolation.
    auth.LOGIN_LIMITER._entries.clear()
    # ``auth.resolve_ldap_identity`` is a module global bound from
    # ``app.ldap``; a racy/leaked ``mock.patch`` in an earlier test (a known
    # hazard of patching shared state from threads) can leave it mocked, so a
    # bad-password login would "succeed" via the stale mock and a later test
    # would see 200 instead of 401.  Rebind it to the real implementation.
    from app import ldap as _ldap

    auth.resolve_ldap_identity = _ldap.resolve_ldap_identity
    # The DB circuit breaker is process-global as well: a transient connect
    # failure in an earlier test (under full-suite load) can keep it open and
    # silently drop audit writes in a later test.  Reset it per test.
    reset_process_wide_db_state()
    yield


@contextmanager
def scratch_database() -> Iterator[str]:
    """Create a throwaway database, yield its name, and drop it afterwards.

    Used by the migration round-trip tests so a downgrade never touches the
    shared ``mpvm_test`` schema.
    """
    admin = psycopg.connect(db.DATABASE_URL, connect_timeout=5, autocommit=True)
    name = f"mpvm_scratch_{socket.gethostname()[:10].replace('.', '_')}_{id(object()) % 1000000}"
    try:
        with admin.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{name}"')
        yield name
    finally:
        try:
            # Terminate stray connections before dropping.
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s AND pid<>pg_backend_pid()",
                (name,),
            )
        finally:
            try:
                with admin.cursor() as cur:
                    cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
            finally:
                admin.close()
