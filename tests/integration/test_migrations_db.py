"""Integration: real migration, schema and repository verification over PostgreSQL.

Drives the real Alembic chain (``migrations/``) inside the Docker test stack
against a **throwaway** scratch database (so a downgrade never touches the
shared ``mpvm_test`` schema) and asserts, against the *observed* behaviour of
the real migrations:

* the migration graph has a single, expected head (``20260911_0023``);
* a full ``base -> head`` upgrade materialises the migration-created tables,
  the 0011/0018/0022 columns and the 0023 index, and seeds the SLA policy;
* ``downgrade base`` empties ``alembic_version`` and drops the 0011/0006/0008
  tables plus the 0011/0018/0022 columns and the 0023 index, while leaving the
  expand/contract 0002 ``notifications`` table in place (its downgrade is a
  deliberate no-op that preserves operator history);
* a re-upgrade to head restores every dropped artefact; and
* the real repositories (notifications, saved views, remediation SLA policy)
  round-trip their data against the migrated schema.

Migration facts below were verified by driving the chain on a live scratch
database, not assumed from the source.
"""

from __future__ import annotations

import os
import subprocess
from contextlib import contextmanager

import psycopg

from app import db, main

EXPECTED_HEAD = "20260911_0023"
HEAD_PARENT = "20260910_0022"

# Tables created by migrations that a full upgrade must materialise and a
# downgrade to base must drop (verified: all absent at base, restored on re-upgrade).
DROPPED_AT_BASE = {
    "vm_workflow_runs",       # 0011
    "vm_workflow_steps",      # 0011
    "remediation_cases",      # 0006
    "remediation_campaigns",  # 0010
    "remediation_sla_policy", # 0006 (seeded with policy_id=1)
    "app_roles",              # 0008
    "app_role_permissions",   # 0008
}

# 0002 uses the expand/contract strategy: its downgrade is a no-op that keeps
# operator history, so the notifications table SURVIVES a downgrade to base.
EXPAND_CONTRACT_TABLE = "notifications"

# (table, column) pairs added by migrations that a downgrade to base must drop
# and a re-upgrade must restore (verified: all dropped at base, restored on re-upgrade).
ALTERED_COLUMNS = {
    ("remediation_cases", "verification_status"),   # 0011
    ("remediation_campaigns", "asset_group_id"),    # 0018
    ("vulnerability_passports", "exploitation_evidence"),  # 0022 (generated)
}

INDEX_0023 = "idx_asset_card_vulnerability_passports_finding"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _scratch_url(name: str) -> str:
    """Build a URL for a new database on the same server, keeping credentials."""
    scheme, rest = db.DATABASE_URL.split("://", 1)
    auth = rest.partition("/")[0]  # "user:pass@host:port"
    return f"{scheme}://{auth}/{name}"


def _run_alembic(database_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run an ``alembic`` subcommand against ``database_url``; assert it succeeds."""
    env = dict(os.environ, MPVM_DATABASE_URL=database_url)
    completed = subprocess.run(
        ["alembic", *args],
        env=env,
        cwd="/workspace",
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, (
        f"alembic {' '.join(args)} failed:\n{completed.stdout}\n{completed.stderr}"
    )
    return completed


@contextmanager
def _conn(database_url: str):
    conn = psycopg.connect(database_url, autocommit=True, connect_timeout=10)
    try:
        yield conn
    finally:
        conn.close()


def _tables(database_url: str) -> set[str]:
    with _conn(database_url) as conn:
        rows = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"
        ).fetchall()
    return {row[0] for row in rows}  # raw psycopg returns tuples, not dicts


def _current_revisions(database_url: str) -> list[str]:
    with _conn(database_url) as conn:
        row_exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_name='alembic_version')"
        ).fetchone()
        if not (row_exists and row_exists[0]):
            return []
        rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
    return [row[0] for row in rows]


def _has_column(database_url: str, table: str, column: str) -> bool:
    with _conn(database_url) as conn:
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns "
            "WHERE table_name=%s AND column_name=%s)",
            (table, column),
        ).fetchone()
    return bool(row and row[0])


def _has_index(database_url: str, index_name: str) -> bool:
    with _conn(database_url) as conn:
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname=%s)",
            (index_name,),
        ).fetchone()
    return bool(row and row[0])


def _sla_seed_present(database_url: str) -> bool:
    with _conn(database_url) as conn:
        row = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM remediation_sla_policy WHERE policy_id=1)"
        ).fetchone()
    return bool(row and row[0])


# --------------------------------------------------------------------------- #
# migration graph
# --------------------------------------------------------------------------- #
def test_alembic_graph_has_single_expected_head(migrated_db):
    heads = _run_alembic(db.DATABASE_URL, "heads")
    current = _run_alembic(db.DATABASE_URL, "current")

    # Exactly one head, and it is the expected revision.
    head_lines = [ln.strip() for ln in heads.stdout.splitlines() if ln.strip()]
    assert len(head_lines) == 1, f"expected a single head, got:\n{heads.stdout}"
    assert EXPECTED_HEAD in head_lines[0], f"unexpected head line: {head_lines[0]!r}"
    assert "(head)" in head_lines[0], f"head marker missing: {head_lines[0]!r}"

    # The shared (already-migrated) test database is at that head.
    assert EXPECTED_HEAD in current.stdout, f"current revision is not {EXPECTED_HEAD}:\n{current.stdout}"


# --------------------------------------------------------------------------- #
# full base <-> head round-trip on a scratch database
# --------------------------------------------------------------------------- #
def test_migration_roundtrip_base_to_head_and_back(migrated_db):
    from tests.conftest import scratch_database

    with scratch_database() as name:
        url = _scratch_url(name)

        # 1. Fresh scratch DB: empty, upgrade to head.
        assert _tables(url) == set(), "scratch database should start empty"
        _run_alembic(url, "upgrade", "head")
        assert _current_revisions(url) == [EXPECTED_HEAD]
        assert DROPPED_AT_BASE <= _tables(url), "upgrade missing migration tables"
        assert EXPAND_CONTRACT_TABLE in _tables(url)
        assert _has_index(url, INDEX_0023), "0023 index missing after upgrade"
        for table, column in ALTERED_COLUMNS:
            assert _has_column(url, table, column), f"{table}.{column} missing after upgrade"
        assert _sla_seed_present(url), "remediation_sla_policy seed missing after upgrade"

        # 2. Downgrade the whole chain to base: alembic_version empties, the
        #    0011/0006/0008/0010 tables and 0011/0018/0022 columns are dropped,
        #    the 0023 index is gone, but the expand/contract notifications table
        #    is intentionally preserved.
        _run_alembic(url, "downgrade", "base")
        assert _current_revisions(url) == [], "alembic_version should be empty at base"
        base_tables = _tables(url)
        assert not (DROPPED_AT_BASE & base_tables), (
            f"tables should be dropped at base, still present: {DROPPED_AT_BASE & base_tables}"
        )
        assert EXPAND_CONTRACT_TABLE in base_tables, "expand/contract table should survive base"
        for table, column in ALTERED_COLUMNS:
            assert not _has_column(url, table, column), f"{table}.{column} should be dropped at base"
        assert not _has_index(url, INDEX_0023), "0023 index should be dropped at base"

        # 3. Re-upgrade to head: everything is restored.
        _run_alembic(url, "upgrade", "head")
        assert _current_revisions(url) == [EXPECTED_HEAD]
        assert DROPPED_AT_BASE <= _tables(url), "re-upgrade missing migration tables"
        assert EXPAND_CONTRACT_TABLE in _tables(url)
        assert _has_index(url, INDEX_0023), "0023 index missing after re-upgrade"
        for table, column in ALTERED_COLUMNS:
            assert _has_column(url, table, column), f"{table}.{column} missing after re-upgrade"
        assert _sla_seed_present(url), "remediation_sla_policy seed missing after re-upgrade"


def _seed_sla_policy(url: str) -> None:
    """Re-create the single SLA policy row (0006 seeds it on fresh installs)."""
    with _conn(url) as conn:
        conn.execute(
            "INSERT INTO remediation_sla_policy (policy_id) VALUES (1) "
            "ON CONFLICT (policy_id) DO NOTHING"
        )


# --------------------------------------------------------------------------- #
# 0023 idempotency (its upgrade is CREATE INDEX IF NOT EXISTS)
# --------------------------------------------------------------------------- #
def test_migration_0023_is_idempotent(migrated_db):
    from tests.conftest import scratch_database

    with scratch_database() as name:
        url = _scratch_url(name)

        # Fresh install: the baseline schema_statements already creates the index,
        # so upgrading through 0023 must not fail with a duplicate-index error.
        _run_alembic(url, "upgrade", "head")
        assert _current_revisions(url) == [EXPECTED_HEAD]
        assert _has_index(url, INDEX_0023)

        # Downgrade one step (drops the index) then re-apply 0023.
        _run_alembic(url, "downgrade", "-1")
        assert _current_revisions(url) == [HEAD_PARENT]
        assert not _has_index(url, INDEX_0023), "0023 index should be dropped by downgrade"

        _run_alembic(url, "upgrade", "head")
        assert _current_revisions(url) == [EXPECTED_HEAD]
        assert _has_index(url, INDEX_0023), "0023 index should be restored by upgrade"


# --------------------------------------------------------------------------- #
# repository round-trips against the migrated schema (shared test DB)
# --------------------------------------------------------------------------- #
def test_notifications_repository_roundtrip(test_db):
    repo = main.AUTOMATION_REPOSITORY
    created = repo.create_notification(
        level="info",
        title="migration-repo-probe",
        message="round-trip verification",
        event_type="test",
        details={"origin": "migrations_db"},
    )
    assert created.get("notification_id"), f"create_notification returned no id: {created}"
    assert created["title"] == "migration-repo-probe"

    listing = repo.list_notifications(unread_only=True)
    assert any(n.get("notification_id") == created["notification_id"] for n in listing["rows"]), (
        "created notification not present in unread listing"
    )
    assert int(listing["unread"]) >= 1

    assert repo.mark_notification_read(created["notification_id"]) is True
    after = repo.list_notifications(unread_only=True)
    assert all(n.get("notification_id") != created["notification_id"] for n in after["rows"]), (
        "notification should no longer be unread after mark_read"
    )


def test_saved_views_repository_roundtrip(test_db):
    repo = main.CONTAINER.repositories.operations
    saved = db.save_view(route="assets", name="migration-repo-view", filters={"q": "probe"})
    assert saved.get("id"), f"save_view returned no id: {saved}"

    views = repo.saved_views("assets")
    assert any(v.get("name") == "migration-repo-view" for v in views), (
        "saved view not present after save_view"
    )

    assert db.delete_saved_view(int(saved["id"])) is True
    views = repo.saved_views("assets")
    assert all(v.get("id") != saved["id"] for v in views), "saved view still present after delete"


def test_remediation_sla_policy_repository(test_db):
    # The test_db fixture truncates all tables (including the 0006 seed row), so
    # restore the single default policy row that a fresh migration install has.
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO remediation_sla_policy (policy_id) VALUES (1) "
            "ON CONFLICT (policy_id) DO NOTHING"
        )
    policy = main.CONTAINER.services.remediation.policy()
    # The 0006 migration seeds a single default policy row; the repository must
    # surface it with the documented positive defaults.
    assert policy, "remediation SLA policy not returned"
    assert int(policy.get("critical_days", 0)) > 0
    assert int(policy.get("high_days", 0)) > 0
    assert int(policy.get("medium_days", 0)) > 0
    assert int(policy.get("low_days", 0)) > 0
