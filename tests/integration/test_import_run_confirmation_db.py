"""Regression test: the confirmed-export gate must be fail-closed on real data.

Post-export asset removal may only delete assets whose export AND local save
are confirmed. The confirmation gate (``get_confirmed_exported_asset_ids``)
returns asset IDs for a *completed* import run only; failed, still-running or
missing runs must yield ``None`` so that no unconfirmed asset is ever removed.
"""
from __future__ import annotations

from app import db
from app.repositories.imports.runs import (
    create_import_run,
    finish_import_run,
    get_confirmed_exported_asset_ids,
)


def _asset(conn, key: str, mp_asset_id: str | None) -> int:
    now = db.now_utc()
    row = conn.execute(
        "INSERT INTO assets (asset_key, mp_asset_id, ip_address, first_seen, last_seen) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (key, mp_asset_id, f"192.0.2.{len(key)}", now, now),
    ).fetchone()
    assert row is not None
    return int(row["id"])


def _finding(conn, run_id: int, asset_id: int) -> None:
    conn.execute(
        "INSERT INTO vulnerability_findings (import_run_id, asset_id, kind, raw_row_json, created_at) "
        "VALUES (%s, %s, 'os', '{}', %s)",
        (run_id, asset_id, db.now_utc()),
    )


def test_confirmed_exported_asset_ids_are_fail_closed(test_db):
    completed = create_import_run(source="pdql", pdql="select * from asset", csv_filename="c.csv", delete_after_export=True)
    failed = create_import_run(source="pdql", pdql=None, csv_filename="f.csv", delete_after_export=True)
    running = create_import_run(source="pdql", pdql=None, csv_filename="r.csv", delete_after_export=True)
    with db.connect() as conn:
        saved = _asset(conn, "saved-asset", "mp-asset-confirmed")
        ghost = _asset(conn, "ghost-asset", None)
        _finding(conn, completed, saved)
        _finding(conn, completed, ghost)
        _finding(conn, failed, saved)
    finish_import_run(completed, row_count=2, asset_count=1, finding_count=2)
    finish_import_run(failed, row_count=1, asset_count=1, finding_count=1, status="failed", error="simulated MP VM outage")

    # Only the completed run confirms its saved asset; a finding in another run
    # and an asset without an MP asset ID never leak into the confirmed set.
    assert get_confirmed_exported_asset_ids(completed) == ["mp-asset-confirmed"]
    # A failed import is not a confirmation: nothing may be removed.
    assert get_confirmed_exported_asset_ids(failed) is None
    # A still-running import (status default) is not a confirmation either.
    assert get_confirmed_exported_asset_ids(running) is None
    # A missing run is not a confirmation either.
    assert get_confirmed_exported_asset_ids(999_999) is None
