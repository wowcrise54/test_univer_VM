"""Repository for CSV import run records."""

from __future__ import annotations

from ...persistence import codecs, connection


def create_import_run(
    *,
    source: str,
    pdql: str | None = None,
    csv_filename: str | None = None,
    delete_after_export: bool = False,
) -> int:
    current = codecs.now_utc()
    with connection.connect() as conn:
        row = conn.execute(
            """
            INSERT INTO import_runs (source, pdql, csv_filename, delete_after_export, started_at)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (source, pdql, csv_filename, delete_after_export, current),
        ).fetchone()
        assert row is not None
        return int(row["id"])


def get_confirmed_exported_asset_ids(run_id: int):
    """MP asset IDs saved by a completed import run; None when the run is missing or did not complete."""
    with connection.connect() as conn:
        row = conn.execute("SELECT status FROM import_runs WHERE id = %s", (run_id,)).fetchone()
        if row is None or row["status"] != "completed":
            return None
        rows = conn.execute(
            """
            SELECT DISTINCT a.mp_asset_id
            FROM vulnerability_findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.import_run_id = %s AND a.mp_asset_id IS NOT NULL
            """,
            (run_id,),
        ).fetchall()
    return [str(r["mp_asset_id"]) for r in rows]


def finish_import_run(
    run_id: int,
    *,
    row_count: int,
    asset_count: int,
    finding_count: int,
    status: str = "completed",
    error: str | None = None,
    asset_removal_operation_id: str | None = None,
) -> None:
    with connection.connect() as conn:
        conn.execute(
            """
            UPDATE import_runs
            SET row_count = %s, asset_count = %s, finding_count = %s, status = %s, error = %s,
                asset_removal_operation_id = %s, finished_at = %s
            WHERE id = %s
            """,
            (
                row_count,
                asset_count,
                finding_count,
                status,
                error,
                asset_removal_operation_id,
                codecs.now_utc(),
                run_id,
            ),
        )
