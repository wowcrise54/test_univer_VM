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
