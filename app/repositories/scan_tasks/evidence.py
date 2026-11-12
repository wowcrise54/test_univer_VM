"""Repository for completed scan evidence rows."""

from __future__ import annotations

from ...persistence import connection


def record_completed_scan_evidence(
    postprocess_run_id: str,
    *,
    mp_task_id: str,
    scanned_at: str,
) -> int:
    with connection.connect() as conn:
        result = conn.execute(
            """
            INSERT INTO asset_scan_evidence (
                asset_id, postprocess_run_id, mp_task_id, scanned_at, updated_at
            )
            SELECT DISTINCT asset_id, %s, %s, %s::timestamptz, NOW()
            FROM scan_postprocess_items
            WHERE postprocess_run_id = %s
              AND status = 'completed'
              AND NULLIF(asset_id, '') IS NOT NULL
            ON CONFLICT (asset_id) DO UPDATE SET
                postprocess_run_id = EXCLUDED.postprocess_run_id,
                mp_task_id = EXCLUDED.mp_task_id,
                scanned_at = EXCLUDED.scanned_at,
                updated_at = NOW()
            WHERE EXCLUDED.scanned_at >= asset_scan_evidence.scanned_at
            """,
            (postprocess_run_id, mp_task_id, scanned_at, postprocess_run_id),
        )
    return int(result.rowcount or 0)
