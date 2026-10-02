from __future__ import annotations

import uuid
from typing import Any

from .. import db


class ScannerTaskFolderRepository:
    def list(self) -> list[dict[str, Any]]:
        with db.connect() as conn:
            rows = conn.execute(
                """SELECT f.folder_id::text AS folder_id, f.name,
                          COALESCE(array_agg(a.task_id ORDER BY a.task_id)
                              FILTER (WHERE a.task_id IS NOT NULL), ARRAY[]::text[]) AS task_ids
                   FROM scanner_task_folders f
                   LEFT JOIN scanner_task_folder_assignments a USING (folder_id)
                   GROUP BY f.folder_id, f.name
                   ORDER BY lower(f.name), f.folder_id"""
            ).fetchall()
        return [dict(row) for row in rows]

    def create(self, name: str, *, actor: str | None) -> dict[str, Any]:
        folder_id = str(uuid.uuid4())
        now = db.now_utc()
        with db.connect() as conn:
            row = conn.execute(
                """INSERT INTO scanner_task_folders
                       (folder_id, name, created_by, updated_by, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   RETURNING folder_id::text AS folder_id, name, created_at, updated_at""",
                (folder_id, name, actor, actor, now, now),
            ).fetchone()
        return dict(row)

    def rename(self, folder_id: str, name: str, *, actor: str | None) -> dict[str, Any] | None:
        with db.connect() as conn:
            row = conn.execute(
                """UPDATE scanner_task_folders
                   SET name=%s, updated_by=%s, updated_at=%s
                   WHERE folder_id=%s
                   RETURNING folder_id::text AS folder_id, name, created_at, updated_at""",
                (name, actor, db.now_utc(), folder_id),
            ).fetchone()
        return dict(row) if row else None

    def delete(self, folder_id: str) -> bool:
        with db.connect() as conn:
            result = conn.execute(
                "DELETE FROM scanner_task_folders WHERE folder_id=%s",
                (folder_id,),
            )
        return result.rowcount > 0

    def folder_exists(self, folder_id: str) -> bool:
        with db.connect() as conn:
            return conn.execute(
                "SELECT 1 FROM scanner_task_folders WHERE folder_id=%s",
                (folder_id,),
            ).fetchone() is not None

    def assign(self, task_ids: list[str], folder_id: str | None, *, actor: str | None) -> None:
        if not task_ids:
            return
        with db.connect() as conn:
            if folder_id is None:
                conn.execute(
                    "DELETE FROM scanner_task_folder_assignments WHERE task_id = ANY(%s)",
                    (task_ids,),
                )
                return
            conn.execute(
                """INSERT INTO scanner_task_folder_assignments
                       (task_id, folder_id, updated_by, updated_at)
                   SELECT task_id, %s, %s, %s FROM unnest(%s::text[]) AS task_id
                   ON CONFLICT (task_id) DO UPDATE
                       SET folder_id=EXCLUDED.folder_id,
                           updated_by=EXCLUDED.updated_by,
                           updated_at=EXCLUDED.updated_at""",
                (folder_id, actor, db.now_utc(), task_ids),
            )

    def unassign_task(self, task_id: str) -> None:
        with db.connect() as conn:
            conn.execute(
                "DELETE FROM scanner_task_folder_assignments WHERE task_id=%s",
                (task_id,),
            )
