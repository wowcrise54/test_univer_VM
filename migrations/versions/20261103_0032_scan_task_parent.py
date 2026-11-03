"""Link precheck tasks to the audit task they were created for.

The link used to live only in the last MP VM response of the precheck row, which
the next status update overwrote, so precheck tasks could not be found again to
be deleted together with (or after) their audit task.
"""

from alembic import op

revision = "20261103_0032"
down_revision = "20261102_0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS parent_task_id TEXT")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_tasks_parent ON scan_tasks (parent_task_id) "
        "WHERE parent_task_id IS NOT NULL"
    )
    # Responses that are not JSON objects (or hold invalid JSON) are skipped.
    op.execute(
        """
        UPDATE scan_tasks
        SET parent_task_id = last_remote_response_json::jsonb ->> 'audit_task_id'
        WHERE parent_task_id IS NULL
          AND left(status, 9) = 'precheck_'
          AND CASE
                WHEN last_remote_response_json LIKE '{%'
                THEN last_remote_response_json::jsonb ? 'audit_task_id'
                ELSE FALSE
              END
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_scan_tasks_parent")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS parent_task_id")
