"""Store task-specific schedules and personal task folders."""

from alembic import op

revision = "20261111_0040"
down_revision = "20261110_0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_tasks ADD COLUMN team_schedule_override JSONB")
    op.execute("""
        CREATE TABLE team_task_folders (
            owner_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            folder_id UUID NOT NULL,
            name TEXT NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
            PRIMARY KEY (owner_id, folder_id)
        )
    """)
    op.execute("CREATE UNIQUE INDEX uq_team_task_folder_name ON team_task_folders (owner_id, lower(name))")
    op.execute("""
        CREATE TABLE team_task_folder_assignments (
            owner_id BIGINT NOT NULL,
            task_id TEXT NOT NULL REFERENCES scan_tasks(mp_task_id) ON DELETE CASCADE,
            folder_id UUID NOT NULL,
            PRIMARY KEY (owner_id, task_id),
            FOREIGN KEY (owner_id, folder_id) REFERENCES team_task_folders(owner_id, folder_id) ON DELETE CASCADE
        )
    """)
    op.execute("CREATE INDEX ix_team_task_folder_assignments_task ON team_task_folder_assignments (task_id)")


def downgrade() -> None:
    op.execute("DROP TABLE team_task_folder_assignments")
    op.execute("DROP TABLE team_task_folders")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN team_schedule_override")
