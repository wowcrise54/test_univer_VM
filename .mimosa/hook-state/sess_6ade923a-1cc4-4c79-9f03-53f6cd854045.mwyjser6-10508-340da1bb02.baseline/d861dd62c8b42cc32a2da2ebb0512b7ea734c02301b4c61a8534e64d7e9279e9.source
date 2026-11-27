from alembic import op


revision = "20261002_0026"
down_revision = "20261001_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE scanner_task_folders (
               folder_id UUID PRIMARY KEY,
               name VARCHAR(120) NOT NULL,
               created_by TEXT,
               updated_by TEXT,
               created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               CONSTRAINT ck_scanner_task_folders_name_nonblank CHECK (length(btrim(name)) > 0)
           )"""
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_scanner_task_folders_name_ci "
        "ON scanner_task_folders (lower(name))"
    )
    op.execute(
        """CREATE TABLE scanner_task_folder_assignments (
               task_id TEXT PRIMARY KEY CHECK (length(btrim(task_id)) > 0),
               folder_id UUID NOT NULL REFERENCES scanner_task_folders(folder_id) ON DELETE CASCADE,
               updated_by TEXT,
               updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
           )"""
    )
    op.execute(
        "CREATE INDEX idx_scanner_task_folder_assignments_folder "
        "ON scanner_task_folder_assignments (folder_id, task_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE scanner_task_folder_assignments")
    op.execute("DROP TABLE scanner_task_folders")
