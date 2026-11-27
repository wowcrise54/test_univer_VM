from alembic import op


revision = "20261002_0027"
down_revision = "20261002_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE operations ADD COLUMN cleared_at TIMESTAMPTZ")
    op.execute("ALTER TABLE operations ADD COLUMN cleared_by TEXT")
    op.execute(
        "CREATE INDEX idx_operations_visible_created "
        "ON operations (created_at DESC) WHERE cleared_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX idx_operations_visible_created")
    op.execute("ALTER TABLE operations DROP COLUMN cleared_by")
    op.execute("ALTER TABLE operations DROP COLUMN cleared_at")
