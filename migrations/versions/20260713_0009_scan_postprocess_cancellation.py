"""Add durable cancellation state to scan post-processing operations."""

from alembic import op


revision = "20260713_0009"
down_revision = "20260713_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE scan_postprocess_runs "
        "ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN NOT NULL DEFAULT FALSE"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scan_postprocess_runs DROP COLUMN IF EXISTS cancel_requested")
