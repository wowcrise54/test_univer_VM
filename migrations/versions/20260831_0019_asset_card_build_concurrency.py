"""Allow up to four concurrent asset-card build jobs."""

from alembic import op


revision = "20260831_0019"
down_revision = "20260827_0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_build_jobs_single_active")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_card_build_jobs_active "
        "ON asset_card_build_jobs(status, asset_id) "
        "WHERE status IN ('queued', 'running', 'cancelling')"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_build_jobs_active")
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_card_build_jobs_single_active "
        "ON asset_card_build_jobs ((1)) "
        "WHERE status IN ('queued', 'running', 'cancelling')"
    )
