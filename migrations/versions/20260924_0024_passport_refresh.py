"""Prevent concurrent full passport refreshes and index passport references."""

from alembic import op

revision = "20260924_0024"
down_revision = "20260911_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uq_active_passport_catalog_refresh
        ON operations (kind) WHERE kind = 'passport_catalog_refresh'
        AND status IN ('queued', 'running', 'cancelling')""")
    # PostgreSQL does not automatically index referencing columns. Without this,
    # every old passport deletion scans the entire remediation_cases table.
    op.execute("""CREATE INDEX IF NOT EXISTS idx_remediation_cases_passport_internal_id
        ON remediation_cases (passport_internal_id)""")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_remediation_cases_passport_internal_id")
    op.execute("DROP INDEX IF EXISTS uq_active_passport_catalog_refresh")
