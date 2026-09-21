"""Add indexes for vulnerability read-model pagination and passport lookup."""

from alembic import op

revision = "20260911_0023"
down_revision = "20260910_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The baseline schema (app.db.schema_statements) already creates this index
    # on fresh installs, so the migration must be idempotent to upgrade both
    # brand-new and previously-migrated databases without a DuplicateTable error.
    op.execute(
        """CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_passports_finding
           ON asset_card_vulnerability_passports (asset_vulnerability_id, passport_internal_id)"""
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_vulnerability_passports_finding")
