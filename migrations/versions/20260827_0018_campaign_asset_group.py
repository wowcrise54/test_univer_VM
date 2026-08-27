"""Link remediation campaigns to local asset groups."""

from alembic import op


revision = "20260827_0018"
down_revision = "20260826_0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE remediation_campaigns ADD COLUMN IF NOT EXISTS "
        "asset_group_id UUID REFERENCES asset_groups(group_id) ON DELETE SET NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_remediation_campaign_asset_group "
        "ON remediation_campaigns(asset_group_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_remediation_campaign_asset_group")
    op.execute("ALTER TABLE remediation_campaigns DROP COLUMN IF EXISTS asset_group_id")
