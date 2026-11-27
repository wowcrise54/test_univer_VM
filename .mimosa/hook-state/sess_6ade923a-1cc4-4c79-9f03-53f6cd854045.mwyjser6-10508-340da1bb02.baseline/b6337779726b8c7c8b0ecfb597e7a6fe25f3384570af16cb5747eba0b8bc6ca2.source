"""Add paged asset-card lookup indexes."""

from alembic import op


revision = "20260709_0003"
down_revision = "20260708_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_group_order "
        "ON asset_card_vulnerabilities(group_id, cve_name, name, id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_vulnerabilities_group_order")
