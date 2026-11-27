"""Store background Wazuh assessments for asset cards."""

from alembic import op

revision = "20261127_0043"
down_revision = "20261126_0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE wazuh_asset_assessments (
            asset_id TEXT PRIMARY KEY REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            inventory_at TEXT NOT NULL,
            checked_at TIMESTAMPTZ NOT NULL,
            result JSONB NOT NULL
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE wazuh_asset_assessments")
