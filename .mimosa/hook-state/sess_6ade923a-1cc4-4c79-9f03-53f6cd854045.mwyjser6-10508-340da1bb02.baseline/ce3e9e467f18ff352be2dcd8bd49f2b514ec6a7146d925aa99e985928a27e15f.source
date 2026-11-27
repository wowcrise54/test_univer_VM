"""Store compact asset-card snapshots for change history."""

from alembic import op


revision = "20260901_0020"
down_revision = "20260831_0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_card_history (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            captured_at TEXT NOT NULL,
            quality_json TEXT NOT NULL DEFAULT '{}',
            changes_json TEXT NOT NULL DEFAULT '[]',
            summary_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_card_history_asset_time "
        "ON asset_card_history(asset_id, captured_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_history_asset_time")
    op.execute("DROP TABLE IF EXISTS asset_card_history")
