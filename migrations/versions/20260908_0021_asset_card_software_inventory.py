"""Materialize asset-card software rows for fast local queries."""

from alembic import op


revision = "20260908_0021"
down_revision = "20260901_0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE asset_cards
        ADD COLUMN IF NOT EXISTS software_inventory_updated_at TEXT
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_card_software_inventory (
            id BIGSERIAL PRIMARY KEY,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            entity_path TEXT NOT NULL,
            soft_name TEXT NOT NULL,
            soft_name_normalized TEXT NOT NULL,
            soft_version TEXT NOT NULL DEFAULT '',
            soft_version_normalized TEXT NOT NULL DEFAULT '',
            vendor TEXT,
            architecture TEXT,
            install_path TEXT,
            is_windows BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at TEXT NOT NULL,
            UNIQUE(asset_id, entity_path)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_card_software_name_version
        ON asset_card_software_inventory(
            is_windows,
            soft_name_normalized,
            soft_version_normalized,
            asset_id
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_card_software_name
        ON asset_card_software_inventory(soft_name_normalized, asset_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_card_software_name_version_prefix
        ON asset_card_software_inventory(
            is_windows,
            soft_name_normalized,
            soft_version_normalized text_pattern_ops,
            asset_id
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_card_software_asset
        ON asset_card_software_inventory(asset_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_asset_card_software_asset")
    op.execute("DROP INDEX IF EXISTS idx_asset_card_software_name_version_prefix")
    op.execute("DROP INDEX IF EXISTS idx_asset_card_software_name")
    op.execute("DROP INDEX IF EXISTS idx_asset_card_software_name_version")
    op.execute("DROP TABLE IF EXISTS asset_card_software_inventory")
    op.execute(
        "ALTER TABLE asset_cards "
        "DROP COLUMN IF EXISTS software_inventory_updated_at"
    )
