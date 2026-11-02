"""Add a per-asset digest of the search field catalog.

Listing searchable fields aggregated the whole asset_card_search_fields table
(tens of millions of rows) on every request.
"""

from alembic import op

revision = "20261102_0030"
down_revision = "20261027_0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_card_search_field_catalog (
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            field_path TEXT NOT NULL,
            value_type TEXT NOT NULL,
            field_name TEXT NOT NULL,
            sample_value TEXT,
            PRIMARY KEY (asset_id, field_path, value_type)
        )
        """
    )
    op.execute("SET LOCAL statement_timeout = 0")
    op.execute(
        """
        INSERT INTO asset_card_search_field_catalog
            (asset_id, field_path, value_type, field_name, sample_value)
        SELECT asset_id, field_path, value_type, MIN(field_name),
               MIN(value_text) FILTER (WHERE value_text IS NOT NULL)
        FROM asset_card_search_fields
        GROUP BY asset_id, field_path, value_type
        ON CONFLICT DO NOTHING
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS asset_card_search_field_catalog")
