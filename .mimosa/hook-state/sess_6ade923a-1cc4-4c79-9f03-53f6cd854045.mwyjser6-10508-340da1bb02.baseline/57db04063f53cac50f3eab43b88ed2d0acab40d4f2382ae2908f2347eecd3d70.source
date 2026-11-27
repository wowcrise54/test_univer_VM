"""Store the current MP VM trending-vulnerability snapshot."""

from alembic import op


revision = "20260724_0015"
down_revision = "20260724_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_passport_trends (
            passport_internal_id TEXT PRIMARY KEY
                REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
            description TEXT,
            is_trend_since TEXT,
            vendors_json TEXT NOT NULL DEFAULT '[]',
            affected_components_json TEXT NOT NULL DEFAULT '[]',
            source_pdql TEXT NOT NULL,
            pdql_token TEXT,
            synced_at TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vulnerability_passport_trends_since
        ON vulnerability_passport_trends(is_trend_since DESC, passport_internal_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS vulnerability_passport_trends")
