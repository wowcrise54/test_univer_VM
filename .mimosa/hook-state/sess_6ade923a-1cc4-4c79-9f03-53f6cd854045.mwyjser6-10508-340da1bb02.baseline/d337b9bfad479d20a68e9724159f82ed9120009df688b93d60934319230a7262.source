"""Retain completed scanner evidence for compliance reporting."""

from alembic import op


revision = "20260825_0016"
down_revision = "20260724_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_scan_evidence (
            asset_id TEXT PRIMARY KEY REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            postprocess_run_id TEXT NOT NULL,
            mp_task_id TEXT NOT NULL,
            scanned_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_asset_scan_evidence_scanned_at
        ON asset_scan_evidence(scanned_at DESC)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS asset_scan_evidence")
