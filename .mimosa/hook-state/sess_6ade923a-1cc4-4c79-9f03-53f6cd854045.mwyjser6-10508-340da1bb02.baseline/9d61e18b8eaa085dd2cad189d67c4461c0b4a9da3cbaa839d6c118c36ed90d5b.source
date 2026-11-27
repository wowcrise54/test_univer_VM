"""Indexes behind the dashboard summary endpoints.

The VM overview walks the open remediation cases in attention order and the
coverage summary looks for truncated finding groups per asset; both used to
sort or scan the whole table.
"""

from alembic import op


revision = "20261104_0033"
down_revision = "20261103_0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_remediation_cases_open_attention
            ON remediation_cases (
                (CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END),
                due_at NULLS LAST
            )
            WHERE status IN ('open', 'in_progress')
            """
        )
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_card_vulnerability_groups_truncated
            ON asset_card_vulnerability_groups (asset_id)
            WHERE truncated
            """
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_asset_card_vulnerability_groups_truncated")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_remediation_cases_open_attention")
