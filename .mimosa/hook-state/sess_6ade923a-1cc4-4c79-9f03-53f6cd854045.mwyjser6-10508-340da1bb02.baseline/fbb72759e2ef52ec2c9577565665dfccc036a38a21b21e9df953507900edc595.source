"""Add indexes for remediation resolution reporting."""

from alembic import op


revision = "20260724_0014"
down_revision = "20260721_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_remediation_cases_resolved_at
            ON remediation_cases(resolved_at DESC)
            WHERE status = 'resolved'
            """
        )
        op.execute(
            """
            CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_remediation_case_events_resolution
            ON remediation_case_events(created_at DESC, case_id)
            WHERE event_type = 'finding_absent'
            """
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS idx_remediation_case_events_resolution"
        )
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS idx_remediation_cases_resolved_at"
        )
