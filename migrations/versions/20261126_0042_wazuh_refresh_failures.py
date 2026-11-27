"""Persist final Wazuh CTI refresh errors by operation and CVE."""

from alembic import op

revision = "20261126_0042"
down_revision = "20261126_0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE wazuh_cti_refresh_failures (
            operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE CASCADE,
            passport_id TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            attempts INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY (operation_id, passport_id)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE wazuh_cti_refresh_failures")
