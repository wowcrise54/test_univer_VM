"""Index package applicability rules from local Wazuh CTI passports."""

from alembic import op

revision = "20261126_0041"
down_revision = "20261111_0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE wazuh_cti_package_rules (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            passport_id TEXT NOT NULL REFERENCES vulnerability_passports(internal_id) ON DELETE CASCADE,
            vendor TEXT NOT NULL,
            release TEXT NOT NULL,
            package_name TEXT NOT NULL,
            default_status TEXT NOT NULL,
            versions JSONB NOT NULL
        )
    """)
    op.execute("""
        CREATE INDEX idx_wazuh_cti_package_lookup
        ON wazuh_cti_package_rules (vendor, release, package_name)
    """)
    op.execute("CREATE INDEX idx_wazuh_cti_package_passport ON wazuh_cti_package_rules (passport_id)")


def downgrade() -> None:
    op.execute("DROP TABLE wazuh_cti_package_rules")
