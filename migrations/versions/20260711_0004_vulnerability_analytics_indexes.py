"""Add indexes used by the vulnerability analytics dashboard."""

from alembic import op

revision = "20260711_0004"
down_revision = "20260709_0003"
branch_labels = None
depends_on = None


INDEXES = (
    (
        "idx_asset_card_vulnerabilities_cve_upper",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_cve_upper "
        "ON asset_card_vulnerabilities((UPPER(TRIM(cve_name))))",
    ),
    (
        "idx_asset_card_vulnerabilities_severity_lower",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerabilities_severity_lower "
        "ON asset_card_vulnerabilities((CASE "
        "WHEN LOWER(TRIM(COALESCE(severity, ''))) IN ('critical', 'high', 'medium', 'low') "
        "THEN LOWER(TRIM(severity)) ELSE 'unknown' END))",
    ),
    (
        "idx_asset_card_vulnerability_groups_source",
        "CREATE INDEX IF NOT EXISTS idx_asset_card_vulnerability_groups_source "
        "ON asset_card_vulnerability_groups(source_type)",
    ),
    (
        "idx_asset_cards_last_seen",
        "CREATE INDEX IF NOT EXISTS idx_asset_cards_last_seen ON asset_cards(last_seen DESC)",
    ),
)


def upgrade() -> None:
    for _name, statement in INDEXES:
        op.execute(statement)


def downgrade() -> None:
    for name, _statement in reversed(INDEXES):
        op.execute(f"DROP INDEX IF EXISTS {name}")
