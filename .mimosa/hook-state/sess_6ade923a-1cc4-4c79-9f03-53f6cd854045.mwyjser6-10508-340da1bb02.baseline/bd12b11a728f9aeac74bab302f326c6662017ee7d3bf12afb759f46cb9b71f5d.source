"""Materialize passport exploitation-evidence flag for fast risk queries."""

from alembic import op

revision = "20260910_0022"
down_revision = "20260908_0021"
branch_labels = None
depends_on = None

_EXPR = (
    "LOWER(COALESCE(raw_detail_json, '') || COALESCE(metrics_json, '') || COALESCE(raw_record_json, '')) "
    "SIMILAR TO '%(exploit|exploited|эксплуат)%'"
)


def upgrade() -> None:
    # Stored generated column: computed once per row change (not per risk query).
    # PostgreSQL re-derives it automatically whenever a base column is updated.
    op.execute(
        f"ALTER TABLE vulnerability_passports "
        f"ADD COLUMN IF NOT EXISTS exploitation_evidence BOOLEAN GENERATED ALWAYS AS ({_EXPR}) STORED"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE vulnerability_passports DROP COLUMN IF EXISTS exploitation_evidence")
