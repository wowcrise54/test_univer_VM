"""Rederive exploitation evidence from explicit, consistent JSON booleans."""

from alembic import op

from app.repositories.risk_evidence_schema import EVIDENCE_COLUMNS, FUNCTIONS_SQL

revision = "20261001_0025"
down_revision = "20260924_0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in FUNCTIONS_SQL:
        op.execute(statement)
    op.execute("ALTER TABLE vulnerability_passports DROP COLUMN IF EXISTS exploitation_evidence")
    op.execute("ALTER TABLE vulnerability_passports DROP COLUMN IF EXISTS exploitation_evidence_source")
    # Recomputes every legacy row and stays materialized on subsequent writes.
    for column in EVIDENCE_COLUMNS:
        op.execute(f"ALTER TABLE vulnerability_passports ADD COLUMN {column}")


def downgrade() -> None:
    op.execute("ALTER TABLE vulnerability_passports DROP COLUMN exploitation_evidence_source")
    op.execute("ALTER TABLE vulnerability_passports DROP COLUMN exploitation_evidence")
    op.execute("ALTER TABLE vulnerability_passports ADD COLUMN exploitation_evidence BOOLEAN GENERATED ALWAYS AS (LOWER(COALESCE(raw_detail_json, '') || COALESCE(metrics_json, '') || COALESCE(raw_record_json, '')) SIMILAR TO '%(exploit|exploited|эксплуат)%') STORED")
    op.execute("DROP FUNCTION risk_exploit_source(text,text,text)")
    op.execute("DROP FUNCTION risk_exploit_state(text,text,text)")
    op.execute("DROP FUNCTION risk_exploit_boolean(text)")
