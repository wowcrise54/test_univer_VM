from alembic import op


revision = "20261027_0029"
down_revision = "20261024_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IP addresses, networks, ranges and FQDNs typed by the engineer; the MP VM
    # payload may be narrowed by a precheck.
    op.execute("ALTER TABLE scan_tasks ADD COLUMN preset_targets JSONB")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS preset_targets")
