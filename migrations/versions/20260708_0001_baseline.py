"""Establish the backward-compatible MP VM schema baseline."""

from alembic import op
import sqlalchemy as sa

from app.db import schema_statements


revision = "20260708_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in schema_statements():
        op.execute(sa.text(statement))


def downgrade() -> None:
    # Baseline adoption is intentionally non-destructive. Existing installations
    # can downgrade the application without dropping operator data.
    pass
