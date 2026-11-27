"""Skip CVE and OS-family rebuilds when a passport update leaves their inputs unchanged.

Loading passport details rewrites raw_detail_json only, yet the trigger deleted
and re-inserted the passport's CVE rows every time. The function now rebuilds
each table only when its own inputs changed.
"""

from alembic import op

from app.repositories.passport_cve_schema import FUNCTION_SQL

revision = "20261104_0033"
down_revision = "20261103_0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in FUNCTION_SQL:
        op.execute(statement)


def downgrade() -> None:
    # The previous function body only did extra work; its results are identical,
    # so the new function can stay in place.
    pass
