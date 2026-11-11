"""Expression index for the default passport list ORDER BY.

The default sort of ``GET /api/vulnerability-passports/local`` is
``(severity rank, score DESC NULLS LAST, name NULLS LAST, internal_id)``.
Without an index matching those exact expressions PostgreSQL sorted all
500k rows of ``vulnerability_passports`` on every page request. Measured on a
500k-row lab database: the default sort dropped from about 740 ms to under 1 ms,
the filtered variants (severity, short/long q) from 570/990 ms to 4-60 ms, and
the per-request ``COUNT(*)`` from about 250 ms to 26 ms (narrow index).

The index expressions are copied verbatim from the default ``order_sql`` in
``app/repositories/passports/catalog.py`` — PostgreSQL matches index
expressions textually, so the two definitions must stay in sync. Explicit
``NULLS LAST`` is required in the index definition: with a NULLS-modifier in
the ORDER BY but an implicit one in the index the planner silently refuses
the index (observed on PostgreSQL 16).
"""

from alembic import op

revision = "20261110_0038"
down_revision = "20261106_0037"
branch_labels = None
depends_on = None

INDEX_NAME = "idx_vulnerability_passports_default_sort"

INDEX_SQL = f"""
CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME}
ON vulnerability_passports (
    (CASE LOWER(COALESCE(severity, '')) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'none' THEN 5 ELSE 6 END),
    (CASE WHEN REPLACE(COALESCE(score, ''), ',', '.') ~ '^[0-9]+([.][0-9]+)?$' THEN REPLACE(score, ',', '.')::numeric ELSE NULL END) DESC NULLS LAST,
    name NULLS LAST,
    internal_id
)
"""


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(INDEX_SQL)


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
