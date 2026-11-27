"""Expression index for the passport list score-desc sort.

``sort_by=score&sort_dir=desc`` on ``GET /api/vulnerability-passports/local``
currently runs a Parallel Seq Scan over all 500k rows of
``vulnerability_passports`` plus a top-N heapsort (measured 565 ms on the lab
database). This index lets PostgreSQL answer that order with a backward index
scan plus a bounded top-N fetch, on the same order of magnitude as the
0038 default-sort index (740 ms -> under 1 ms).

It does NOT cover ``sort_dir=asc``: an ascending score sort still takes a seq
scan. That direction is a rare, low-traffic case, so a second, mirror index
is deliberately not created.

The index expression is copied verbatim from the allowed-sort "score" entry in
``app/repositories/passports/catalog.py`` — PostgreSQL matches index
expressions textually, so the two definitions must stay in sync. Explicit
``NULLS LAST``/``NULLS FIRST`` modifiers are required in the index definition:
with an implicit NULLS modifier in the index the planner silently refuses the
index (observed on PostgreSQL 16).
"""

from alembic import op

revision = "20261110_0039"
down_revision = "20261110_0038"
branch_labels = None
depends_on = None

INDEX_NAME = "idx_vulnerability_passports_score_sort"

INDEX_SQL = f"""
CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME}
ON vulnerability_passports (
    (CASE WHEN REPLACE(COALESCE(score, ''), ',', '.') ~ '^[0-9]+([.][0-9]+)?$' THEN REPLACE(score, ',', '.')::numeric ELSE NULL END) DESC NULLS LAST,
    internal_id ASC NULLS FIRST
)
"""


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(INDEX_SQL)


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
