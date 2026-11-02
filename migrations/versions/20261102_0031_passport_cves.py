"""Index the match data of vulnerability passports.

Matching findings to passports parsed cves_json of the whole catalog on every
asset card save. CVE names and OS family now live in tables kept by a trigger.
"""

from alembic import op

from app.repositories.passport_cve_schema import BACKFILL_SQL, SCHEMA_SQL

revision = "20261102_0031"
down_revision = "20261102_0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in SCHEMA_SQL:
        op.execute(statement)
    op.execute("SET LOCAL statement_timeout = 0")
    for statement in BACKFILL_SQL:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_vulnerability_passport_cves_sync ON vulnerability_passports")
    op.execute("DROP FUNCTION IF EXISTS vulnerability_passport_cves_sync()")
    op.execute("DROP TABLE IF EXISTS vulnerability_passport_cves")
