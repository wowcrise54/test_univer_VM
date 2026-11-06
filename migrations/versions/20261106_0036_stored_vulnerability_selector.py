"""Store the vulnerability selector instead of recomputing it for every row.

The dashboard groups, filters and joins findings by a "selector" (the identity
of a vulnerability across hosts). It was a large CASE expression over text
functions that every query re-evaluated for each finding, and its result could
not be indexed. It depends on the finding and on its group (source type and
name), so a generated column is impossible; a trigger keeps a plain column in
step instead:

* ``vulnerability_selector(...)`` is the single definition of the formula;
* a BEFORE trigger on findings fills ``selector`` for every writer (COPY, raw
  INSERT) and refreshes it when a source column changes;
* a trigger on groups refreshes the findings of a group whose source type or
  name changes (card saves replace groups today, so this is a safety net);
* existing rows are backfilled in short committed batches, then indexed.

The backfill rewrites every finding once. Run it off-peak on a large database:
with 1M findings expect a minute or two plus table and index bloat that
autovacuum removes afterwards.
"""

import sqlalchemy as sa
from alembic import op


revision = "20261106_0036"
down_revision = "20261105_0035"
branch_labels = None
depends_on = None

BACKFILL_BATCH = 20000

SELECTOR_FUNCTION = r"""
CREATE OR REPLACE FUNCTION vulnerability_selector(
    finding_vulnerability_id TEXT,
    finding_cve_name TEXT,
    finding_name TEXT,
    finding_instance_id TEXT,
    group_source_type TEXT,
    group_name TEXT
) RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN NULLIF(TRIM(finding_vulnerability_id), '') IS NOT NULL
            THEN 'id:' || TRIM(finding_vulnerability_id)
                || CASE WHEN group_source_type = 'docker'
                    THEN '|source:docker' ELSE '' END
        WHEN NULLIF(TRIM(finding_cve_name), '') IS NOT NULL
            THEN 'cve:' || UPPER(TRIM(finding_cve_name))
                || CASE WHEN group_source_type = 'docker'
                    THEN '|source:docker' ELSE '' END
        WHEN NULLIF(TRIM(finding_name), '') IS NOT NULL
            THEN 'name:' || LOWER(REGEXP_REPLACE(TRIM(finding_name), '\s+', ' ', 'g'))
                || '|source:' || group_source_type
                || '|object:' || LOWER(REGEXP_REPLACE(TRIM(COALESCE(group_name, '')), '\s+', ' ', 'g'))
        ELSE 'instance:' || TRIM(finding_instance_id)
    END
$$
"""

FINDING_TRIGGER_FUNCTION = """
CREATE OR REPLACE FUNCTION asset_card_vulnerability_selector_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    group_row RECORD;
BEGIN
    SELECT source_type, name INTO group_row
    FROM asset_card_vulnerability_groups WHERE id = NEW.group_id;
    NEW.selector := vulnerability_selector(
        NEW.vulnerability_id, NEW.cve_name, NEW.name, NEW.vulnerability_instance_id,
        group_row.source_type, group_row.name
    );
    RETURN NEW;
END
$$
"""

GROUP_TRIGGER_FUNCTION = """
CREATE OR REPLACE FUNCTION asset_card_vulnerability_group_selector_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE asset_card_vulnerabilities AS finding
    SET selector = vulnerability_selector(
        finding.vulnerability_id, finding.cve_name, finding.name, finding.vulnerability_instance_id,
        NEW.source_type, NEW.name
    )
    WHERE finding.group_id = NEW.id;
    RETURN NEW;
END
$$
"""


def upgrade() -> None:
    op.execute(SELECTOR_FUNCTION)
    op.execute("ALTER TABLE asset_card_vulnerabilities ADD COLUMN IF NOT EXISTS selector TEXT")
    op.execute(FINDING_TRIGGER_FUNCTION)
    op.execute("DROP TRIGGER IF EXISTS trg_asset_card_vulnerability_selector ON asset_card_vulnerabilities")
    op.execute(
        """
        CREATE TRIGGER trg_asset_card_vulnerability_selector
        BEFORE INSERT OR UPDATE OF vulnerability_id, cve_name, name, vulnerability_instance_id, group_id
        ON asset_card_vulnerabilities
        FOR EACH ROW EXECUTE FUNCTION asset_card_vulnerability_selector_sync()
        """
    )
    op.execute(GROUP_TRIGGER_FUNCTION)
    op.execute("DROP TRIGGER IF EXISTS trg_asset_card_vulnerability_group_selector ON asset_card_vulnerability_groups")
    op.execute(
        """
        CREATE TRIGGER trg_asset_card_vulnerability_group_selector
        AFTER UPDATE OF source_type, name ON asset_card_vulnerability_groups
        FOR EACH ROW
        WHEN (OLD.source_type IS DISTINCT FROM NEW.source_type OR OLD.name IS DISTINCT FROM NEW.name)
        EXECUTE FUNCTION asset_card_vulnerability_group_selector_sync()
        """
    )

    with op.get_context().autocommit_block():
        bind = op.get_bind()
        bounds = bind.execute(sa.text("SELECT MIN(id) AS low, MAX(id) AS high FROM asset_card_vulnerabilities")).one()
        if bounds.low is not None:
            low = bounds.low
            while low <= bounds.high:
                # Rows written after the triggers above already have a selector.
                bind.execute(
                    sa.text(
                        """
                        UPDATE asset_card_vulnerabilities AS finding
                        SET selector = vulnerability_selector(
                            finding.vulnerability_id, finding.cve_name, finding.name,
                            finding.vulnerability_instance_id, vulnerability_group.source_type,
                            vulnerability_group.name
                        )
                        FROM asset_card_vulnerability_groups AS vulnerability_group
                        WHERE vulnerability_group.id = finding.group_id
                          AND finding.id >= :low AND finding.id < :high
                          AND finding.selector IS NULL
                        """
                    ),
                    {"low": low, "high": low + BACKFILL_BATCH},
                )
                low += BACKFILL_BATCH
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_card_vulnerabilities_selector "
            "ON asset_card_vulnerabilities (selector, asset_id)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS idx_asset_card_vulnerabilities_selector")
    op.execute("DROP TRIGGER IF EXISTS trg_asset_card_vulnerability_group_selector ON asset_card_vulnerability_groups")
    op.execute("DROP FUNCTION IF EXISTS asset_card_vulnerability_group_selector_sync()")
    op.execute("DROP TRIGGER IF EXISTS trg_asset_card_vulnerability_selector ON asset_card_vulnerabilities")
    op.execute("DROP FUNCTION IF EXISTS asset_card_vulnerability_selector_sync()")
    op.execute("ALTER TABLE asset_card_vulnerabilities DROP COLUMN IF EXISTS selector")
    op.execute("DROP FUNCTION IF EXISTS vulnerability_selector(TEXT, TEXT, TEXT, TEXT, TEXT, TEXT)")
