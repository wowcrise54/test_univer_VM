"""Per-vulnerability and per-host rollups, kept exact by triggers.

The dashboard groups every finding on each request: the list by selector (11 s
for 1M findings) and the summary by host, severity and selector (23 s). Two
tables hold those aggregates so both become indexed reads:

* ``vulnerability_rollup`` - one row per selector (hosts, findings, severity,
  components, CVE names ...);
* ``vulnerability_host_rollup`` - one row per host (findings by severity,
  distinct vulnerabilities, sources ...).

Both are maintained inside the writing transaction, so they are never stale:

* ``vulnerability_rollup_source`` and ``vulnerability_host_rollup_source`` are
  the single definitions of the aggregates;
* ``refresh_vulnerability_rollup(selectors)`` and
  ``refresh_vulnerability_host_rollup(assets)`` rebuild just those rows from the
  findings through the selector and asset indexes (about 30 ms for one host);
* statement-level triggers with transition tables call them for the selectors
  and hosts a statement touched, whatever wrote them (COPY, raw SQL, cascades
  from a deleted group or card);
* writers are serialised by an advisory lock, which card saves already hold
  through the passport write lock, so concurrent saves cannot overwrite each
  other's rows.

Only data that comes from findings and their groups is stored. Host-level
values that change independently (``asset_cards.last_seen``, display names) are
read live for the rows being shown.
"""

from alembic import op


revision = "20261106_0037"
down_revision = "20261106_0036"
branch_labels = None
depends_on = None

# Distinct from the passport write lock (1297106509, 1448301139).
ROLLUP_LOCK = "1297106509, 1380009036"

SELECTOR_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_rollup (
    selector TEXT PRIMARY KEY,
    vulnerability_id TEXT,
    cve TEXT,
    name TEXT,
    severity_rank SMALLINT NOT NULL,
    cvss_score NUMERIC,
    affected_hosts INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    affected_objects INTEGER NOT NULL,
    components TEXT[],
    sources TEXT[] NOT NULL,
    docker_containers TEXT[],
    docker_images TEXT[],
    severity_ranks SMALLINT[] NOT NULL,
    cves TEXT[]
)
"""

HOST_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_host_rollup (
    asset_id TEXT PRIMARY KEY,
    findings INTEGER NOT NULL,
    unique_vulnerabilities INTEGER NOT NULL,
    high_risk_vulnerabilities INTEGER NOT NULL,
    severity_rank SMALLINT NOT NULL,
    cvss_score NUMERIC,
    sources TEXT[] NOT NULL,
    findings_critical INTEGER NOT NULL,
    findings_high INTEGER NOT NULL,
    findings_medium INTEGER NOT NULL,
    findings_low INTEGER NOT NULL,
    findings_unknown INTEGER NOT NULL
)
"""

# Severity rank of one finding: critical 1 ... low 4, anything else 5.
RANK_SQL = (
    "CASE CASE WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) IN ('critical', 'high', 'medium', 'low') "
    "THEN LOWER(TRIM(finding.severity)) ELSE 'unknown' END "
    "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
)

CONTAINER_NAME_SQL = """CASE
            WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                NULLIF(finding.vulnerability_json::jsonb ->> 'container_name', ''),
                NULLIF(finding.vulnerability_json::jsonb #>> '{docker_container,container_name}', ''),
                NULLIF(vulnerability_group.group_json::jsonb ->> 'container_name', ''),
                NULLIF(vulnerability_group.name, '')
            )
        END"""

IMAGE_NAME_SQL = """CASE
            WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                NULLIF(finding.vulnerability_json::jsonb #>> '{docker_image,image_name}', ''),
                NULLIF(vulnerability_group.group_json::jsonb ->> 'image_name', ''),
                NULLIF(finding.vulnerability_json::jsonb ->> 'image_id', ''),
                NULLIF(finding.vulnerability_json::jsonb #>> '{docker_image,image_key}', '')
            )
        END"""

VALID_FINDING_SQL = """COALESCE(
    NULLIF(TRIM(finding.vulnerability_id), ''),
    NULLIF(TRIM(finding.cve_name), ''),
    NULLIF(TRIM(finding.name), ''),
    NULLIF(TRIM(finding.vulnerability_instance_id), '')
) IS NOT NULL"""

SELECTOR_VIEW_SQL = f"""
CREATE OR REPLACE VIEW vulnerability_rollup_source AS
SELECT
    finding.selector,
    MAX(NULLIF(finding.vulnerability_id, '')) AS vulnerability_id,
    MAX(NULLIF(finding.cve_name, '')) AS cve,
    MAX(NULLIF(finding.name, '')) AS name,
    MIN({RANK_SQL})::smallint AS severity_rank,
    MAX(finding.cvss_score) AS cvss_score,
    COUNT(DISTINCT finding.asset_id)::integer AS affected_hosts,
    COUNT(*)::integer AS findings,
    COUNT(DISTINCT vulnerability_group.id)::integer AS affected_objects,
    ARRAY_AGG(DISTINCT vulnerability_group.name ORDER BY vulnerability_group.name)
        FILTER (WHERE NULLIF(vulnerability_group.name, '') IS NOT NULL) AS components,
    ARRAY_AGG(DISTINCT vulnerability_group.source_type ORDER BY vulnerability_group.source_type) AS sources,
    ARRAY_AGG(DISTINCT {CONTAINER_NAME_SQL} ORDER BY {CONTAINER_NAME_SQL})
        FILTER (WHERE {CONTAINER_NAME_SQL} IS NOT NULL) AS docker_containers,
    ARRAY_AGG(DISTINCT {IMAGE_NAME_SQL} ORDER BY {IMAGE_NAME_SQL})
        FILTER (WHERE {IMAGE_NAME_SQL} IS NOT NULL) AS docker_images,
    ARRAY_AGG(DISTINCT {RANK_SQL}::smallint ORDER BY {RANK_SQL}::smallint) AS severity_ranks,
    ARRAY_AGG(DISTINCT UPPER(TRIM(finding.cve_name)) ORDER BY UPPER(TRIM(finding.cve_name)))
        FILTER (WHERE NULLIF(TRIM(finding.cve_name), '') IS NOT NULL) AS cves
FROM asset_card_vulnerabilities AS finding
JOIN asset_card_vulnerability_groups AS vulnerability_group ON vulnerability_group.id = finding.group_id
WHERE {VALID_FINDING_SQL}
GROUP BY finding.selector
"""

HOST_VIEW_SQL = f"""
CREATE OR REPLACE VIEW vulnerability_host_rollup_source AS
SELECT
    ranked.asset_id,
    COUNT(*)::integer AS findings,
    COUNT(DISTINCT ranked.selector)::integer AS unique_vulnerabilities,
    (COUNT(DISTINCT ranked.selector) FILTER (WHERE ranked.severity_rank <= 2))::integer
        AS high_risk_vulnerabilities,
    MIN(ranked.severity_rank)::smallint AS severity_rank,
    MAX(ranked.cvss_score) AS cvss_score,
    ARRAY_AGG(DISTINCT ranked.source_type ORDER BY ranked.source_type) AS sources,
    (COUNT(*) FILTER (WHERE ranked.severity_rank = 1))::integer AS findings_critical,
    (COUNT(*) FILTER (WHERE ranked.severity_rank = 2))::integer AS findings_high,
    (COUNT(*) FILTER (WHERE ranked.severity_rank = 3))::integer AS findings_medium,
    (COUNT(*) FILTER (WHERE ranked.severity_rank = 4))::integer AS findings_low,
    (COUNT(*) FILTER (WHERE ranked.severity_rank = 5))::integer AS findings_unknown
FROM (
    SELECT
        finding.asset_id,
        finding.selector,
        finding.cvss_score,
        vulnerability_group.source_type,
        {RANK_SQL} AS severity_rank
    FROM asset_card_vulnerabilities AS finding
    JOIN asset_card_vulnerability_groups AS vulnerability_group ON vulnerability_group.id = finding.group_id
    WHERE {VALID_FINDING_SQL}
) AS ranked
GROUP BY ranked.asset_id
"""

SELECTOR_COLUMNS = (
    "selector, vulnerability_id, cve, name, severity_rank, cvss_score, affected_hosts, findings, "
    "affected_objects, components, sources, docker_containers, docker_images, severity_ranks, cves"
)
HOST_COLUMNS = (
    "asset_id, findings, unique_vulnerabilities, high_risk_vulnerabilities, severity_rank, cvss_score, "
    "sources, findings_critical, findings_high, findings_medium, findings_low, findings_unknown"
)

REFRESH_SELECTOR_FUNCTION = f"""
CREATE OR REPLACE FUNCTION refresh_vulnerability_rollup(target_selectors TEXT[]) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM vulnerability_rollup WHERE selector = ANY(target_selectors);
    INSERT INTO vulnerability_rollup ({SELECTOR_COLUMNS})
    SELECT {SELECTOR_COLUMNS} FROM vulnerability_rollup_source WHERE selector = ANY(target_selectors);
END
$$
"""

REFRESH_HOST_FUNCTION = f"""
CREATE OR REPLACE FUNCTION refresh_vulnerability_host_rollup(target_assets TEXT[]) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM vulnerability_host_rollup WHERE asset_id = ANY(target_assets);
    INSERT INTO vulnerability_host_rollup ({HOST_COLUMNS})
    SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup_source WHERE asset_id = ANY(target_assets);
END
$$
"""

SYNC_FUNCTION = f"""
CREATE OR REPLACE FUNCTION vulnerability_rollup_sync() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    affected_selectors TEXT[];
    affected_assets TEXT[];
BEGIN
    PERFORM pg_advisory_xact_lock({ROLLUP_LOCK});
    IF TG_OP = 'INSERT' THEN
        SELECT ARRAY_AGG(DISTINCT selector) FILTER (WHERE selector IS NOT NULL), ARRAY_AGG(DISTINCT asset_id)
        INTO affected_selectors, affected_assets FROM new_rows;
    ELSIF TG_OP = 'DELETE' THEN
        SELECT ARRAY_AGG(DISTINCT selector) FILTER (WHERE selector IS NOT NULL), ARRAY_AGG(DISTINCT asset_id)
        INTO affected_selectors, affected_assets FROM old_rows;
    ELSE
        SELECT ARRAY_AGG(DISTINCT changed.selector) FILTER (WHERE changed.selector IS NOT NULL),
               ARRAY_AGG(DISTINCT changed.asset_id)
        INTO affected_selectors, affected_assets
        FROM (
            SELECT selector, asset_id FROM old_rows UNION SELECT selector, asset_id FROM new_rows
        ) AS changed;
    END IF;
    IF affected_selectors IS NOT NULL THEN
        PERFORM refresh_vulnerability_rollup(affected_selectors);
    END IF;
    IF affected_assets IS NOT NULL THEN
        PERFORM refresh_vulnerability_host_rollup(affected_assets);
    END IF;
    RETURN NULL;
END
$$
"""

TRIGGERS = (
    ("trg_vulnerability_rollup_insert", "INSERT", "REFERENCING NEW TABLE AS new_rows"),
    ("trg_vulnerability_rollup_delete", "DELETE", "REFERENCING OLD TABLE AS old_rows"),
    ("trg_vulnerability_rollup_update", "UPDATE", "REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows"),
)


def upgrade() -> None:
    op.execute(SELECTOR_TABLE_SQL)
    op.execute(HOST_TABLE_SQL)
    op.execute(SELECTOR_VIEW_SQL)
    op.execute(HOST_VIEW_SQL)
    op.execute(REFRESH_SELECTOR_FUNCTION)
    op.execute(REFRESH_HOST_FUNCTION)
    op.execute(SYNC_FUNCTION)
    # Writers wait here until the backfill is done, so none of their changes is lost.
    op.execute(f"SELECT pg_advisory_xact_lock({ROLLUP_LOCK})")
    for name, event, referencing in TRIGGERS:
        op.execute(f"DROP TRIGGER IF EXISTS {name} ON asset_card_vulnerabilities")
        op.execute(
            f"CREATE TRIGGER {name} AFTER {event} ON asset_card_vulnerabilities "
            f"{referencing} FOR EACH STATEMENT EXECUTE FUNCTION vulnerability_rollup_sync()"
        )
    op.execute("DELETE FROM vulnerability_rollup")
    op.execute(
        f"INSERT INTO vulnerability_rollup ({SELECTOR_COLUMNS}) "
        f"SELECT {SELECTOR_COLUMNS} FROM vulnerability_rollup_source"
    )
    op.execute("DELETE FROM vulnerability_host_rollup")
    op.execute(
        f"INSERT INTO vulnerability_host_rollup ({HOST_COLUMNS}) "
        f"SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup_source"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_rollup_default_order "
        "ON vulnerability_rollup (affected_hosts DESC, findings DESC, selector)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulnerability_host_rollup_top "
        "ON vulnerability_host_rollup (findings DESC, high_risk_vulnerabilities DESC, "
        "unique_vulnerabilities DESC, asset_id)"
    )


def downgrade() -> None:
    for name, _event, _referencing in reversed(TRIGGERS):
        op.execute(f"DROP TRIGGER IF EXISTS {name} ON asset_card_vulnerabilities")
    op.execute("DROP FUNCTION IF EXISTS vulnerability_rollup_sync()")
    op.execute("DROP FUNCTION IF EXISTS refresh_vulnerability_host_rollup(TEXT[])")
    op.execute("DROP FUNCTION IF EXISTS refresh_vulnerability_rollup(TEXT[])")
    op.execute("DROP VIEW IF EXISTS vulnerability_host_rollup_source")
    op.execute("DROP VIEW IF EXISTS vulnerability_rollup_source")
    op.execute("DROP TABLE IF EXISTS vulnerability_host_rollup")
    op.execute("DROP TABLE IF EXISTS vulnerability_rollup")
