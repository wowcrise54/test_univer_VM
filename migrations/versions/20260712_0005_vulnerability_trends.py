"""Add retained aggregate vulnerability history and an initial baseline."""

from alembic import op


revision = "20260712_0005"
down_revision = "20260711_0004"
branch_labels = None
depends_on = None


SNAPSHOT_AGGREGATES_SQL = r"""
WITH findings AS (
    SELECT
        CASE
            WHEN NULLIF(TRIM(finding.vulnerability_id), '') IS NOT NULL
                THEN 'id:' || TRIM(finding.vulnerability_id)
            WHEN NULLIF(TRIM(finding.cve_name), '') IS NOT NULL
                THEN 'cve:' || UPPER(TRIM(finding.cve_name))
            WHEN NULLIF(TRIM(finding.name), '') IS NOT NULL
                THEN 'name:' || LOWER(REGEXP_REPLACE(TRIM(finding.name), '\s+', ' ', 'g'))
                    || '|source:' || vulnerability_group.source_type
                    || '|object:' || LOWER(REGEXP_REPLACE(
                        TRIM(COALESCE(vulnerability_group.name, '')), '\s+', ' ', 'g'
                    ))
            ELSE 'instance:' || TRIM(finding.vulnerability_instance_id)
        END AS selector,
        finding.asset_id,
        finding.cve_name AS cve,
        CASE
            WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) IN (
                'critical', 'high', 'medium', 'low'
            ) THEN LOWER(TRIM(finding.severity))
            ELSE 'unknown'
        END AS severity,
        CASE
            WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) = 'critical' THEN 1
            WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) = 'high' THEN 2
            WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) = 'medium' THEN 3
            WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) = 'low' THEN 4
            ELSE 5
        END AS severity_rank
    FROM asset_card_vulnerabilities AS finding
    JOIN asset_card_vulnerability_groups AS vulnerability_group
        ON vulnerability_group.id = finding.group_id
    JOIN asset_cards AS card
        ON card.asset_id = finding.asset_id
    WHERE COALESCE(
        NULLIF(TRIM(finding.vulnerability_id), ''),
        NULLIF(TRIM(finding.cve_name), ''),
        NULLIF(TRIM(finding.name), ''),
        NULLIF(TRIM(finding.vulnerability_instance_id), '')
    ) IS NOT NULL
),
coverage AS (
    SELECT
        COUNT(DISTINCT card.asset_id) AS cards_total,
        (SELECT COUNT(DISTINCT asset_id) FROM findings) AS cards_with_findings,
        COUNT(DISTINCT vulnerability_group.id)
            FILTER (WHERE vulnerability_group.truncated) AS truncated_groups,
        MIN(card.last_seen) AS oldest_at,
        MAX(card.last_seen) AS freshest_at
    FROM asset_cards AS card
    LEFT JOIN asset_card_vulnerability_groups AS vulnerability_group
        ON vulnerability_group.asset_id = card.asset_id
),
vulnerability_rollup AS (
    SELECT selector, MIN(severity_rank) AS severity_rank
    FROM findings
    GROUP BY selector
),
totals AS (
    SELECT
        COUNT(DISTINCT asset_id) AS affected_hosts,
        COUNT(*) AS findings,
        COUNT(DISTINCT selector) AS unique_vulnerabilities,
        COUNT(DISTINCT UPPER(TRIM(cve)))
            FILTER (WHERE NULLIF(TRIM(cve), '') IS NOT NULL) AS unique_cves,
        COUNT(DISTINCT asset_id) FILTER (WHERE severity_rank <= 2) AS high_risk_hosts,
        (SELECT COUNT(*) FROM vulnerability_rollup WHERE severity_rank = 5)
            AS unrated_vulnerabilities
    FROM findings
),
severity_names(severity, severity_rank) AS (
    VALUES ('critical', 1), ('high', 2), ('medium', 3), ('low', 4), ('unknown', 5)
),
severity_rollup AS (
    SELECT
        severity,
        COUNT(*) AS findings,
        COUNT(DISTINCT asset_id) AS affected_hosts,
        COUNT(DISTINCT selector) AS unique_vulnerabilities
    FROM findings
    GROUP BY severity
),
inserted_snapshot AS (
    INSERT INTO vulnerability_aggregate_snapshots (
        scope, trigger_kind, trigger_id, captured_at,
        hosts_total, affected_hosts, findings, unique_vulnerabilities,
        unique_cves, high_risk_hosts, unrated_vulnerabilities,
        coverage_cards_total, coverage_cards_with_findings,
        coverage_truncated_groups, coverage_complete,
        coverage_oldest_at, coverage_freshest_at
    )
    SELECT
        'all_asset_cards', 'baseline', 'vulnerability-trends-v1', NOW(),
        coverage.cards_total, totals.affected_hosts, totals.findings,
        totals.unique_vulnerabilities, totals.unique_cves,
        totals.high_risk_hosts, totals.unrated_vulnerabilities,
        coverage.cards_total, coverage.cards_with_findings,
        coverage.truncated_groups, coverage.truncated_groups = 0,
        coverage.oldest_at, coverage.freshest_at
    FROM coverage CROSS JOIN totals
    ON CONFLICT (trigger_kind, trigger_id) DO NOTHING
    RETURNING id
)
INSERT INTO vulnerability_aggregate_snapshot_severity (
    snapshot_id, severity, findings, affected_hosts, unique_vulnerabilities
)
SELECT
    inserted_snapshot.id,
    severity_names.severity,
    COALESCE(severity_rollup.findings, 0),
    COALESCE(severity_rollup.affected_hosts, 0),
    COALESCE(severity_rollup.unique_vulnerabilities, 0)
FROM inserted_snapshot
CROSS JOIN severity_names
LEFT JOIN severity_rollup USING (severity)
ON CONFLICT (snapshot_id, severity) DO NOTHING
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_aggregate_snapshots (
            id BIGSERIAL PRIMARY KEY,
            scope TEXT NOT NULL DEFAULT 'all_asset_cards',
            trigger_kind TEXT NOT NULL,
            trigger_id TEXT NOT NULL,
            captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            hosts_total BIGINT NOT NULL DEFAULT 0 CHECK (hosts_total >= 0),
            affected_hosts BIGINT NOT NULL DEFAULT 0 CHECK (affected_hosts >= 0),
            findings BIGINT NOT NULL DEFAULT 0 CHECK (findings >= 0),
            unique_vulnerabilities BIGINT NOT NULL DEFAULT 0 CHECK (unique_vulnerabilities >= 0),
            unique_cves BIGINT NOT NULL DEFAULT 0 CHECK (unique_cves >= 0),
            high_risk_hosts BIGINT NOT NULL DEFAULT 0 CHECK (high_risk_hosts >= 0),
            unrated_vulnerabilities BIGINT NOT NULL DEFAULT 0 CHECK (unrated_vulnerabilities >= 0),
            coverage_cards_total BIGINT NOT NULL DEFAULT 0 CHECK (coverage_cards_total >= 0),
            coverage_cards_with_findings BIGINT NOT NULL DEFAULT 0
                CHECK (coverage_cards_with_findings >= 0),
            coverage_truncated_groups BIGINT NOT NULL DEFAULT 0
                CHECK (coverage_truncated_groups >= 0),
            coverage_complete BOOLEAN NOT NULL DEFAULT TRUE,
            coverage_oldest_at TEXT,
            coverage_freshest_at TEXT,
            UNIQUE (trigger_kind, trigger_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_aggregate_snapshot_severity (
            snapshot_id BIGINT NOT NULL
                REFERENCES vulnerability_aggregate_snapshots(id) ON DELETE CASCADE,
            severity TEXT NOT NULL
                CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
            findings BIGINT NOT NULL DEFAULT 0 CHECK (findings >= 0),
            affected_hosts BIGINT NOT NULL DEFAULT 0 CHECK (affected_hosts >= 0),
            unique_vulnerabilities BIGINT NOT NULL DEFAULT 0 CHECK (unique_vulnerabilities >= 0),
            PRIMARY KEY (snapshot_id, severity)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_vulnerability_aggregate_snapshots_scope_captured
        ON vulnerability_aggregate_snapshots(scope, captured_at DESC, id DESC)
        """
    )
    op.execute(SNAPSHOT_AGGREGATES_SQL)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS vulnerability_aggregate_snapshot_severity")
    op.execute("DROP TABLE IF EXISTS vulnerability_aggregate_snapshots")
