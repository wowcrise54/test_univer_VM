"""Add vulnerability remediation cases, SLA policy and immutable audit."""

from alembic import op


revision = "20260713_0006"
down_revision = "20260712_0005"
branch_labels = None
depends_on = None


SELECTOR_SQL = r"""
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
END
""".strip()


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_sla_policy (
            policy_id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (policy_id = 1),
            critical_days INTEGER NOT NULL DEFAULT 7 CHECK (critical_days > 0),
            high_days INTEGER NOT NULL DEFAULT 30 CHECK (high_days > 0),
            medium_days INTEGER NOT NULL DEFAULT 90 CHECK (medium_days > 0),
            low_days INTEGER NOT NULL DEFAULT 180 CHECK (low_days > 0),
            near_due_days INTEGER NOT NULL DEFAULT 7 CHECK (near_due_days >= 0),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        INSERT INTO remediation_sla_policy (policy_id) VALUES (1)
        ON CONFLICT (policy_id) DO NOTHING
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_cases (
            case_id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            vulnerability_key TEXT NOT NULL,
            title TEXT,
            cve TEXT,
            severity TEXT NOT NULL DEFAULT 'unknown'
                CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
            cvss_score NUMERIC,
            passport_internal_id TEXT REFERENCES vulnerability_passports(internal_id) ON DELETE SET NULL,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'in_progress', 'risk_accepted', 'false_positive', 'resolved')),
            assignee TEXT,
            due_at TIMESTAMPTZ,
            manual_due BOOLEAN NOT NULL DEFAULT FALSE,
            risk_reason TEXT,
            risk_expires_at TIMESTAMPTZ,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            reopened_at TIMESTAMPTZ,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (asset_id, vulnerability_key)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_case_events (
            event_id BIGSERIAL PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES remediation_cases(case_id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT,
            changes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
            comment TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_remediation_cases_queue
        ON remediation_cases(status, due_at, severity, first_seen_at)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_remediation_cases_asset
        ON remediation_cases(asset_id, status)
        """
    )
    op.execute(
        f"""
        WITH normalized AS (
            SELECT DISTINCT ON (finding.asset_id, {SELECTOR_SQL})
                finding.asset_id,
                {SELECTOR_SQL} AS vulnerability_key,
                finding.name,
                finding.cve_name,
                CASE WHEN LOWER(TRIM(COALESCE(finding.severity, ''))) IN
                    ('critical', 'high', 'medium', 'low')
                    THEN LOWER(TRIM(finding.severity)) ELSE 'unknown' END AS severity,
                finding.cvss_score,
                link.passport_internal_id
            FROM asset_card_vulnerabilities finding
            JOIN asset_card_vulnerability_groups vulnerability_group ON vulnerability_group.id = finding.group_id
            LEFT JOIN asset_card_vulnerability_passports link ON link.asset_vulnerability_id = finding.id
            WHERE COALESCE(NULLIF(TRIM(finding.vulnerability_id), ''), NULLIF(TRIM(finding.cve_name), ''),
                NULLIF(TRIM(finding.name), ''), NULLIF(TRIM(finding.vulnerability_instance_id), '')) IS NOT NULL
            ORDER BY finding.asset_id, {SELECTOR_SQL}, finding.cvss_score DESC NULLS LAST, link.passport_internal_id
        )
        INSERT INTO remediation_cases (
            case_id, asset_id, vulnerability_key, title, cve, severity, cvss_score,
            passport_internal_id, due_at
        )
        SELECT md5(asset_id || chr(31) || vulnerability_key), asset_id, vulnerability_key,
            name, cve_name, severity, cvss_score, passport_internal_id,
            CASE severity
                WHEN 'critical' THEN NOW() + INTERVAL '7 days'
                WHEN 'high' THEN NOW() + INTERVAL '30 days'
                WHEN 'medium' THEN NOW() + INTERVAL '90 days'
                WHEN 'low' THEN NOW() + INTERVAL '180 days'
            END
        FROM normalized
        ON CONFLICT (asset_id, vulnerability_key) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO remediation_case_events(case_id,event_type,new_status,changes_json)
        SELECT c.case_id,'finding_created','open','{"source":"migration"}'::jsonb
        FROM remediation_cases c
        WHERE NOT EXISTS (SELECT 1 FROM remediation_case_events e WHERE e.case_id=c.case_id)
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS remediation_case_events")
    op.execute("DROP TABLE IF EXISTS remediation_cases")
    op.execute("DROP TABLE IF EXISTS remediation_sla_policy")
