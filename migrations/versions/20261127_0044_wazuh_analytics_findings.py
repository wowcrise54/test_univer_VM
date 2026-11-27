"""Expose current Wazuh package findings to vulnerability analytics."""

from alembic import op

revision = "20261127_0044"
down_revision = "20261127_0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE VIEW wazuh_analytics_findings AS
        SELECT DISTINCT
            assessment.asset_id,
            'id:' || passport.internal_id AS selector,
            passport.internal_id AS passport_id,
            upper(trim(match->>'cve')) AS cve_name,
            COALESCE(NULLIF(passport.name, ''), upper(trim(match->>'cve'))) AS name,
            passport.severity,
            CASE WHEN passport.score ~ '^[0-9]+([.][0-9]+)?$'
                 THEN passport.score::numeric END AS cvss_score,
            concat_ws(' ', match->>'package', match->>'version') AS object_name,
            jsonb_build_array(assessment.asset_id, match->>'package', match->>'version')::text AS group_id,
            assessment.checked_at::text AS updated_at
        FROM wazuh_asset_assessments AS assessment
        JOIN asset_cards AS card
          ON card.asset_id = assessment.asset_id AND card.last_seen = assessment.inventory_at
        CROSS JOIN LATERAL jsonb_array_elements(assessment.result->'matches') AS match
        JOIN vulnerability_passports AS passport ON passport.internal_id = match->>'passport_id'
        WHERE NULLIF(trim(match->>'cve'), '') IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM asset_card_vulnerabilities AS existing
              WHERE existing.asset_id = assessment.asset_id
                AND upper(trim(existing.cve_name)) = upper(trim(match->>'cve'))
          )
    """)


def downgrade() -> None:
    op.execute("DROP VIEW wazuh_analytics_findings")
