"""Keep one automatically selected passport per vulnerability finding."""

from alembic import op


revision = "20260715_0012"
down_revision = "20260714_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older reconciliation linked every passport that mentioned the same CVE.
    # Keep its best known choice before enforcing the new one-to-one invariant.
    op.execute(
        """
        DELETE FROM asset_card_vulnerability_passports AS link
        USING (
            SELECT asset_vulnerability_id, passport_internal_id
            FROM (
                SELECT
                    asset_vulnerability_id,
                    passport_internal_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY asset_vulnerability_id
                        ORDER BY
                            CASE match_method
                                WHEN 'vulner_id' THEN 0
                                WHEN 'cve_os_version' THEN 1
                                WHEN 'cve_os' THEN 2
                                WHEN 'cve_generic' THEN 3
                                WHEN 'cve' THEN 4
                                ELSE 5
                            END,
                            linked_at DESC,
                            passport_internal_id
                    ) AS link_rank
                FROM asset_card_vulnerability_passports
            ) AS ranked
            WHERE link_rank > 1
        ) AS duplicate
        WHERE link.asset_vulnerability_id = duplicate.asset_vulnerability_id
          AND link.passport_internal_id = duplicate.passport_internal_id
        """
    )
    op.create_index(
        "uq_asset_card_vulnerability_passports_one_per_finding",
        "asset_card_vulnerability_passports",
        ["asset_vulnerability_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_asset_card_vulnerability_passports_one_per_finding",
        table_name="asset_card_vulnerability_passports",
    )
