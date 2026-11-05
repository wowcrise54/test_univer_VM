"""Trigram indexes for the substring search boxes.

``ILIKE '%text%'`` cannot use a btree index, so the vulnerability dashboard
search and the passport catalog search scanned their whole tables. GIN
``gin_trgm_ops`` indexes serve these patterns (for search text of at least
three characters; shorter text still scans).

On a lab database with 1M findings and 80k passports the dashboard search
dropped from about 1 s to under 0.2 s and the passport search from 450 ms to
3 ms. The price is write cost: re-inserting 5000 findings of one host took about
twice as long with the three finding indexes, so only columns that the search
boxes really filter on are indexed.

The extension is a trusted one on PostgreSQL 13+, so the database owner can
create it; a role without that right makes this migration fail loudly instead of
leaving the search without indexes (the dashboard search is written to rely on
them).
"""

from alembic import op


revision = "20261105_0035"
down_revision = "20261105_0034"
branch_labels = None
depends_on = None


TRIGRAM_INDEXES = (
    ("idx_asset_card_vulnerabilities_vulnerability_id_trgm", "asset_card_vulnerabilities", "vulnerability_id"),
    ("idx_asset_card_vulnerabilities_cve_name_trgm", "asset_card_vulnerabilities", "cve_name"),
    ("idx_asset_card_vulnerabilities_name_trgm", "asset_card_vulnerabilities", "name"),
    ("idx_asset_card_vulnerability_groups_name_trgm", "asset_card_vulnerability_groups", "name"),
    ("idx_vulnerability_passports_internal_id_trgm", "vulnerability_passports", "internal_id"),
    ("idx_vulnerability_passports_external_id_trgm", "vulnerability_passports", "external_id"),
    ("idx_vulnerability_passports_name_trgm", "vulnerability_passports", "name"),
    ("idx_vulnerability_passports_package_id_trgm", "vulnerability_passports", "package_id"),
    ("idx_vulnerability_passports_package_version_trgm", "vulnerability_passports", "package_version"),
    ("idx_vulnerability_passports_cves_json_trgm", "vulnerability_passports", "cves_json"),
)


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    with op.get_context().autocommit_block():
        for name, table, column in TRIGRAM_INDEXES:
            op.execute(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {table} USING gin ({column} gin_trgm_ops)"
            )


def downgrade() -> None:
    # The extension stays: other databases objects or later migrations may use it.
    with op.get_context().autocommit_block():
        for name, _table, _column in reversed(TRIGRAM_INDEXES):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
