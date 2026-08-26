"""Add locally evaluated asset groups."""

from alembic import op


revision = "20260826_0017"
down_revision = "20260825_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_groups (
            group_id UUID PRIMARY KEY,
            parent_id UUID REFERENCES asset_groups(group_id) ON DELETE SET NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            query_json TEXT NOT NULL,
            definition_version INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'stale',
            member_count INTEGER NOT NULL DEFAULT 0,
            indexed_cards INTEGER NOT NULL DEFAULT 0,
            total_cards INTEGER NOT NULL DEFAULT 0,
            last_evaluated_at TIMESTAMPTZ,
            last_error TEXT,
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            archived_at TIMESTAMPTZ
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_group_evaluations (
            evaluation_id UUID PRIMARY KEY,
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            definition_version INTEGER NOT NULL,
            status TEXT NOT NULL,
            matched_count INTEGER NOT NULL DEFAULT 0,
            indexed_cards INTEGER NOT NULL DEFAULT 0,
            total_cards INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at TIMESTAMPTZ
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_group_members (
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            evaluation_id UUID NOT NULL REFERENCES asset_group_evaluations(evaluation_id) ON DELETE CASCADE,
            membership_source TEXT NOT NULL DEFAULT 'rule',
            evidence_json TEXT NOT NULL DEFAULT '[]',
            evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (group_id, asset_id)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_group_overrides (
            group_id UUID NOT NULL REFERENCES asset_groups(group_id) ON DELETE CASCADE,
            asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
            action TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
            created_by TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (group_id, asset_id)
        )
        """
    )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_groups_parent_name ON asset_groups(COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), LOWER(name)) WHERE archived_at IS NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_asset_group_members_asset ON asset_group_members(asset_id, group_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_asset_group_evaluations_group_started ON asset_group_evaluations(group_id, started_at DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS asset_group_overrides")
    op.execute("DROP TABLE IF EXISTS asset_group_members")
    op.execute("DROP TABLE IF EXISTS asset_group_evaluations")
    op.execute("DROP TABLE IF EXISTS asset_groups")
