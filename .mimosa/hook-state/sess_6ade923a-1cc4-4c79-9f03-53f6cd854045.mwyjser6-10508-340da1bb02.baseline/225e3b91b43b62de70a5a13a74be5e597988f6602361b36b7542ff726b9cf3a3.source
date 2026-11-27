"""Add asset context, local risk scoring and remediation campaigns."""

from alembic import op

revision = "20260713_0010"
down_revision = "20260713_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE IF NOT EXISTS asset_contexts (
        asset_id TEXT PRIMARY KEY REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
        criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
        environment TEXT NOT NULL DEFAULT 'production' CHECK (environment IN ('production','test','development')),
        exposure TEXT NOT NULL DEFAULT 'internal' CHECK (exposure IN ('external','internal','isolated')),
        owner TEXT, tags JSONB NOT NULL DEFAULT '[]'::jsonb,
        version INTEGER NOT NULL DEFAULT 1, updated_by TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    op.execute("""CREATE TABLE IF NOT EXISTS asset_context_events (
        event_id BIGSERIAL PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES asset_cards(asset_id) ON DELETE CASCADE,
        actor_username TEXT, changes_json JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    op.execute("""CREATE TABLE IF NOT EXISTS remediation_campaigns (
        campaign_id UUID PRIMARY KEY, name TEXT NOT NULL, assignee TEXT, due_at TIMESTAMPTZ, comment TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft','active','completed','cancelled')),
        created_by TEXT, version INTEGER NOT NULL DEFAULT 1, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    op.execute("""CREATE TABLE IF NOT EXISTS remediation_campaign_cases (
        campaign_id UUID NOT NULL REFERENCES remediation_campaigns(campaign_id) ON DELETE CASCADE,
        case_id TEXT NOT NULL REFERENCES remediation_cases(case_id) ON DELETE CASCADE,
        added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(campaign_id,case_id))""")
    op.execute("""CREATE TABLE IF NOT EXISTS remediation_campaign_events (
        event_id BIGSERIAL PRIMARY KEY, campaign_id UUID NOT NULL REFERENCES remediation_campaigns(campaign_id) ON DELETE CASCADE,
        actor_username TEXT, event_type TEXT NOT NULL, changes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_asset_context_filter ON asset_contexts(criticality,environment,exposure,owner)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_campaign_cases_case ON remediation_campaign_cases(case_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS remediation_campaign_events")
    op.execute("DROP TABLE IF EXISTS remediation_campaign_cases")
    op.execute("DROP TABLE IF EXISTS remediation_campaigns")
    op.execute("DROP TABLE IF EXISTS asset_context_events")
    op.execute("DROP TABLE IF EXISTS asset_contexts")
