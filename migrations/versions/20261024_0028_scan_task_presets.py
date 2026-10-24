from alembic import op


revision = "20261024_0028"
down_revision = "20261002_0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """CREATE TABLE scan_task_presets (
               preset_id UUID PRIMARY KEY,
               name VARCHAR(120) NOT NULL,
               description TEXT NOT NULL DEFAULT '',
               os_family TEXT NOT NULL CHECK (os_family IN ('windows', 'linux')),
               scope_id TEXT NOT NULL CHECK (length(btrim(scope_id)) > 0),
               profile_id TEXT NOT NULL CHECK (length(btrim(profile_id)) > 0),
               credential_id TEXT,
               credential_transport TEXT NOT NULL DEFAULT 'windows'
                   CHECK (credential_transport IN ('windows', 'ssh')),
               agent_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
               host_discovery_enabled BOOLEAN NOT NULL DEFAULT FALSE,
               host_discovery_profile_id TEXT,
               is_fqdn_priority BOOLEAN NOT NULL DEFAULT TRUE,
               time_zone TEXT NOT NULL DEFAULT '+05:00',
               trigger_parameters JSONB,
               denied_scan_settings JSONB,
               start_options JSONB NOT NULL DEFAULT '{}'::jsonb,
               allowed_asset_groups JSONB NOT NULL DEFAULT '[]'::jsonb,
               max_groups_per_task INTEGER NOT NULL DEFAULT 5 CHECK (max_groups_per_task BETWEEN 1 AND 100),
               max_active_tasks INTEGER CHECK (max_active_tasks IS NULL OR max_active_tasks >= 1),
               name_prefix VARCHAR(60) NOT NULL DEFAULT '',
               is_active BOOLEAN NOT NULL DEFAULT TRUE,
               version INTEGER NOT NULL DEFAULT 1,
               created_by TEXT,
               updated_by TEXT,
               created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
               CONSTRAINT ck_scan_task_presets_name_nonblank CHECK (length(btrim(name)) > 0)
           )"""
    )
    op.execute(
        "CREATE UNIQUE INDEX uq_scan_task_presets_active_name_ci "
        "ON scan_task_presets (lower(name)) WHERE is_active"
    )
    op.execute(
        """CREATE TABLE scan_task_preset_roles (
               preset_id UUID NOT NULL REFERENCES scan_task_presets(preset_id) ON DELETE CASCADE,
               role_id BIGINT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
               PRIMARY KEY (preset_id, role_id)
           )"""
    )
    op.execute("CREATE INDEX idx_scan_task_preset_roles_role ON scan_task_preset_roles (role_id, preset_id)")
    op.execute(
        "ALTER TABLE scan_tasks ADD COLUMN preset_id UUID "
        "REFERENCES scan_task_presets(preset_id) ON DELETE SET NULL"
    )
    op.execute("ALTER TABLE scan_tasks ADD COLUMN preset_version INTEGER")
    op.execute("ALTER TABLE scan_tasks ADD COLUMN created_by TEXT")
    # Groups chosen by the engineer; the MP VM payload may be narrowed by a precheck.
    op.execute("ALTER TABLE scan_tasks ADD COLUMN preset_asset_groups JSONB")
    op.execute("CREATE INDEX idx_scan_tasks_preset ON scan_tasks (preset_id) WHERE preset_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_scan_tasks_preset")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS preset_asset_groups")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS created_by")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS preset_version")
    op.execute("ALTER TABLE scan_tasks DROP COLUMN IF EXISTS preset_id")
    op.execute("DROP TABLE scan_task_preset_roles")
    op.execute("DROP TABLE scan_task_presets")
