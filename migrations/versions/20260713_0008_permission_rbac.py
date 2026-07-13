"""Replace single user roles with permission-based RBAC and audit."""

from alembic import op

from app.auth import BUILTIN_ROLE_NAMES, BUILTIN_ROLE_PERMISSIONS, PERMISSIONS

revision = "20260713_0008"
down_revision = "20260713_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE app_auth_sessions ADD COLUMN IF NOT EXISTS elevated_until TEXT")
    op.execute("""CREATE TABLE IF NOT EXISTS app_permissions (
        permission_key TEXT PRIMARY KEY, domain TEXT NOT NULL, action TEXT NOT NULL, description TEXT NOT NULL)""")
    op.execute("""CREATE TABLE IF NOT EXISTS app_roles (
        id BIGSERIAL PRIMARY KEY, role_key TEXT UNIQUE, name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '', is_system BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    op.execute("""CREATE TABLE IF NOT EXISTS app_role_permissions (
        role_id BIGINT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
        permission_key TEXT NOT NULL REFERENCES app_permissions(permission_key) ON DELETE CASCADE,
        PRIMARY KEY(role_id, permission_key))""")
    op.execute("""CREATE TABLE IF NOT EXISTS app_user_roles (
        user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        role_id BIGINT NOT NULL REFERENCES app_roles(id) ON DELETE RESTRICT,
        PRIMARY KEY(user_id, role_id))""")
    op.execute("""CREATE TABLE IF NOT EXISTS app_auth_identities (
        id BIGSERIAL PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
        user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL, UNIQUE(provider, subject))""")
    op.execute("""CREATE TABLE IF NOT EXISTS app_auth_audit_events (
        id BIGSERIAL PRIMARY KEY, actor_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
        actor_username TEXT, event_type TEXT NOT NULL, permission_key TEXT,
        decision TEXT NOT NULL CHECK(decision IN ('allow','deny')), target_type TEXT, target_id TEXT,
        ip_address TEXT, user_agent TEXT, trace_id TEXT, request_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_app_auth_audit_created ON app_auth_audit_events(created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_app_auth_audit_actor ON app_auth_audit_events(actor_user_id, created_at DESC)")
    quote = lambda value: str(value).replace("'", "''")
    for key, (domain, description) in PERMISSIONS.items():
        op.execute(f"""INSERT INTO app_permissions(permission_key,domain,action,description)
            VALUES('{quote(key)}','{quote(domain)}','{quote(key.split('.', 1)[1])}','{quote(description)}')
            ON CONFLICT(permission_key) DO UPDATE SET domain=EXCLUDED.domain,
            action=EXCLUDED.action,description=EXCLUDED.description""")
    for key in ("admin", "operator", "viewer"):
        op.execute(f"""INSERT INTO app_roles(role_key,name,description,is_system,created_at,updated_at)
            VALUES('{key}','{quote(BUILTIN_ROLE_NAMES[key])}','{quote(f'System role {key}')}',TRUE,NOW()::text,NOW()::text)
            ON CONFLICT(role_key) DO UPDATE SET name=EXCLUDED.name,is_system=TRUE,updated_at=EXCLUDED.updated_at""")
        for permission in BUILTIN_ROLE_PERMISSIONS[key]:
            op.execute(f"""INSERT INTO app_role_permissions(role_id,permission_key)
                SELECT id,'{quote(permission)}' FROM app_roles WHERE role_key='{key}' ON CONFLICT DO NOTHING""")
    op.execute("""DO $$ BEGIN
        IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='app_users' AND column_name='role') THEN
            EXECUTE 'INSERT INTO app_user_roles(user_id,role_id) SELECT users.id,roles.id FROM app_users users JOIN app_roles roles ON roles.role_key=users.role ON CONFLICT DO NOTHING';
            ALTER TABLE app_users DROP COLUMN role;
        END IF;
    END $$""")


def downgrade() -> None:
    op.execute("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS role TEXT")
    op.execute("""UPDATE app_users users SET role = COALESCE((
        SELECT roles.role_key FROM app_user_roles ur JOIN app_roles roles ON roles.id=ur.role_id
        WHERE ur.user_id=users.id AND roles.role_key IN ('admin','operator','viewer')
        ORDER BY CASE roles.role_key WHEN 'admin' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END LIMIT 1), 'viewer')""")
    op.execute("ALTER TABLE app_users ALTER COLUMN role SET NOT NULL")
    op.execute("DROP TABLE IF EXISTS app_auth_audit_events")
    op.execute("DROP TABLE IF EXISTS app_auth_identities")
    op.execute("DROP TABLE IF EXISTS app_user_roles")
    op.execute("DROP TABLE IF EXISTS app_role_permissions")
    op.execute("DROP TABLE IF EXISTS app_roles")
    op.execute("DROP TABLE IF EXISTS app_permissions")
    op.execute("ALTER TABLE app_auth_sessions DROP COLUMN IF EXISTS elevated_until")
