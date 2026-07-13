"""Add local application users, roles and revocable sessions."""

from alembic import op


revision = "20260713_0007"
down_revision = "20260713_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app_auth_sessions (
            id UUID PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            revoked_at TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_app_auth_sessions_user ON app_auth_sessions(user_id, expires_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_app_auth_sessions_token ON app_auth_sessions(token_hash) WHERE revoked_at IS NULL")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS app_auth_sessions")
    op.execute("DROP TABLE IF EXISTS app_users")
