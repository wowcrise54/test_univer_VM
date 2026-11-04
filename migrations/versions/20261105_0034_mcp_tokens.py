"""Add personal access tokens for the MCP endpoint.

Replaces the single shared MCP token: every client gets its own revocable token
with scopes and an expiry, and its requests run in a read-capped session of the
token owner.
"""

from alembic import op

from app.repositories.mcp_tokens_schema import SCHEMA_SQL

revision = "20261105_0034"
down_revision = "20261104_0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for statement in SCHEMA_SQL:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_app_auth_sessions_mcp_token")
    op.execute("ALTER TABLE app_auth_sessions DROP COLUMN IF EXISTS permission_cap")
    op.execute("ALTER TABLE app_auth_sessions DROP COLUMN IF EXISTS mcp_token_id")
    op.execute("DROP TABLE IF EXISTS app_mcp_tokens")
