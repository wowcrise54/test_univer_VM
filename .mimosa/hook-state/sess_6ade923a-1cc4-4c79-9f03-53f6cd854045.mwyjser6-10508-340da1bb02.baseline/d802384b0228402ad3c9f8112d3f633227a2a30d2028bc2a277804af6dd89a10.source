"""Personal access tokens of the MCP endpoint.

A token belongs to a user, carries read scopes and an expiry, and is stored only
as a hash. Sessions opened for a token point back to it, so revoking the token
ends every session it opened.
"""

SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS app_mcp_tokens (
        id BIGSERIAL PRIMARY KEY,
        public_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        owner_user_id BIGINT NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
        secret_hash TEXT NOT NULL,
        scopes TEXT[] NOT NULL,
        ip_allowlist TEXT[] NOT NULL DEFAULT '{}',
        created_by_username TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        revoked_by_username TEXT,
        last_used_at TIMESTAMPTZ,
        last_used_ip TEXT,
        rotated_from BIGINT REFERENCES app_mcp_tokens(id) ON DELETE SET NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_app_mcp_tokens_owner ON app_mcp_tokens(owner_user_id)",
    "ALTER TABLE app_auth_sessions ADD COLUMN IF NOT EXISTS mcp_token_id BIGINT REFERENCES app_mcp_tokens(id) ON DELETE CASCADE",
    "ALTER TABLE app_auth_sessions ADD COLUMN IF NOT EXISTS permission_cap TEXT[]",
    "CREATE INDEX IF NOT EXISTS idx_app_auth_sessions_mcp_token ON app_auth_sessions(mcp_token_id) WHERE mcp_token_id IS NOT NULL",
)
