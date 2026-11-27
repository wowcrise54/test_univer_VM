"""Remove password reconfirmation state from application sessions."""

from alembic import op

revision = "20260721_0013"
down_revision = "20260715_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE app_auth_sessions DROP COLUMN IF EXISTS elevated_until")


def downgrade() -> None:
    op.execute("ALTER TABLE app_auth_sessions ADD COLUMN IF NOT EXISTS elevated_until TEXT")
