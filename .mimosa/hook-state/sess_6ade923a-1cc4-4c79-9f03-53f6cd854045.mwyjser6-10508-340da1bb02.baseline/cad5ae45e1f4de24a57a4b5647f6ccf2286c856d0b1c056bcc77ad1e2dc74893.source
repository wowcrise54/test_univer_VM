"""Add runbook automation, schedules, audit and notifications."""

import sqlalchemy as sa
from alembic import op

revision = "20260708_0002"
down_revision = "20260708_0001"
branch_labels = None
depends_on = None


STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS automation_runbooks (
        runbook_id TEXT PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        draft_json TEXT NOT NULL DEFAULT '{}',
        published_version INTEGER,
        allow_destructive BOOLEAN NOT NULL DEFAULT FALSE,
        approved_hash TEXT,
        approved_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS automation_runbook_versions (
        runbook_id TEXT NOT NULL REFERENCES automation_runbooks(runbook_id) ON DELETE CASCADE,
        version INTEGER NOT NULL,
        definition_json TEXT NOT NULL,
        definition_hash TEXT NOT NULL,
        destructive_approved BOOLEAN NOT NULL DEFAULT FALSE,
        published_at TEXT NOT NULL,
        PRIMARY KEY(runbook_id, version)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS automation_schedules (
        schedule_id TEXT PRIMARY KEY,
        runbook_id TEXT NOT NULL REFERENCES automation_runbooks(runbook_id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        timezone TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        next_run_at TEXT NOT NULL,
        last_scheduled_at TEXT,
        last_status TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS automation_runs (
        run_id TEXT PRIMARY KEY,
        runbook_id TEXT NOT NULL REFERENCES automation_runbooks(runbook_id) ON DELETE CASCADE,
        version INTEGER NOT NULL,
        schedule_id TEXT REFERENCES automation_schedules(schedule_id) ON DELETE SET NULL,
        trigger_type TEXT NOT NULL,
        scheduled_for TEXT,
        status TEXT NOT NULL,
        current_step INTEGER NOT NULL DEFAULT 0,
        dry_run BOOLEAN NOT NULL DEFAULT FALSE,
        definition_json TEXT NOT NULL,
        result_json TEXT NOT NULL DEFAULT '{}',
        error TEXT,
        cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
        idempotency_key TEXT UNIQUE,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS automation_run_steps (
        run_id TEXT NOT NULL REFERENCES automation_runs(run_id) ON DELETE CASCADE,
        step_index INTEGER NOT NULL,
        step_id TEXT NOT NULL,
        step_type TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        child_operation_id TEXT,
        input_json TEXT NOT NULL DEFAULT '{}',
        output_json TEXT NOT NULL DEFAULT '{}',
        error TEXT,
        started_at TEXT,
        finished_at TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(run_id, step_index)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS automation_audit_events (
        event_id TEXT PRIMARY KEY,
        runbook_id TEXT REFERENCES automation_runbooks(runbook_id) ON DELETE CASCADE,
        run_id TEXT REFERENCES automation_runs(run_id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id TEXT PRIMARY KEY,
        level TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        event_type TEXT NOT NULL,
        runbook_id TEXT,
        run_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}',
        is_read BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TEXT NOT NULL,
        read_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
        delivery_id TEXT PRIMARY KEY,
        notification_id TEXT NOT NULL REFERENCES notifications(notification_id) ON DELETE CASCADE,
        attempt INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        next_attempt_at TEXT,
        response_status INTEGER,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_automation_schedules_due ON automation_schedules(enabled, next_run_at)",
    "CREATE INDEX IF NOT EXISTS idx_automation_runs_runbook_status ON automation_runs(runbook_id, status, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_automation_runs_schedule ON automation_runs(schedule_id, scheduled_for)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(is_read, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries(status, next_attempt_at)",
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(sa.text(statement))


def downgrade() -> None:
    # Expand/contract policy: keep operator history when rolling application code back.
    pass
