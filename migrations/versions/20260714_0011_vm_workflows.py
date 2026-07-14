"""Add durable VM workflow orchestration and verification metadata."""

from alembic import op

revision = "20260714_0011"
down_revision = "20260713_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""CREATE TABLE IF NOT EXISTS vm_workflow_runs (
        workflow_id UUID PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('scan','verification')),
        status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
          ('queued','running','cancelling','completed','completed_with_errors','failed','cancelled')),
        stage TEXT NOT NULL DEFAULT 'queued', progress_percent INTEGER NOT NULL DEFAULT 0
          CHECK (progress_percent BETWEEN 0 AND 100),
        task_id TEXT, campaign_id UUID REFERENCES remediation_campaigns(campaign_id) ON DELETE SET NULL,
        operation_id TEXT, retry_of UUID REFERENCES vm_workflow_runs(workflow_id) ON DELETE SET NULL,
        idempotency_key TEXT UNIQUE, requested_by TEXT, request_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        result_json JSONB NOT NULL DEFAULT '{}'::jsonb, error_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ,
        finished_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    op.execute("""CREATE TABLE IF NOT EXISTS vm_workflow_steps (
        step_id BIGSERIAL PRIMARY KEY, workflow_id UUID NOT NULL REFERENCES vm_workflow_runs(workflow_id) ON DELETE CASCADE,
        step_key TEXT NOT NULL, position INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
          ('pending','running','completed','failed','cancelled','skipped')),
        progress_percent INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
        operation_id TEXT, message TEXT, result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        error_json JSONB NOT NULL DEFAULT '{}'::jsonb, started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(workflow_id,step_key))""")
    op.execute("ALTER TABLE remediation_cases ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'none'")
    op.execute("ALTER TABLE remediation_cases ADD COLUMN IF NOT EXISTS verification_workflow_id UUID")
    op.execute("ALTER TABLE remediation_cases ADD COLUMN IF NOT EXISTS verification_message TEXT")
    op.execute("ALTER TABLE remediation_cases ADD COLUMN IF NOT EXISTS exception_reason TEXT")
    op.execute("ALTER TABLE remediation_cases ADD COLUMN IF NOT EXISTS exception_expires_at TIMESTAMPTZ")
    op.execute("""DO $$ BEGIN
      ALTER TABLE remediation_cases ADD CONSTRAINT ck_remediation_verification_status
        CHECK (verification_status IN ('none','queued','running','passed','failed'));
    EXCEPTION WHEN duplicate_object THEN NULL; END $$""")
    op.execute("""DO $$ BEGIN
      ALTER TABLE remediation_cases ADD CONSTRAINT fk_remediation_verification_workflow
        FOREIGN KEY (verification_workflow_id) REFERENCES vm_workflow_runs(workflow_id) ON DELETE SET NULL;
    EXCEPTION WHEN duplicate_object THEN NULL; END $$""")
    op.execute("UPDATE remediation_cases SET exception_reason=risk_reason, exception_expires_at=risk_expires_at WHERE status='risk_accepted'")
    op.execute("CREATE INDEX IF NOT EXISTS idx_vm_workflow_status_updated ON vm_workflow_runs(status,updated_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_vm_workflow_campaign ON vm_workflow_runs(campaign_id,created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_vm_workflow_steps_run_position ON vm_workflow_steps(workflow_id,position)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediation_verification ON remediation_cases(verification_status,verification_workflow_id)")


def downgrade() -> None:
    op.execute("ALTER TABLE remediation_cases DROP CONSTRAINT IF EXISTS fk_remediation_verification_workflow")
    op.execute("ALTER TABLE remediation_cases DROP CONSTRAINT IF EXISTS ck_remediation_verification_status")
    op.execute("ALTER TABLE remediation_cases DROP COLUMN IF EXISTS verification_status")
    op.execute("ALTER TABLE remediation_cases DROP COLUMN IF EXISTS verification_workflow_id")
    op.execute("ALTER TABLE remediation_cases DROP COLUMN IF EXISTS verification_message")
    op.execute("ALTER TABLE remediation_cases DROP COLUMN IF EXISTS exception_reason")
    op.execute("ALTER TABLE remediation_cases DROP COLUMN IF EXISTS exception_expires_at")
    op.execute("DROP TABLE IF EXISTS vm_workflow_steps")
    op.execute("DROP TABLE IF EXISTS vm_workflow_runs")
