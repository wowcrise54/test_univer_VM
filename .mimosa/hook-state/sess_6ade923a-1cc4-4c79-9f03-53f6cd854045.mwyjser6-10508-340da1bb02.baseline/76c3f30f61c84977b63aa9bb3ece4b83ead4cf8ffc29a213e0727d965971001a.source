from __future__ import annotations

from collections.abc import Callable
from typing import Any


def database_startup_steps(runtime: Any) -> list[tuple[str, Callable[[], Any]]]:
    """Compatibility wiring for existing use cases, in dependency order.

    Each completed stage is checkpointed by DatabaseRecovery. Keeping scheduler
    activation last prevents it from observing partially initialized state.
    """
    return [
        ("migrations", lambda: runtime.db.init_db()),
        ("rbac", lambda: runtime.app_auth.ensure_rbac_catalog()),
        ("bootstrap", lambda: runtime.app_auth.ensure_bootstrap_admin(
            runtime.SETTINGS.bootstrap_admin_username,
            runtime.SETTINGS.bootstrap_admin_password,
            runtime.SETTINGS.bootstrap_admin_display_name,
        )),
        ("passport_jobs", lambda: runtime.db.interrupt_active_vulnerability_passport_detail_jobs()),
        ("passport_refresh", lambda: runtime.passport_refresh.interrupt_active()),
        ("card_jobs", lambda: runtime.db.interrupt_active_asset_card_build_jobs()),
        ("postprocess_leases", lambda: runtime.db.release_scan_postprocess_leases()),
        ("operations", lambda: runtime.db.sync_operations_from_sources()),
        ("snapshot", lambda: runtime.CONTAINER.services.vulnerabilities.ensure_baseline()),
        ("remediation", lambda: runtime.CONTAINER.services.remediation.reconcile_all()),
        ("digest", lambda: runtime.CONTAINER.services.remediation.ensure_daily_digest(
            webhook_enabled=bool(runtime.SETTINGS.automation_webhook_url),
        )),
        ("backfill", lambda: runtime.start_asset_search_backfill(strict=True)),
        ("postprocess_resume", lambda: runtime.resume_scan_postprocess_runs(strict=True)),
        ("workflow_resume", lambda: runtime.CONTAINER.services.vm_workflows.resume()),
        ("automation_resume", lambda: runtime.get_automation_service().resume_runs()),
        ("audit_retention", lambda: runtime.CONTAINER.operation_runner.submit(
            "maintenance", runtime.app_auth.cleanup_audit_events, 365,
        )),
        ("scheduler", lambda: runtime.get_automation_service().start_scheduler()),
    ]
