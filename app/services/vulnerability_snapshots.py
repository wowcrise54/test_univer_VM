from __future__ import annotations

from typing import Any

from ..diagnostics import log_event
from .main_host import host


def capture_vulnerability_snapshot(trigger_kind: str, trigger_id: str) -> dict[str, Any] | None:
    """Persist best-effort vulnerability history without failing the primary operation."""
    try:
        snapshot = host.CONTAINER.services.vulnerabilities.capture_snapshot(
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
        )
        log_event(
            "vulnerabilities",
            "snapshot.capture.completed",
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
            snapshot_id=(snapshot.get("snapshot") or {}).get("id")
            if isinstance(snapshot, dict)
            else None,
            created=snapshot.get("created") if isinstance(snapshot, dict) else None,
        )
        return snapshot
    except Exception:
        host.log_exception(
            "vulnerabilities",
            "snapshot.capture.failed",
            trigger_kind=trigger_kind,
            trigger_id=trigger_id,
        )
        return None


def ensure_vulnerability_snapshot_baseline() -> dict[str, Any] | None:
    try:
        return host.CONTAINER.services.vulnerabilities.ensure_baseline()
    except Exception:
        host.log_exception("vulnerabilities", "snapshot.baseline.failed")
        return None
