"""Safe persisted context for operation diagnostic bundles."""

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.diagnostics import ID_PATTERN, build_diagnostic_archive, redact

OPERATION_FIELDS = (
    "operation_id", "kind", "status", "stage", "progress_percent", "message",
    "source_id", "trace_id", "subject", "created_at", "updated_at", "started_at",
    "finished_at", "cancel_requested", "retry_of", "version",
)
EVENT_FIELDS = ("id", "status", "stage", "progress_percent", "message", "created_at")


def build_operation_diagnostic_archive(operation: Mapping[str, Any]) -> Path:
    """Exclude arbitrary request/result payloads; redact all exported context."""
    snapshot = redact({key: operation[key] for key in OPERATION_FIELDS if key in operation})
    events = [
        redact({key: event[key] for key in EVENT_FIELDS if key in event})
        for event in (operation.get("events") or [])
        if isinstance(event, Mapping)
    ]
    trace_id = str(operation.get("trace_id") or "")
    source_id = str(operation.get("source_id") or "")
    # Identifiers are also used for filenames; malformed values never become paths.
    trace_id = trace_id if ID_PATTERN.fullmatch(trace_id) else ""
    source_id = source_id if ID_PATTERN.fullmatch(source_id) else ""
    return build_diagnostic_archive(
        trace_id=trace_id or None,
        job_id=None if trace_id else source_id or None,
        operation_snapshot=snapshot,
        operation_events=events,
    )