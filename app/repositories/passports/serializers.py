"""Decoders and presentational transforms for vulnerability passport rows."""

from __future__ import annotations

from typing import Any

from ...persistence.codecs import clean_value, first_non_empty, json_loads


def decode_vulnerability_passport(row: dict[str, Any]) -> dict[str, Any]:
    cves = json_loads(row.get("cves_json"), [])
    metrics = json_loads(row.get("metrics_json"), {})
    raw_record = json_loads(row.get("raw_record_json"), {})
    raw_detail = json_loads(row.get("raw_detail_json"), None)
    return {
        "id": row.get("id"),
        "internal_id": row.get("internal_id"),
        "external_id": row.get("external_id"),
        "name": row.get("name"),
        "severity": row.get("severity"),
        "score": row.get("score"),
        "issue_time": row.get("issue_time"),
        "package_id": row.get("package_id"),
        "package_version": row.get("package_version"),
        "cves": cves if isinstance(cves, list) else [],
        "metrics": metrics if isinstance(metrics, dict) else {},
        "raw_record": raw_record if isinstance(raw_record, dict) else {},
        "raw_detail": raw_detail if isinstance(raw_detail, dict) else None,
        "has_detail": isinstance(raw_detail, dict),
        "source_pdql": row.get("source_pdql"),
        "pdql_token": row.get("pdql_token"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "detail_updated_at": row.get("detail_updated_at"),
    }


def decode_vulnerability_passport_summary(row: dict[str, Any]) -> dict[str, Any]:
    cves = json_loads(row.get("cves_json"), [])
    metrics = json_loads(row.get("metrics_json"), {})
    raw_detail = json_loads(row.get("raw_detail_json"), {})
    return {
        "id": row.get("id"),
        "internal_id": row.get("internal_id"),
        "external_id": row.get("external_id"),
        "name": row.get("name"),
        "severity": row.get("severity"),
        "score": row.get("score"),
        "issue_time": row.get("issue_time"),
        "package_id": row.get("package_id"),
        "package_version": row.get("package_version"),
        "cves": cves if isinstance(cves, list) else [],
        "metrics": metrics if isinstance(metrics, dict) else {},
        "short_description": vulnerability_passport_short_description(raw_detail),
        "has_detail": bool(row.get("has_detail")),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "detail_updated_at": row.get("detail_updated_at"),
    }


def vulnerability_passport_short_description(raw_detail: Any) -> str | None:
    if not isinstance(raw_detail, dict):
        return None
    details = raw_detail.get("details")
    candidates = (
        raw_detail.get("description"),
        raw_detail.get("vulnerabilityDescription"),
        details.get("description") if isinstance(details, dict) else None,
        raw_detail.get("localizedDescription"),
    )
    for value in candidates:
        if isinstance(value, dict):
            value = first_non_empty(
                value.get("text"),
                value.get("description"),
                value.get("displayName"),
                value.get("name"),
                value.get("value"),
            )
        if isinstance(value, list):
            value = " ".join(
                clean_value(item) or ""
                for item in value
                if not isinstance(item, dict | list)
            )
        text = clean_value(value)
        if text:
            return text
    return None


def decode_vulnerability_passport_detail_job(row: dict[str, Any]) -> dict[str, Any]:
    errors = json_loads(row.get("errors_json"), [])
    return {
        "job_id": row.get("job_id"),
        "status": row.get("status"),
        "requested_count": int(row.get("requested_count") or 0),
        "eligible_count": int(row.get("eligible_count") or 0),
        "processed_count": int(row.get("processed_count") or 0),
        "loaded_count": int(row.get("loaded_count") or 0),
        "failed_count": int(row.get("failed_count") or 0),
        "skipped_fresh_count": int(row.get("skipped_fresh_count") or 0),
        "cancel_requested": bool(row.get("cancel_requested")),
        "errors": errors if isinstance(errors, list) else [],
        "message": row.get("message"),
        "created_at": row.get("created_at"),
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
        "updated_at": row.get("updated_at"),
    }
