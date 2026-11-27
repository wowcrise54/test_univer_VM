from __future__ import annotations

from typing import Any

from ..mpvm.passport_records import normalize_vulnerability_passport_record


def validate_full_catalog(records: list[dict[str, Any]], summary: dict[str, Any]) -> bool:
    """Validate content; return whether every page proves a complete catalog.

    Unknown totals allow non-destructive imports, never passport replacement.
    """
    batches = summary.get("batches", [])
    if not isinstance(batches, list):
        raise ValueError("MP VM returned invalid pagination metadata")

    page_totals = {
        batch.get("reported_total")
        for batch in batches
        if isinstance(batch, dict) and batch.get("reported_total") is not None
    }
    if len(page_totals) > 1:
        raise ValueError("MP VM catalog total changed during pagination")

    total = summary.get("reportedTotal")
    if total is not None and (not isinstance(total, int) or isinstance(total, bool) or total < 0):
        raise ValueError("MP VM returned an invalid passport catalog total")
    if total is not None and len(records) != total:
        raise ValueError("MP VM returned an incomplete passport catalog")
    if total is not None and page_totals and next(iter(page_totals)) != total:
        raise ValueError("MP VM catalog total changed during pagination")
    if not records and total != 0:
        raise ValueError("MP VM returned an unverified empty passport catalog")

    identifiers: list[str] = []
    for row in records:
        if not isinstance(row, dict):
            raise ValueError("MP VM returned an invalid passport record")
        identifier = normalize_vulnerability_passport_record(row).get("internal_id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("MP VM returned a passport without internalId")
        identifiers.append(identifier)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("MP VM returned duplicate passport identifiers")
    return total is not None and bool(batches) and all(
        isinstance(batch, dict) and batch.get("reported_total") == total
        for batch in batches
    )