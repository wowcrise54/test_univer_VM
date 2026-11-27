from __future__ import annotations

import json
from typing import Any

from .common import as_dict, first_present, normalize_boolean


def normalize_vulnerability_passport_record(record: dict[str, Any]) -> dict[str, Any]:
    passport = as_dict(record.get("@VulnerPassport"))
    cves = normalize_compact_items(
        first_present(
            record.get("compact(VulnerPassport.CVEs)"),
            record.get("VulnerPassport.CVEs"),
            passport.get("cves"),
            passport.get("CVEs"),
        )
    )
    metrics = first_present(record.get("VulnerPassport.Metrics"), passport.get("metrics"), passport.get("Metrics"))
    internal_id = first_present(passport.get("internalId"), record.get("internalId"), record.get("VulnerPassport.InternalId"))
    return {
        "internal_id": internal_id,
        "name": first_present(passport.get("name"), passport.get("displayName"), record.get("VulnerPassport.Name")),
        "external_id": first_present(passport.get("id"), record.get("VulnerPassport.Id")),
        "severity": first_present(record.get("VulnerPassport.SeverityRating"), passport.get("severityRating")),
        "score": first_present(record.get("VulnerPassport.Score"), passport.get("score")),
        "issue_time": first_present(record.get("VulnerPassport.IssueTime"), passport.get("issueTime")),
        "package_id": first_present(record.get("VulnerPassport.PackageId"), passport.get("packageId")),
        "package_version": first_present(record.get("VulnerPassport.PackageVersion"), passport.get("packageVersion")),
        "metrics": metrics if isinstance(metrics, dict) else {},
        "cves": cves,
        "raw_record": record,
    }


def normalize_trending_vulnerability_record(record: dict[str, Any]) -> dict[str, Any]:
    passport = as_dict(record.get("@VulnerPassport"))
    affected_components = passport.get("affectedComponents")
    if not isinstance(affected_components, list):
        affected_components = passport.get("AffectedComponents")
    nested_vendors: list[Any] = []
    nested_names: list[Any] = []
    if isinstance(affected_components, list):
        for component in affected_components:
            if not isinstance(component, dict):
                nested_names.append(component)
                continue
            nested_vendors.append(first_present(component.get("vendor"), component.get("Vendor")))
            nested_names.append(
                first_present(
                    component.get("name"),
                    component.get("displayName"),
                    component.get("Name"),
                )
            )

    normalized = normalize_vulnerability_passport_record(record)
    trend_value = first_present(
        record.get("VulnerPassport.IsTrend"),
        passport.get("isTrend"),
        passport.get("IsTrend"),
    )
    normalized.update(
        {
            # This normalizer is only used for the result of the exact
            # IsTrend=true PDQL query, where some MP VM versions omit the
            # selected boolean from the returned row.
            "is_trend": True if trend_value is None else normalize_boolean(trend_value),
            "description": normalize_passport_text(
                first_present(
                    record.get("VulnerPassport.Description"),
                    passport.get("description"),
                    passport.get("Description"),
                )
            ),
            "is_trend_since": first_present(
                record.get("VulnerPassport.IsTrendSince"),
                passport.get("isTrendSince"),
                passport.get("IsTrendSince"),
            ),
            "vendors": normalize_passport_labels(
                first_present(
                    record.get("VulnerPassport.AffectedComponents.Vendor"),
                    nested_vendors,
                )
            ),
            "affected_components": normalize_passport_labels(
                first_present(
                    record.get("compact(VulnerPassport.AffectedComponents.Name)"),
                    record.get("VulnerPassport.AffectedComponents.Name"),
                    nested_names,
                )
            ),
        }
    )
    return normalized


def vulnerability_passport_summary(passport: dict[str, Any]) -> dict[str, Any]:
    return {
        "internal_id": passport.get("internal_id"),
        "external_id": passport.get("external_id"),
        "name": passport.get("name"),
        "severity": passport.get("severity"),
        "score": passport.get("score"),
        "issue_time": passport.get("issue_time"),
        "package_id": passport.get("package_id"),
        "package_version": passport.get("package_version"),
        "cves": passport.get("cves") if isinstance(passport.get("cves"), list) else [],
        "metrics": as_dict(passport.get("metrics")),
        "has_detail": False,
    }


def dedupe_vulnerability_passports(passports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for passport in passports:
        key = passport.get("internal_id") or passport.get("external_id") or passport.get("name")
        if key is None:
            result.append(passport)
            continue
        key_text = str(key)
        if key_text in seen:
            continue
        seen.add(key_text)
        result.append(passport)
    return result


def merge_trending_vulnerability_records(
    passports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge rows expanded by affected-component fields into one passport."""

    merged: dict[str, dict[str, Any]] = {}
    metadata_fields = (
        "external_id",
        "name",
        "severity",
        "score",
        "description",
        "issue_time",
        "is_trend_since",
        "package_id",
        "package_version",
    )
    for passport in passports:
        internal_id = str(passport.get("internal_id") or "").strip()
        if not internal_id:
            continue
        current = merged.get(internal_id)
        if current is None:
            current = {
                **passport,
                "vendors": list(passport.get("vendors") or []),
                "affected_components": list(
                    passport.get("affected_components") or []
                ),
                "cves": list(passport.get("cves") or []),
            }
            merged[internal_id] = current
            continue
        for field in metadata_fields:
            current_value = current.get(field)
            candidate_value = passport.get(field)
            if (
                (current_value is None or current_value == "")
                and candidate_value is not None
                and candidate_value != ""
            ):
                current[field] = passport[field]
        for field in ("vendors", "affected_components"):
            values = current.setdefault(field, [])
            for value in passport.get(field) or []:
                if value not in values:
                    values.append(value)
        cves = current.setdefault("cves", [])
        cve_keys = {
            json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
            for item in cves
        }
        for cve in passport.get("cves") or []:
            key = json.dumps(cve, ensure_ascii=False, sort_keys=True, default=str)
            if key not in cve_keys:
                cve_keys.add(key)
                cves.append(cve)
    return list(merged.values())


def normalize_compact_items(value: Any) -> list[dict[str, Any]]:
    items: list[Any] = []
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        items = value["data"]
    elif isinstance(value, list):
        items = value

    result: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            result.append(
                {
                    "display_name": first_present(item.get("displayName"), item.get("name"), item.get("id")),
                    "url": item.get("url"),
                    "raw": item,
                }
            )
        elif item:
            result.append({"display_name": str(item), "url": None, "raw": item})
    return result


def normalize_passport_labels(value: Any) -> list[str]:
    labels: list[str] = []

    def append(item: Any) -> None:
        if item is None or item == "":
            return
        if isinstance(item, list):
            for child in item:
                append(child)
            return
        if isinstance(item, dict):
            data = item.get("data")
            if isinstance(data, list):
                append(data)
                return
            label = first_present(
                item.get("display_name"),
                item.get("displayName"),
                item.get("name"),
                item.get("Name"),
                item.get("value"),
                item.get("title"),
                item.get("id"),
            )
            append(label)
            return
        text = str(item).strip()
        if text and text not in labels:
            labels.append(text)

    append(value)
    return labels


def normalize_passport_text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        value = first_present(
            value.get("text"),
            value.get("description"),
            value.get("displayName"),
            value.get("name"),
            value.get("value"),
        )
    if isinstance(value, list):
        parts = [normalize_passport_text(item) for item in value]
        value = " ".join(part for part in parts if part)
    if value is None:
        return None
    text = str(value).strip()
    return text or None
