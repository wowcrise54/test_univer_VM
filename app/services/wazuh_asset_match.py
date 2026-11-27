"""Match local Ubuntu and Debian package inventories against local CTI rules."""

import re
import subprocess
from collections import defaultdict
from datetime import datetime
from functools import lru_cache
from threading import Event
from typing import Any

import psycopg

from ..persistence import connection, schema
from ..repositories.asset_cards import wazuh_match

PLATFORMS = {
    ("ubuntu", "22.04"): ("canonical", "jammy"),
    ("ubuntu", "24.04"): ("canonical", "noble"),
    ("ubuntu", "26.04"): ("canonical", "resolute"),
    ("debian", "12"): ("debian", "bookworm"),
}
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+")
VERSION = re.compile(r"(?:[0-9]+:)?[0-9][a-zA-Z0-9.+~:-]*")
STATUSES = {"affected": True, "unaffected": False, "unknown": None}
PackageRule = tuple[str, str, str, str, list[dict[str, Any]]]


def platform_for(os_name: str | None, os_version: str | None) -> tuple[str, str] | None:
    name = (os_name or "").strip().lower()
    version = (os_version or "").strip().split(".")
    return PLATFORMS.get((name, ".".join(version[:2]) if name == "ubuntu" else version[0]))


def extract_rules(providers: list[Any]) -> list[PackageRule]:
    rules = []
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        metadata = provider.get("providerMetadata")
        vendor = metadata.get("shortName") if isinstance(metadata, dict) else None
        if not isinstance(vendor, str):
            continue
        allowed = {release for source, release in PLATFORMS.values() if source == vendor}
        if not allowed:
            continue
        for item in provider.get("affected") or []:
            if not isinstance(item, dict) or item.get("vendor") != vendor:
                continue
            package = item.get("product")
            platforms = item.get("platforms")
            if not isinstance(package, str) or not PACKAGE.fullmatch(package) or not isinstance(platforms, list):
                continue
            versions = item.get("versions", [])
            if not isinstance(versions, list) or any(not isinstance(rule, dict) for rule in versions):
                continue
            versions = [
                {key: rule[key] for key in ("status", "version", "versionType", "lessThan", "lessThanOrEqual", "changes")
                 if key in rule}
                for rule in versions
            ]
            default = item.get("defaultStatus")
            default = default if isinstance(default, str) and default in STATUSES else "unknown"
            for release in platforms:
                if isinstance(release, str) and release in allowed:
                    rules.append((vendor, release, package, default, versions))
    return rules


@lru_cache(maxsize=16384)
def _compare(version: str, operator: str, bound: str) -> bool | None:
    if not VERSION.fullmatch(version) or not VERSION.fullmatch(bound):
        return None
    result = subprocess.run(
        ["dpkg", "--compare-versions", version, operator, bound],
        capture_output=True, timeout=3, check=False,
    )
    return result.returncode == 0 if result.returncode in (0, 1) and not result.stderr else None


def applies_to_version(version: str, default: str, rules: list[dict[str, Any]]) -> bool | None:
    if not VERSION.fullmatch(version):
        return None
    matches = set()
    for rule in rules:
        lower = rule.get("version")
        upper = rule.get("lessThan", rule.get("lessThanOrEqual"))
        if (not isinstance(lower, str) or rule.get("changes")
                or rule.get("versionType") not in (None, "deb", "custom")
                or ("lessThan" in rule and "lessThanOrEqual" in rule)
                or (upper is not None and not isinstance(upper, str))):
            return None
        after = _compare(version, "ge" if upper is not None else "eq", lower)
        before = True if upper == "*" or upper is None else _compare(
            version, "lt" if "lessThan" in rule else "le", upper,
        )
        if after is None or before is None:
            return None
        if after and before:
            status = rule.get("status")
            matches.add(STATUSES.get(status) if isinstance(status, str) else None)
    if matches:
        return matches.pop() if len(matches) == 1 else None
    return STATUSES[default]


def assess_asset(asset_id: str, *, additional_only: bool = False) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        result = _assess_asset(conn, asset_id)
        if additional_only and result:
            _exclude_existing(conn, asset_id, result)
        return result


def _assess_asset(
    conn: psycopg.Connection[dict[str, Any]], asset_id: str, stop: Event | None = None,
) -> dict[str, Any] | None:
    inventory = wazuh_match.read_inventory(conn, asset_id)
    if inventory is None:
        return None
    platform = platform_for(inventory["os_name"], inventory["os_version"])
    packages: dict[str, set[str]] = defaultdict(set)
    for name, version in inventory["packages"] or []:
        if name and version:
            packages[name].add(version)
    rules = wazuh_match.read_rules(conn, *platform, sorted(packages)) if platform and packages else []
    by_package = defaultdict(list)
    for rule in rules:
        by_package[rule["package_name"], rule["passport_id"]].append(rule)
    matches = []
    evaluated = set()
    unknown = 0
    for (package, passport_id), applicable in by_package.items():
        if stop is not None and stop.is_set():
            return None
        for version in sorted(packages[package]):
            outcomes = {applies_to_version(version, row["default_status"], row["versions"]) for row in applicable}
            if outcomes == {True}:
                matches.append({
                    "passport_id": passport_id, "cve": passport_id.split(":", 1)[1],
                    "package": package, "version": version,
                    "rules": [row["versions"] for row in applicable],
                })
            if outcomes in ({True}, {False}):
                evaluated.add((package, version))
            else:
                unknown += 1
    return {
        "source": "wazuh-cti", "platform": platform, "inventory_at": inventory["last_seen"],
        "inventory_complete": bool(inventory["complete"]), "packages": sum(map(len, packages.values())),
        "evaluated_packages": len(evaluated), "unknown_assessments": unknown, "matches": matches,
    }


def _exclude_existing(conn: psycopg.Connection[dict[str, Any]], asset_id: str, result: dict[str, Any]) -> None:
    if result["matches"]:
        existing_cves = wazuh_match.read_existing_cves(conn, asset_id)
        result["matches"] = [match for match in result["matches"] if match["cve"].upper() not in existing_cves]


def reconcile_asset(asset_id: str, cutoff: datetime, stop: Event) -> None:
    with connection.connect() as conn:
        if not wazuh_match.claim_due_asset(conn, asset_id, cutoff):
            return
        result = _assess_asset(conn, asset_id, stop)
        if result is not None and not stop.is_set():
            wazuh_match.save_assessment(conn, asset_id, result)


def load_asset_assessment(asset_id: str, *, additional_only: bool = False) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        saved = wazuh_match.read_assessment(conn, asset_id)
        if saved is None:
            return None
        result = saved["result"]
        if result is None:
            platform = platform_for(saved["os_name"], saved["os_version"])
            return {
                "source": "wazuh-cti", "platform": platform, "inventory_at": saved["last_seen"],
                "inventory_complete": False, "packages": 0, "evaluated_packages": 0,
                "unknown_assessments": 0, "matches": [], "pending": platform is not None,
                "checked_at": None,
            }
        if additional_only:
            _exclude_existing(conn, asset_id, result)
        passport_ids = sorted({match["passport_id"] for match in result["matches"]})
        passports = wazuh_match.read_passports(conn, passport_ids) if passport_ids else {}
        return {**result, "passports": passports, "checked_at": saved["checked_at"], "pending": False}
