"""Match local Ubuntu and Debian package inventories against local CTI rules."""

import re
import subprocess
from collections import defaultdict
from functools import lru_cache
from typing import Any

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


def assess_asset(asset_id: str) -> dict[str, Any] | None:
    inventory = wazuh_match.read_inventory(asset_id)
    if inventory is None:
        return None
    platform = platform_for(inventory["os_name"], inventory["os_version"])
    packages: dict[str, set[str]] = defaultdict(set)
    for name, version in inventory["packages"] or []:
        if name and version:
            packages[name].add(version)
    rules = wazuh_match.read_rules(*platform, sorted(packages)) if platform and packages else []
    by_package = defaultdict(list)
    for rule in rules:
        by_package[rule["package_name"], rule["passport_id"]].append(rule)
    matches = []
    evaluated = set()
    unknown = 0
    for (package, passport_id), applicable in by_package.items():
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
