from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from ipaddress import ip_address, ip_network
from typing import Literal

ComplianceScope = Literal["internet", "organization"]
AssetCategory = Literal["user_device", "server", "unclassified"]
FreshnessReason = Literal["fresh", "stale", "missing_scan_date"]

INTERNET_NETWORK = ip_network("10.255.0.0/16")
FRESHNESS_DAYS = 30
SERVER_TYPES = {"server", "virtual server", "physical server"}
USER_DEVICE_TYPES = {"workstation", "desktop", "laptop", "user device"}


@dataclass(frozen=True)
class FreshnessResult:
    scan_at: datetime | None
    cutoff_at: datetime
    is_fresh: bool
    age_days: int | None
    reason: FreshnessReason


def freshness_cutoff(assessment_date: date) -> datetime:
    return datetime.combine(
        assessment_date - timedelta(days=FRESHNESS_DAYS),
        time.min,
        tzinfo=UTC,
    )


def evaluate_freshness(
    scan_at: datetime | str | None,
    assessment_date: date,
) -> FreshnessResult:
    cutoff = freshness_cutoff(assessment_date)
    if not scan_at:
        return FreshnessResult(None, cutoff, False, None, "missing_scan_date")
    parsed = (
        datetime.fromisoformat(scan_at.replace("Z", "+00:00"))
        if isinstance(scan_at, str)
        else scan_at
    )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    is_fresh = parsed >= cutoff
    return FreshnessResult(
        parsed,
        cutoff,
        is_fresh,
        (assessment_date - parsed.date()).days,
        "fresh" if is_fresh else "stale",
    )


def is_internet_asset(value: str | None) -> bool:
    try:
        return ip_address(str(value).strip()) in INTERNET_NETWORK
    except ValueError:
        return False


def classify_asset_type(value: str | None) -> AssetCategory:
    normalized = " ".join(str(value or "").strip().lower().split())
    if normalized in SERVER_TYPES:
        return "server"
    if normalized in USER_DEVICE_TYPES:
        return "user_device"
    return "unclassified"
