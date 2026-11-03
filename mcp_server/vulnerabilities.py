from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any, Protocol

from .client import ApiError

FIX_AVAILABLE = "available"
FIX_NOT_DESCRIBED = "not_described"
FIX_UNKNOWN = "unknown"

PAGE_SIZE = 500
MAX_SELECTORS = 10
MAX_HOSTS_PER_SELECTOR = 2000
MAX_FIX_TEXT_CHARS = 2000
MAX_PASSPORTS = 5
MAX_LISTED_OBJECTS = 5

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_TOKEN_SPLIT = re.compile(r"[,;\s]+")

DATA_SOURCE_NOTE = (
    "Data comes from asset cards saved in the local PostgreSQL of MP VM Client, not from a live MP VM query. "
    "It is only as fresh as the last card refresh of each host (see last_seen / stale)."
)


class Getter(Protocol):
    async def get(self, path: str, **params: Any) -> Any: ...


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(_text(severity).lower(), 4)


def parse_timestamp(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def fix_info(row: dict[str, Any]) -> dict[str, Any]:
    """Whether MP VM describes a fix for this vulnerability, based on its passports.

    ``has_fix=false`` in the application mixes "the passport has no fix" with
    "no passport (or no passport detail) is known", so the two are told apart here.
    """
    passports = [item for item in (row.get("passports") or []) if isinstance(item, dict)]
    how_to_fix = _text(row.get("how_to_fix"))
    if row.get("has_fix") or how_to_fix:
        status, reason = FIX_AVAILABLE, "the passport describes how to fix it"
    elif any(item.get("has_detail") for item in passports):
        status, reason = FIX_NOT_DESCRIBED, "the passport has details but no fix description"
    elif passports:
        status, reason = FIX_UNKNOWN, "a passport is linked but its details are not loaded yet"
    else:
        status, reason = FIX_UNKNOWN, "no vulnerability passport is linked to this finding"
    truncated = len(how_to_fix) > MAX_FIX_TEXT_CHARS
    return {
        "status": status,
        "has_fix": True if status == FIX_AVAILABLE else (False if status == FIX_NOT_DESCRIBED else None),
        "reason": reason,
        "how_to_fix": how_to_fix[:MAX_FIX_TEXT_CHARS] if how_to_fix else None,
        "how_to_fix_truncated": truncated,
        "passports": [
            {
                "external_id": item.get("external_id"),
                "name": item.get("name"),
                "severity": item.get("severity"),
                "score": item.get("score"),
                "has_detail": bool(item.get("has_detail")),
            }
            for item in passports[:MAX_PASSPORTS]
        ],
    }


def slim_vulnerability(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "selector": row.get("selector"),
        "vulnerability_id": row.get("vulnerability_id"),
        "cve": row.get("cve"),
        "name": row.get("name"),
        "severity": row.get("severity"),
        "cvss_score": row.get("cvss_score"),
        "affected_hosts": row.get("affected_hosts"),
        "findings": row.get("findings"),
        "sources": row.get("sources") or [],
        "short_description": row.get("short_description"),
        "last_seen": row.get("last_seen"),
        "fix": fix_info(row),
    }


def host_staleness(last_seen: Any, *, stale_days: int, now: datetime | None = None) -> tuple[float | None, bool | None]:
    parsed = parse_timestamp(last_seen)
    if parsed is None:
        return None, None
    age = ((now or datetime.now(UTC)) - parsed).total_seconds() / 86400
    return round(age, 1), age > stale_days


def slim_host(row: dict[str, Any], *, stale_days: int, now: datetime | None = None) -> dict[str, Any]:
    age_days, stale = host_staleness(row.get("last_seen"), stale_days=stale_days, now=now)
    os_name = " ".join(part for part in (_text(row.get("os_name")), _text(row.get("os_version"))) if part)
    host: dict[str, Any] = {
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "hostname": row.get("hostname"),
        "fqdn": row.get("fqdn"),
        "ip_address": row.get("ip_address"),
        "os": os_name or None,
        "asset_type": row.get("asset_type"),
        "severity": row.get("severity"),
        "cvss_score": row.get("cvss_score"),
        "finding_count": row.get("finding_count"),
        "sources": row.get("sources") or [],
        "last_seen": row.get("last_seen"),
        "age_days": age_days,
        "stale": stale,
    }
    for key in ("objects", "docker_containers", "docker_images"):
        values = row.get(key) or []
        if values:
            host[key] = values[:MAX_LISTED_OBJECTS]
    return host


def match_rows(rows: list[dict[str, Any]], query: str) -> tuple[list[dict[str, Any]], str]:
    """Pick the rows that are exactly the requested CVE / id / name.

    The API ``q`` filter is a substring match, so ``CVE-2024-1`` also returns
    ``CVE-2024-10``. When nothing matches exactly the partial matches are kept
    and reported as such.
    """
    needle = query.strip().lower()
    if not rows:
        return [], "none"
    exact = []
    for row in rows:
        candidates = {_text(row.get("vulnerability_id")).lower(), _text(row.get("name")).lower()}
        candidates.update(token for token in _TOKEN_SPLIT.split(_text(row.get("cve")).lower()) if token)
        if needle in candidates:
            exact.append(row)
    if exact:
        return exact, "exact"
    return rows, "partial"


class CoverageProbe:
    """Best-effort, briefly cached completeness/freshness block of the local data."""

    def __init__(self, client: Getter, *, ttl_seconds: float = 60.0):
        self._client = client
        self._ttl = ttl_seconds
        self._cached: tuple[float, dict[str, Any] | None] | None = None

    async def get(self) -> dict[str, Any] | None:
        now = time.monotonic()
        if self._cached and now - self._cached[0] < self._ttl:
            return self._cached[1]
        try:
            summary = await self._client.get("/api/vulnerabilities/summary")
            coverage = summary.get("coverage") if isinstance(summary, dict) else None
        except ApiError:
            coverage = None
        self._cached = (now, coverage if isinstance(coverage, dict) else None)
        return self._cached[1]


async def resolve_vulnerabilities(
    client: Getter,
    query: str,
    *,
    severity: str | None = None,
    source: str | None = None,
) -> tuple[list[dict[str, Any]], str, int]:
    result = await client.get("/api/vulnerabilities", q=query, severity=severity, source=source, limit=PAGE_SIZE)
    rows = [row for row in result.get("rows", []) if isinstance(row, dict)]
    matched, kind = match_rows(rows, query)
    return matched, kind, int(result.get("total") or len(rows))


async def collect_hosts(
    client: Getter,
    selector: str,
    *,
    severity: str | None = None,
    source: str | None = None,
    host_q: str | None = None,
) -> tuple[list[dict[str, Any]], int, bool]:
    hosts: list[dict[str, Any]] = []
    total = 0
    offset = 0
    while offset < MAX_HOSTS_PER_SELECTOR:
        page = await client.get(
            "/api/vulnerabilities/hosts",
            selector=selector,
            severity=severity,
            source=source,
            host_q=host_q,
            limit=PAGE_SIZE,
            offset=offset,
        )
        rows = [row for row in page.get("rows", []) if isinstance(row, dict)]
        total = int(page.get("total") or 0)
        hosts.extend(rows)
        offset += PAGE_SIZE
        if not rows or offset >= total:
            break
    return hosts, total, total > len(hosts)


def _merge_hosts(per_selector: list[tuple[str, list[dict[str, Any]]]], *, stale_days: int) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    now = datetime.now(UTC)
    for selector, rows in per_selector:
        for row in rows:
            asset_id = _text(row.get("asset_id"))
            if not asset_id:
                continue
            host = merged.get(asset_id)
            if host is None:
                host = slim_host(row, stale_days=stale_days, now=now)
                host["selectors"] = []
                host["remediation"] = []
                merged[asset_id] = host
            else:
                host["sources"] = sorted({*host["sources"], *(row.get("sources") or [])})
                if severity_rank(row.get("severity")) < severity_rank(host.get("severity")):
                    host["severity"] = row.get("severity")
            host["selectors"].append(selector)
            case = row.get("remediation")
            if isinstance(case, dict):
                host["remediation"].append(
                    {
                        "selector": selector,
                        "case_id": case.get("case_id"),
                        "status": case.get("status"),
                        "assignee": case.get("assignee"),
                        "due_at": case.get("due_at"),
                        "overdue": case.get("overdue"),
                    }
                )
    return sorted(
        merged.values(),
        key=lambda h: (severity_rank(h.get("severity")), -(h.get("cvss_score") or 0), _text(h.get("display_name")).lower()),
    )


async def find_hosts_by_vulnerability(
    client: Getter,
    coverage: CoverageProbe,
    *,
    query: str,
    stale_days: int,
    severity: str | None = None,
    source: str | None = None,
    host_q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    query = query.strip()
    matched, match_kind, rows_total = await resolve_vulnerabilities(client, query, severity=severity, source=source)
    selectors_truncated = len(matched) > MAX_SELECTORS or rows_total > PAGE_SIZE
    matched = matched[:MAX_SELECTORS]

    per_selector: list[tuple[str, list[dict[str, Any]]]] = []
    hosts_truncated = False
    for row in matched:
        selector = _text(row.get("selector"))
        if not selector:
            continue
        hosts, _total, cut = await collect_hosts(client, selector, severity=severity, source=source, host_q=host_q)
        hosts_truncated = hosts_truncated or cut
        per_selector.append((selector, hosts))

    merged = _merge_hosts(per_selector, stale_days=stale_days)
    page = merged[offset : offset + limit]
    return {
        "query": query,
        "match": match_kind,
        "vulnerabilities": [slim_vulnerability(row) for row in matched],
        "total_hosts": len(merged),
        "stale_hosts": sum(1 for host in merged if host.get("stale")),
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "hosts": page,
        "truncated": selectors_truncated or hosts_truncated,
        "data_source": {
            "kind": "asset_cards",
            "note": DATA_SOURCE_NOTE,
            "stale_after_days": stale_days,
            "coverage": await coverage.get(),
        },
    }


async def get_fix_info(
    client: Getter,
    *,
    query: str,
    severity: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    matched, match_kind, rows_total = await resolve_vulnerabilities(client, query.strip(), severity=severity, source=source)
    return {
        "query": query.strip(),
        "match": match_kind,
        "vulnerabilities": [slim_vulnerability(row) for row in matched[:MAX_SELECTORS]],
        "truncated": len(matched) > MAX_SELECTORS or rows_total > PAGE_SIZE,
        "note": (
            "fix.status: available = the MP VM passport describes a fix; not_described = the passport has no fix "
            "text; unknown = no passport detail is available, so nothing can be said. "
            "This is information only: no fix is applied."
        ),
    }
