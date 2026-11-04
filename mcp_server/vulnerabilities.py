from __future__ import annotations

import asyncio
import re
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from functools import partial
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
HOST_FETCH_CONCURRENCY = 3
COVERAGE_TTL_SECONDS = 600.0
COVERAGE_TIMEOUT_SECONDS = 20.0
SEARCH_CACHE_TTL_SECONDS = 120.0
SEARCH_CACHE_MAX_ENTRIES = 64
BRIEF_FIX_TEXT_CHARS = 600
BRIEF_PASSPORTS = 2
HOST_COLUMNS = ["asset_id", "name", "ip", "os", "severity", "last_seen", "age_days", "stale", "case"]

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


def fix_info(row: dict[str, Any], *, brief: bool = False) -> dict[str, Any]:
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
    text_chars = BRIEF_FIX_TEXT_CHARS if brief else MAX_FIX_TEXT_CHARS
    truncated = len(how_to_fix) > text_chars
    info = {
        "status": status,
        "has_fix": True if status == FIX_AVAILABLE else (False if status == FIX_NOT_DESCRIBED else None),
        "reason": reason,
        "how_to_fix": how_to_fix[:text_chars] if how_to_fix else None,
        "how_to_fix_truncated": truncated,
        "passports": [
            {
                "external_id": item.get("external_id"),
                "name": item.get("name"),
                "severity": item.get("severity"),
                "score": item.get("score"),
                "has_detail": bool(item.get("has_detail")),
            }
            for item in passports[: BRIEF_PASSPORTS if brief else MAX_PASSPORTS]
        ],
    }
    if brief:
        # status already says what has_fix says; drop empty and false fields
        # (the full text is available from get_vulnerability_fix_info)
        info = {key: value for key, value in info.items() if key != "has_fix" and value not in (None, [], False)}
    return info


def slim_vulnerability(row: dict[str, Any], *, brief: bool = False) -> dict[str, Any]:
    vulnerability = {
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
        "fix": fix_info(row, brief=brief),
    }
    if brief:
        vulnerability.pop("findings", None)
        vulnerability["short_description"] = _text(row.get("short_description"))[:200] or None
        vulnerability = {key: value for key, value in vulnerability.items() if value not in (None, [], "")}
    return vulnerability


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
    if host.get("hostname") == host.get("display_name"):
        del host["hostname"]
    # Empty fields only cost tokens; False is kept because it is an answer (stale: false).
    return {key: value for key, value in host.items() if value is not None and value != [] and value != ""}


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
    """Best-effort, cached completeness/freshness block of the local data.

    ``/api/vulnerabilities/summary`` aggregates every saved card and can take minutes on a large
    database, so the answer is cached for a long time, shared between concurrent callers and
    abandoned after ``timeout_seconds``.
    """

    def __init__(
        self,
        client: Getter,
        *,
        ttl_seconds: float = COVERAGE_TTL_SECONDS,
        timeout_seconds: float = COVERAGE_TIMEOUT_SECONDS,
    ):
        self._client = client
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        self._cached: tuple[float, dict[str, Any]] | None = None
        self._pending: asyncio.Task[dict[str, Any] | None] | None = None

    async def get(self) -> dict[str, Any] | None:
        if self._cached and time.monotonic() - self._cached[0] < self._ttl:
            return self._cached[1]
        if self._pending is None or self._pending.done():
            self._pending = asyncio.ensure_future(self._fetch())
        try:
            # shield: a caller that gives up must not cancel the fetch other callers wait for
            return await asyncio.wait_for(asyncio.shield(self._pending), self._timeout)
        except (TimeoutError, ApiError):
            return None

    async def _fetch(self) -> dict[str, Any] | None:
        summary = await self._client.get("/api/vulnerabilities/summary")
        coverage = summary.get("coverage") if isinstance(summary, dict) else None
        if isinstance(coverage, dict):
            self._cached = (time.monotonic(), coverage)
            return coverage
        return None


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
    hosts = sorted(
        merged.values(),
        key=lambda h: (severity_rank(h.get("severity")), -(h.get("cvss_score") or 0), _text(h.get("display_name")).lower()),
    )
    for host in hosts:
        if not host["remediation"]:
            del host["remediation"]
        if len(per_selector) == 1:
            del host["selectors"]  # every host belongs to the only selector
    return hosts


class SearchCache:
    """Short-lived cache of finished host searches.

    The same question is often repeated (a retry, the next page, another client), and the
    application needs seconds to answer it. Concurrent identical searches share one run.
    """

    def __init__(self, *, ttl_seconds: float = SEARCH_CACHE_TTL_SECONDS, max_entries: int = SEARCH_CACHE_MAX_ENTRIES):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._done: dict[Any, tuple[float, Any]] = {}
        self._pending: dict[Any, asyncio.Future[Any]] = {}

    async def get_or_compute(self, key: Any, compute: Callable[[], Awaitable[Any]]) -> Any:
        hit = self._done.get(key)
        if hit and time.monotonic() - hit[0] < self._ttl:
            return hit[1]
        task = self._pending.get(key)
        if task is None:
            task = asyncio.ensure_future(compute())
            self._pending[key] = task
            task.add_done_callback(partial(self._finish, key))
        # shield: a caller that disconnects must not cancel the run other callers wait for
        return await asyncio.shield(task)

    def _finish(self, key: Any, task: asyncio.Future[Any]) -> None:
        self._pending.pop(key, None)
        if task.cancelled() or task.exception() is not None:
            return  # errors are not cached, and calling exception() marks them as retrieved
        self._done[key] = (time.monotonic(), task.result())
        while len(self._done) > self._max:
            oldest = min(self._done.items(), key=lambda item: item[1][0])[0]
            del self._done[oldest]


def brief_host_row(host: dict[str, Any]) -> list[Any]:
    """One host as a positional row matching HOST_COLUMNS (a fraction of the size of the object form)."""
    case = host.get("remediation")
    return [
        host.get("asset_id"),
        host.get("display_name"),
        host.get("ip_address"),
        host.get("os"),
        host.get("severity"),
        _text(host.get("last_seen"))[:10] or None,
        host.get("age_days"),
        host.get("stale"),
        case[0].get("status") if case else None,
    ]


async def _search(
    client: Getter,
    *,
    query: str,
    stale_days: int,
    severity: str | None,
    source: str | None,
    host_q: str | None,
) -> dict[str, Any]:
    matched, match_kind, rows_total = await resolve_vulnerabilities(client, query, severity=severity, source=source)
    selectors_truncated = len(matched) > MAX_SELECTORS or rows_total > PAGE_SIZE
    matched = matched[:MAX_SELECTORS]

    selectors = [_text(row.get("selector")) for row in matched if _text(row.get("selector"))]
    gate = asyncio.Semaphore(HOST_FETCH_CONCURRENCY)

    async def fetch(selector: str) -> tuple[str, list[dict[str, Any]], bool]:
        async with gate:
            hosts, _total, cut = await collect_hosts(client, selector, severity=severity, source=source, host_q=host_q)
        return selector, hosts, cut

    fetched = await asyncio.gather(*(fetch(selector) for selector in selectors))
    return {
        "matched": matched,
        "match": match_kind,
        "hosts": _merge_hosts([(selector, hosts) for selector, hosts, _cut in fetched], stale_days=stale_days),
        "truncated": selectors_truncated or any(cut for _selector, _hosts, cut in fetched),
    }


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
    include_coverage: bool = False,
    detail: str = "full",
    cache: SearchCache | None = None,
) -> dict[str, Any]:
    query = query.strip()

    async def compute() -> dict[str, Any]:
        return await _search(
            client, query=query, stale_days=stale_days, severity=severity, source=source, host_q=host_q
        )

    if cache is None:
        found = await compute()
    else:
        found = await cache.get_or_compute((query.lower(), severity, source, host_q, stale_days), compute)

    brief = detail == "brief"
    merged: list[dict[str, Any]] = found["hosts"]
    page = merged[offset : offset + limit]
    seen = sorted(text for text in (_text(host.get("last_seen")) for host in merged) if text)
    data_source: dict[str, Any] = {
        "kind": "asset_cards",
        "note": "from saved asset cards, not live MP VM" if brief else DATA_SOURCE_NOTE,
        "stale_after_days": stale_days,
        "hosts_oldest_last_seen": seen[0] if seen else None,
        "hosts_freshest_last_seen": seen[-1] if seen else None,
    }
    if include_coverage:
        data_source["coverage"] = await coverage.get()
        if data_source["coverage"] is None:
            data_source["coverage_note"] = "global coverage was not available in time; retry or call vulnerability_summary"
    result: dict[str, Any] = {
        "query": query,
        "match": found["match"],
        "vulnerabilities": [slim_vulnerability(row, brief=brief) for row in found["matched"]],
        "total_hosts": len(merged),
        "stale_hosts": sum(1 for host in merged if host.get("stale")),
        "hosts_by_severity": dict(Counter(_text(host.get("severity")) or "unknown" for host in merged)),
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "truncated": found["truncated"],
        "data_source": data_source,
    }
    if brief:
        result["host_columns"] = HOST_COLUMNS
        result["hosts"] = [brief_host_row(host) for host in page]
    else:
        result["hosts"] = page
    return result


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
