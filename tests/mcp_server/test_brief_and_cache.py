from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mcp_server import vulnerabilities as vuln
from mcp_server.client import ApiError, AppClient
from mcp_server.shaping import render
from tests.mcp_server.fakes import FakeApi, host_row, iso_ago, make_settings, vuln_row
from tests.mcp_server.test_logic import _api_for_cve


def _find(api: FakeApi, **kwargs: Any) -> dict[str, Any]:
    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            return await vuln.find_hosts_by_vulnerability(client, vuln.CoverageProbe(client), stale_days=14, **kwargs)
        finally:
            await client.aclose()

    return asyncio.run(run())


def test_brief_hosts_are_positional_rows_in_the_order_of_host_columns():
    result = _find(_api_for_cve(), query="CVE-2024-3094", detail="brief")

    assert result["host_columns"] == vuln.HOST_COLUMNS
    rows = {row[0]: dict(zip(result["host_columns"], row, strict=True)) for row in result["hosts"]}
    assert set(rows) == {"a", "b", "c"} and result["returned"] == 3
    assert rows["b"]["name"] == "host-b" and rows["b"]["ip"] == "10.0.0.1" and rows["b"]["os"] == "Linux 6.1"
    assert rows["b"]["severity"] == "critical" and rows["b"]["stale"] is True
    assert len(rows["b"]["last_seen"]) == 10  # the date is enough for a person or a model
    assert rows["a"]["case"] == "in_progress"  # the remediation status
    assert rows["c"]["case"] is None
    assert result["hosts_by_severity"] == {"critical": 1, "high": 1, "medium": 1}


def test_brief_vulnerabilities_drop_empty_and_duplicated_fields():
    api = _api_for_cve()
    result = _find(api, query="CVE-2024-3094", detail="brief")
    available, unknown = result["vulnerabilities"]
    assert available["fix"] == {"status": "available", "reason": "the passport describes how to fix it", "how_to_fix": "Upgrade xz"}
    assert "has_fix" not in unknown["fix"] and "passports" not in unknown["fix"]
    assert "findings" not in available and "short_description" not in available


def test_brief_cuts_a_long_fix_text_but_full_keeps_more():
    api = FakeApi()
    long_fix = "x" * 1500
    api.json(
        "/api/vulnerabilities",
        {"total": 1, "rows": [vuln_row("id:1", vulnerability_id="V-1", cve="CVE-1", has_fix=True, how_to_fix=long_fix)]},
    )
    api.json("/api/vulnerabilities/hosts", {"total": 1, "rows": [host_row("a")]})
    brief = _find(api, query="CVE-1", detail="brief")["vulnerabilities"][0]["fix"]
    full = _find(api, query="CVE-1", detail="full")["vulnerabilities"][0]["fix"]
    assert len(brief["how_to_fix"]) == vuln.BRIEF_FIX_TEXT_CHARS and brief["how_to_fix_truncated"] is True
    assert len(full["how_to_fix"]) == 1500 and full["how_to_fix_truncated"] is False


def test_brief_answer_is_several_times_smaller_than_full_for_many_hosts():
    api = FakeApi()
    api.json("/api/vulnerabilities", {"total": 1, "rows": [vuln_row("id:1", vulnerability_id="V-1", cve="CVE-1")]})
    rows = [
        host_row(
            f"{i:04d}",
            sources=["software", "docker"],
            objects=["libssl 1.1.1", "openssl 1.1.1k"],
            docker_images=["registry.corp/app:1.2.3"],
            last_seen=iso_ago(i % 30),
        )
        for i in range(50)
    ]
    api.json("/api/vulnerabilities/hosts", {"total": 50, "rows": rows})
    brief = len(render(_find(api, query="CVE-1", detail="brief"), 1_000_000))
    full = len(render(_find(api, query="CVE-1", detail="full"), 1_000_000))
    assert brief * 2 < full, (brief, full)


def test_cache_serves_repeats_and_pages_without_asking_the_application_again():
    api = _api_for_cve()
    cache = vuln.SearchCache()

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            probe = vuln.CoverageProbe(client)
            first = await vuln.find_hosts_by_vulnerability(client, probe, stale_days=14, query="CVE-2024-3094", limit=2, cache=cache)
            requests_after_first = len(api.requests)
            second = await vuln.find_hosts_by_vulnerability(
                client, probe, stale_days=14, query=" cve-2024-3094 ", limit=2, offset=2, cache=cache
            )
            return first, second, requests_after_first
        finally:
            await client.aclose()

    first, second, requests_after_first = asyncio.run(run())
    assert [h["asset_id"] for h in first["hosts"]] == ["b", "a"] and [h["asset_id"] for h in second["hosts"]] == ["c"]
    assert len(api.requests) == requests_after_first  # the second page came from the cache


def test_cache_key_covers_the_filters_and_expires():
    async def run():
        calls = []

        async def compute_for(value):
            calls.append(value)
            return value

        cache = vuln.SearchCache(ttl_seconds=0.05)
        a = await cache.get_or_compute(("q", "high"), lambda: compute_for("high"))
        b = await cache.get_or_compute(("q", "low"), lambda: compute_for("low"))
        again = await cache.get_or_compute(("q", "high"), lambda: compute_for("never"))
        await asyncio.sleep(0.08)
        expired = await cache.get_or_compute(("q", "high"), lambda: compute_for("fresh"))
        return a, b, again, expired, calls

    assert asyncio.run(run()) == ("high", "low", "high", "fresh", ["high", "low", "fresh"])


def test_concurrent_identical_searches_share_one_run_and_errors_are_not_cached():
    async def run():
        runs = 0

        async def slow():
            nonlocal runs
            runs += 1
            await asyncio.sleep(0.05)
            return "ok"

        async def broken():
            raise ApiError(500, "BOOM", "failed")

        cache = vuln.SearchCache()
        shared = await asyncio.gather(*(cache.get_or_compute("k", slow) for _ in range(5)))
        with pytest.raises(ApiError):
            await cache.get_or_compute("bad", broken)
        recovered = await cache.get_or_compute("bad", slow)
        return shared, runs, recovered

    shared, runs, recovered = asyncio.run(run())
    assert shared == ["ok"] * 5 and runs == 2 and recovered == "ok"  # one shared run, plus the retry after the error


def test_cache_evicts_the_oldest_entry():
    async def run():
        cache = vuln.SearchCache(max_entries=2)
        for key in ("a", "b", "c"):
            await cache.get_or_compute(key, lambda key=key: _value(key))
            await asyncio.sleep(0.01)
        return sorted(cache._done)

    async def _value(key):
        return key

    assert asyncio.run(run()) == ["b", "c"]


def test_brief_rows_show_what_is_vulnerable_and_where_it_comes_from():
    api = FakeApi()
    api.json("/api/vulnerabilities", {"total": 1, "rows": [vuln_row("id:1", vulnerability_id="V-1", cve="CVE-1")]})
    api.json(
        "/api/vulnerabilities/hosts",
        {
            "total": 2,
            "rows": [
                host_row(
                    "a",
                    sources=["software", "docker"],
                    objects=["openssl 1.1.1k", "libssl 1.1.1", "curl 7.68", "extra 1"],
                    docker_images=["registry.corp/app:1.2.3"],
                ),
                host_row("b", objects=["x" * 500]),
            ],
        },
    )
    result = _find(api, query="CVE-1", detail="brief")
    rows = {row[0]: dict(zip(result["host_columns"], row, strict=True)) for row in result["hosts"]}
    assert rows["a"]["src"] == "software/docker"
    assert rows["a"]["component"] == "openssl 1.1.1k; libssl 1.1.1; curl 7.68; registry.corp/app:1.2.3"  # three objects + image
    assert len(rows["b"]["component"]) == vuln.MAX_COMPONENT_CHARS
