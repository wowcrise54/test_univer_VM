from __future__ import annotations

import asyncio

import httpx2

from mcp_server import vulnerabilities as vuln
from mcp_server.client import AppClient
from tests.mcp_server.fakes import FakeApi, host_row, iso_ago, make_settings, vuln_row


def test_match_rows_prefers_exact_cve_over_substring_hits():
    rows = [
        vuln_row("id:1", vulnerability_id="V-1", cve="CVE-2024-1"),
        vuln_row("cve:CVE-2024-10", cve="CVE-2024-10"),
        vuln_row("id:3", vulnerability_id="V-3", cve="CVE-2024-1, CVE-2024-99"),
    ]
    matched, kind = vuln.match_rows(rows, " cve-2024-1 ")
    assert kind == "exact"
    assert [row["selector"] for row in matched] == ["id:1", "id:3"]


def test_match_rows_by_vulnerability_id_and_name_and_partial_fallback():
    rows = [vuln_row("id:1", vulnerability_id="PT-2024-77", cve="CVE-1", name="OpenSSL overflow")]
    assert vuln.match_rows(rows, "pt-2024-77")[1] == "exact"
    assert vuln.match_rows(rows, "openssl overflow")[1] == "exact"
    matched, kind = vuln.match_rows(rows, "openssl")
    assert (kind, len(matched)) == ("partial", 1)
    assert vuln.match_rows([], "anything") == ([], "none")


def test_fix_info_tells_apart_available_not_described_and_unknown():
    available = vuln.fix_info({"has_fix": True, "how_to_fix": "Update to 1.2.3", "passports": [{"external_id": "P1"}]})
    assert (available["status"], available["has_fix"]) == ("available", True)
    assert available["how_to_fix"] == "Update to 1.2.3"

    described = vuln.fix_info({"has_fix": False, "passports": [{"external_id": "P1", "has_detail": True}]})
    assert (described["status"], described["has_fix"]) == ("not_described", False)

    pending = vuln.fix_info({"has_fix": False, "passports": [{"external_id": "P1", "has_detail": False}]})
    assert (pending["status"], pending["has_fix"]) == ("unknown", None)
    assert "not loaded" in pending["reason"]

    unlinked = vuln.fix_info({"has_fix": False, "passports": []})
    assert (unlinked["status"], unlinked["has_fix"]) == ("unknown", None)
    assert "no vulnerability passport" in unlinked["reason"]


def test_fix_info_truncates_long_text():
    info = vuln.fix_info({"has_fix": True, "how_to_fix": "x" * (vuln.MAX_FIX_TEXT_CHARS + 50)})
    assert len(info["how_to_fix"]) == vuln.MAX_FIX_TEXT_CHARS
    assert info["how_to_fix_truncated"] is True


def test_host_staleness():
    assert vuln.host_staleness(iso_ago(1), stale_days=14)[1] is False
    age, stale = vuln.host_staleness(iso_ago(30), stale_days=14)
    assert stale is True and age is not None and age > 29
    assert vuln.host_staleness("not a date", stale_days=14) == (None, None)
    assert vuln.host_staleness("2026-01-01 10:00:00", stale_days=14)[1] is True


def _find(api: FakeApi, **kwargs):
    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            return await vuln.find_hosts_by_vulnerability(client, vuln.CoverageProbe(client), stale_days=14, **kwargs)
        finally:
            await client.aclose()

    return asyncio.run(run())


def _api_for_cve() -> FakeApi:
    api = FakeApi()
    api.json(
        "/api/vulnerabilities",
        {
            "total": 3,
            "rows": [
                vuln_row("id:100", vulnerability_id="V-100", cve="CVE-2024-3094", how_to_fix="Upgrade xz", has_fix=True),
                vuln_row("cve:CVE-2024-3094|source:docker", cve="CVE-2024-3094", sources=["docker"]),
                vuln_row("cve:CVE-2024-30940", cve="CVE-2024-30940"),
            ],
        },
    )

    def hosts(request: httpx2.Request) -> httpx2.Response:
        selector = request.url.params["selector"]
        rows = {
            "id:100": [
                host_row("a", severity="high", remediation={"case_id": "c1", "status": "in_progress", "overdue": True}),
                host_row("b", severity="critical", cvss_score=9.8, last_seen=iso_ago(40)),
            ],
            "cve:CVE-2024-3094|source:docker": [host_row("b", sources=["docker"]), host_row("c", severity="medium")],
        }[selector]
        return httpx2.Response(200, json={"total": len(rows), "rows": rows, "limit": 500, "offset": 0})

    api.routes["/api/vulnerabilities/hosts"] = hosts
    api.json("/api/vulnerabilities/summary", {"coverage": {"complete": True, "freshest_at": "2026-11-02T10:00:00Z"}})
    return api


def test_find_hosts_unions_selectors_and_ignores_substring_matches():
    result = _find(_api_for_cve(), query="CVE-2024-3094")

    assert result["match"] == "exact"
    assert [v["selector"] for v in result["vulnerabilities"]] == ["id:100", "cve:CVE-2024-3094|source:docker"]
    assert result["vulnerabilities"][0]["fix"]["status"] == "available"
    assert result["vulnerabilities"][1]["fix"]["status"] == "unknown"

    hosts = {h["asset_id"]: h for h in result["hosts"]}
    assert result["total_hosts"] == 3 and set(hosts) == {"a", "b", "c"}
    assert [h["asset_id"] for h in result["hosts"]] == ["b", "a", "c"]  # critical, high, medium
    assert sorted(hosts["b"]["selectors"]) == ["cve:CVE-2024-3094|source:docker", "id:100"]
    assert hosts["b"]["sources"] == ["docker", "software"]
    assert hosts["b"]["stale"] is True and hosts["a"]["stale"] is False
    assert result["stale_hosts"] == 1
    assert hosts["a"]["remediation"][0]["status"] == "in_progress"
    assert result["data_source"]["coverage"] == {"complete": True, "freshest_at": "2026-11-02T10:00:00Z"}
    assert "not from a live MP VM" in result["data_source"]["note"]
    assert result["truncated"] is False


def test_find_hosts_pages_the_result_after_merging():
    result = _find(_api_for_cve(), query="CVE-2024-3094", limit=2, offset=2)
    assert result["total_hosts"] == 3 and result["returned"] == 1
    assert [h["asset_id"] for h in result["hosts"]] == ["c"]


def test_find_hosts_passes_filters_and_only_reads():
    api = _api_for_cve()
    _find(api, query="CVE-2024-3094", severity="high", source="software", host_q="web")
    for request in api.data_requests():
        assert request.method == "GET"
    hosts_request = next(r for r in api.data_requests() if r.url.path.endswith("/hosts"))
    assert api.params(hosts_request)["host_q"] == "web"
    assert api.params(hosts_request)["severity"] == "high"
    assert api.params(hosts_request)["source"] == "software"


def test_find_hosts_with_no_match_returns_empty_answer():
    api = FakeApi()
    api.json("/api/vulnerabilities", {"total": 0, "rows": []})
    api.json("/api/vulnerabilities/summary", {"coverage": None})
    result = _find(api, query="CVE-1999-0001")
    assert (result["match"], result["total_hosts"], result["hosts"]) == ("none", 0, [])
    assert result["data_source"]["coverage"] is None


def test_collect_hosts_follows_pagination():
    api = FakeApi()
    pages = {0: [host_row(f"h{i}") for i in range(500)], 500: [host_row(f"h{i}") for i in range(500, 620)]}

    def hosts(request: httpx2.Request) -> httpx2.Response:
        offset = int(request.url.params["offset"])
        return httpx2.Response(200, json={"total": 620, "rows": pages[offset]})

    api.routes["/api/vulnerabilities/hosts"] = hosts

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            return await vuln.collect_hosts(client, "id:1")
        finally:
            await client.aclose()

    rows, total, truncated = asyncio.run(run())
    assert (len(rows), total, truncated) == (620, 620, False)


def test_get_fix_info_reports_status_per_vulnerability():
    api = _api_for_cve()

    async def run():
        client = AppClient(make_settings(), transport=api.transport())
        try:
            return await vuln.get_fix_info(client, query="CVE-2024-3094")
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert [v["fix"]["status"] for v in result["vulnerabilities"]] == ["available", "unknown"]
    assert "no fix is applied" in result["note"]
