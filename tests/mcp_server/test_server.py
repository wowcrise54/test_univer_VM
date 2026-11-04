from __future__ import annotations

import asyncio
from typing import Any

import httpx2
from mcp import Client

from mcp_server.client import AppClient
from mcp_server.server import build_server
from tests.mcp_server.fakes import FakeApi, body, host_row, make_settings, vuln_row

EXPECTED_TOOLS = {
    "find_hosts_by_vulnerability",
    "get_vulnerability_fix_info",
    "search_vulnerabilities",
    "list_host_vulnerabilities",
    "find_hosts",
    "get_host",
    "vulnerability_summary",
    "trending_vulnerabilities",
    "list_remediation_cases",
    "remediation_summary",
    "data_freshness",
    "list_scan_tasks",
    "list_operations",
    "risk_queue",
}


def _with_client(api: FakeApi, scenario: Any, **settings: Any):
    async def run():
        app_client = AppClient(make_settings(**settings), transport=api.transport())
        server = build_server(make_settings(**settings), app_client)
        try:
            async with Client(server) as mcp_client:
                return await scenario(mcp_client)
        finally:
            await app_client.aclose()

    return asyncio.run(run())


def _api() -> FakeApi:
    api = FakeApi()
    api.json(
        "/api/vulnerabilities",
        {
            "total": 1,
            "rows": [
                vuln_row(
                    "id:7",
                    vulnerability_id="V-7",
                    cve="CVE-2024-0001",
                    has_fix=True,
                    how_to_fix="Install KB500",
                    passports=[{"external_id": "PT-7", "has_detail": True}],
                )
            ],
        },
    )
    api.json(
        "/api/vulnerabilities/hosts",
        {"total": 1, "rows": [host_row("a", remediation={"case_id": "c", "status": "open", "overdue": False})]},
    )
    api.json("/api/vulnerabilities/summary", {"coverage": {"complete": False, "truncated_groups": 3}})
    return api


def test_server_lists_only_read_only_tools_with_valid_schemas():
    async def scenario(client: Client):
        return (await client.list_tools()).tools

    tools = _with_client(_api(), scenario)
    assert {tool.name for tool in tools} == EXPECTED_TOOLS
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
        assert tool.description, tool.name
        assert tool.input_schema["type"] == "object"
    find = next(tool for tool in tools if tool.name == "find_hosts_by_vulnerability")
    assert find.input_schema["required"] == ["query"]
    assert set(find.input_schema["properties"]) >= {"query", "severity", "source", "host_q", "limit", "offset"}


def test_find_hosts_tool_end_to_end_over_mcp():
    api = _api()

    async def scenario(client: Client):
        return await client.call_tool("find_hosts_by_vulnerability", {"query": "CVE-2024-0001", "include_coverage": True})

    result = _with_client(api, scenario)
    assert not result.is_error
    payload = body(result)
    assert payload["match"] == "exact" and payload["total_hosts"] == 1
    row = dict(zip(payload["host_columns"], payload["hosts"][0], strict=True))  # brief rows are the default
    assert row["asset_id"] == "a" and row["case"] == "open"
    assert payload["vulnerabilities"][0]["fix"]["status"] == "available"
    assert payload["vulnerabilities"][0]["fix"]["how_to_fix"] == "Install KB500"
    assert payload["data_source"]["coverage"]["complete"] is False
    assert {request.method for request in api.data_requests()} == {"GET"}


def test_fix_info_tool():
    async def scenario(client: Client):
        return await client.call_tool("get_vulnerability_fix_info", {"query": "V-7"})

    payload = body(_with_client(_api(), scenario))
    assert payload["vulnerabilities"][0]["fix"]["status"] == "available"


def test_tool_rejects_invalid_arguments():
    async def scenario(client: Client):
        return [
            await client.call_tool("find_hosts_by_vulnerability", {"query": "x"}),
            await client.call_tool("search_vulnerabilities", {"limit": 5000}),
            await client.call_tool("search_vulnerabilities", {"severity": "catastrophic"}),
        ]

    for result in _with_client(_api(), scenario):
        assert result.is_error


def test_api_errors_become_tool_errors():
    api = FakeApi()
    api.json(
        "/api/vulnerabilities", {"detail": {"code": "PERMISSION_DENIED", "message": "assets.read required"}}, status=403
    )

    async def scenario(client: Client):
        return await client.call_tool("search_vulnerabilities", {"q": "openssl"})

    result = _with_client(api, scenario)
    assert result.is_error
    assert "PERMISSION_DENIED" in result.content[0].text


def test_search_and_host_vulnerabilities_pass_filters_to_the_api():
    api = _api()

    async def scenario(client: Client):
        await client.call_tool("search_vulnerabilities", {"q": "ssl", "has_fix": "yes", "severity": "high", "limit": 7})
        await client.call_tool("list_host_vulnerabilities", {"asset_id": "asset/1", "source": "docker"})

    _with_client(api, scenario)
    search, host = api.data_requests()
    assert api.params(search) == {"q": "ssl", "has_fix": "yes", "severity": "high", "limit": "7", "offset": "0"}
    assert api.params(host)["asset_id"] == "asset/1" and api.params(host)["source"] == "docker"


def test_passthrough_tools_call_the_expected_endpoints():
    api = FakeApi()
    for path in (
        "/api/asset-cards/local",
        "/api/asset-cards/win%2F1",
        "/api/vulnerabilities/trending",
        "/api/remediation/cases",
        "/api/remediation/summary",
        "/api/remediation/resolution-stats",
        "/api/coverage/summary",
        "/api/coverage/assets",
        "/api/scanner-tasks",
        "/api/operations",
        "/api/operations/summary",
        "/api/risk/queue",
    ):
        api.json(path.replace("%2F", "/") if "%2F" in path else path, {"rows": []})
    api.routes["/api/scanner-tasks"] = lambda _r: httpx2.Response(200, json=[{"id": 1}])
    api.json("/api/vulnerabilities/summary", {"totals": {"findings": 1}, "top_vulnerabilities": [vuln_row("id:1")], "top_hosts": [host_row("a")]})

    calls = [
        ("find_hosts", {"q": "web"}),
        ("trending_vulnerabilities", {"context": "docker"}),
        ("list_remediation_cases", {"overdue": True, "status": "open"}),
        ("remediation_summary", {}),
        ("data_freshness", {"issue": "stale"}),
        ("list_scan_tasks", {}),
        ("list_operations", {"status": "running"}),
        ("risk_queue", {"level": "urgent"}),
        ("vulnerability_summary", {}),
    ]

    async def scenario(client: Client):
        return [(name, await client.call_tool(name, args)) for name, args in calls]

    for name, result in _with_client(api, scenario):
        assert not result.is_error, (name, result.content)
    paths = {request.url.path for request in api.data_requests()}
    assert {"/api/asset-cards/local", "/api/risk/queue", "/api/coverage/summary", "/api/operations/summary"} <= paths
    assert {request.method for request in api.data_requests()} == {"GET"}
    cases = next(r for r in api.data_requests() if r.url.path == "/api/remediation/cases")
    assert api.params(cases)["overdue"] == "true"


def test_get_host_quotes_the_asset_id():
    api = FakeApi()
    api.routes["/api/asset-cards/win/1"] = lambda _r: httpx2.Response(200, json={"asset_id": "win/1"})
    api.routes["/api/asset-cards/win%2F1"] = lambda _r: httpx2.Response(200, json={"asset_id": "win/1"})

    async def scenario(client: Client):
        return await client.call_tool("get_host", {"asset_id": "win/1"})

    result = _with_client(api, scenario)
    request = api.data_requests()[-1]
    assert request.url.raw_path.split(b"?")[0] == b"/api/asset-cards/win%2F1"
    assert not result.is_error or "NOT_FOUND" in result.content[0].text
