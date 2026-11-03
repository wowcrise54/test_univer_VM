"""Integration: the MCP server against the real API, RBAC and PostgreSQL.

The MCP server logs in as a dedicated ``viewer`` account over the application's
ASGI interface, so these tests pin what that account can see and, just as
important, that it cannot change anything.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from mcp import Client

from app import auth, db, main
from mcp_server.client import ApiError, AppClient
from mcp_server.server import build_server
from tests.mcp_server.fakes import make_settings

pytestmark = pytest.mark.integration

PASSWORD = "S3cure-Passw0rd!"


def _make_user(username: str, role: str) -> None:
    current = db.now_utc()
    with db.connect() as conn:
        row = conn.execute(
            """INSERT INTO app_users(username,display_name,password_hash,is_active,created_at,updated_at)
               VALUES(%s,%s,%s,TRUE,%s,%s) RETURNING id""",
            (username, username.title(), auth.hash_password(PASSWORD), current, current),
        ).fetchone()
        role_row = conn.execute("SELECT id FROM app_roles WHERE role_key=%s", (role,)).fetchone()
        assert row is not None and role_row is not None
        conn.execute("INSERT INTO app_user_roles(user_id,role_id) VALUES(%s,%s)", (row["id"], role_row["id"]))


def _card(conn, asset_id: str, name: str, ip: str, last_seen: datetime) -> None:
    conn.execute(
        "INSERT INTO asset_cards(asset_id,display_name,hostname,ip_address,os_name,asset_type,first_seen,last_seen) "
        "VALUES(%s,%s,%s,%s,'Linux','Server',%s,%s)",
        (asset_id, name, name, ip, db.now_utc(), last_seen.isoformat()),
    )


def _finding(conn, asset_id: str, vulnerability_id: str, cve: str, *, severity: str = "high") -> int:
    group = conn.execute(
        """INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at)
           VALUES(%s,'software','software','software',0,%s) ON CONFLICT(asset_id,source_type,collection_id)
           DO UPDATE SET updated_at=EXCLUDED.updated_at RETURNING id""",
        (asset_id, db.now_utc()),
    ).fetchone()
    row = conn.execute(
        """INSERT INTO asset_card_vulnerabilities(asset_id,group_id,vulnerability_id,cve_name,name,severity,cvss_score,updated_at)
           VALUES(%s,%s,%s,%s,%s,%s,8.1,%s) RETURNING id""",
        (asset_id, group["id"], vulnerability_id, cve, f"vulnerability {cve}", severity, db.now_utc()),
    ).fetchone()
    return int(row["id"])


def _passport(conn, internal_id: str, finding_id: int, detail: dict[str, Any] | None) -> None:
    now = db.now_utc()
    conn.execute(
        """INSERT INTO vulnerability_passports(internal_id,external_id,name,severity,cves_json,raw_detail_json,
                                               first_seen,last_seen,detail_updated_at)
           VALUES(%s,%s,%s,'high','[]',%s,%s,%s,%s)""",
        (internal_id, f"PT-{internal_id}", f"passport {internal_id}", json.dumps(detail) if detail else None, now, now, now if detail else None),
    )
    conn.execute(
        "INSERT INTO asset_card_vulnerability_passports(asset_vulnerability_id,passport_internal_id,match_method,linked_at) "
        "VALUES(%s,%s,'vulner_id',%s)",
        (finding_id, internal_id, now),
    )


@pytest.fixture
def seeded(test_db):
    now = datetime.now(UTC)
    with db.connect() as conn:
        _card(conn, "web-1", "web-1", "10.0.0.1", now - timedelta(days=1))
        _card(conn, "web-2", "web-2", "10.0.0.2", now - timedelta(days=40))
        _card(conn, "db-1", "db-1", "10.0.0.3", now - timedelta(days=1))
        # Fix described in the passport.
        _passport(conn, "p-3094", _finding(conn, "web-1", "V-3094", "CVE-2024-3094"), {"howToFix": "Upgrade xz to 5.6.2"})
        conn.execute(
            "INSERT INTO asset_card_vulnerability_passports(asset_vulnerability_id,passport_internal_id,match_method,linked_at) "
            "VALUES(%s,'p-3094','vulner_id',%s)",
            (_finding(conn, "web-2", "V-3094", "CVE-2024-3094"), db.now_utc()),
        )
        # Passport known, but without a fix.
        _passport(conn, "p-9999", _finding(conn, "db-1", "V-9999", "CVE-2024-9999"), {"description": "no fix yet"})
        # No passport at all, and a CVE that only contains the searched text.
        _finding(conn, "web-1", "V-1111", "CVE-2024-1111")
        _finding(conn, "db-1", "V-30940", "CVE-2024-30940")
    _make_user("mcp-viewer", "viewer")
    _make_user("mcp-operator", "operator")


def _client(username: str = "mcp-viewer") -> AppClient:
    settings = make_settings(username=username, password=PASSWORD)
    return AppClient(settings, transport=httpx2.ASGITransport(app=main.app))


def _call(tool: str, arguments: dict[str, Any], username: str = "mcp-viewer") -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        client = _client(username)
        server = build_server(make_settings(), client)
        try:
            async with Client(server) as mcp_client:
                result = await mcp_client.call_tool(tool, arguments)
        finally:
            await client.aclose()
        assert not result.is_error, result.content
        return json.loads(result.content[0].text)

    return asyncio.run(run())


def test_find_hosts_by_cve_lists_hosts_with_fix_and_freshness(seeded):
    payload = _call("find_hosts_by_vulnerability", {"query": "CVE-2024-3094"})

    assert payload["match"] == "exact"
    assert {host["asset_id"] for host in payload["hosts"]} == {"web-1", "web-2"}
    assert payload["total_hosts"] == 2 and payload["stale_hosts"] == 1
    by_id = {host["asset_id"]: host for host in payload["hosts"]}
    assert by_id["web-1"]["stale"] is False and by_id["web-2"]["stale"] is True
    fix = payload["vulnerabilities"][0]["fix"]
    assert fix["status"] == "available" and "xz" in fix["how_to_fix"]
    assert payload["data_source"]["coverage"] is not None


def test_find_hosts_by_vulnerability_id_and_fix_states(seeded):
    by_id = _call("find_hosts_by_vulnerability", {"query": "V-9999"})
    assert [host["asset_id"] for host in by_id["hosts"]] == ["db-1"]
    assert by_id["vulnerabilities"][0]["fix"]["status"] == "not_described"

    unlinked = _call("get_vulnerability_fix_info", {"query": "CVE-2024-1111"})
    assert unlinked["vulnerabilities"][0]["fix"]["status"] == "unknown"
    assert unlinked["vulnerabilities"][0]["fix"]["has_fix"] is None


def test_substring_of_another_cve_is_not_reported_as_a_host_of_it(seeded):
    payload = _call("find_hosts_by_vulnerability", {"query": "CVE-2024-3094"})
    assert "db-1" not in {host["asset_id"] for host in payload["hosts"]}  # db-1 only has CVE-2024-30940


def test_no_match_returns_an_empty_answer_not_an_error(seeded):
    payload = _call("find_hosts_by_vulnerability", {"query": "CVE-1999-0001"})
    assert (payload["match"], payload["total_hosts"]) == ("none", 0)


def test_other_read_tools_work_for_a_viewer(seeded):
    summary = _call("vulnerability_summary", {})
    assert summary["totals"]["affected_hosts"] == 3
    host_vulns = _call("list_host_vulnerabilities", {"asset_id": "web-1"})
    assert {row["cve"] for row in host_vulns["rows"]} == {"CVE-2024-3094", "CVE-2024-1111"}
    searched = _call("search_vulnerabilities", {"has_fix": "yes"})
    assert [row["cve"] for row in searched["rows"]] == ["CVE-2024-3094"]
    assert _call("get_host", {"asset_id": "web-1"})["asset_id"] == "web-1"
    assert _call("find_hosts", {"q": "web"})
    for tool in ("remediation_summary", "data_freshness", "list_scan_tasks", "list_operations", "risk_queue"):
        assert _call(tool, {}) is not None, tool


def test_the_viewer_account_cannot_change_anything(seeded):
    async def run() -> list[int]:
        client = _client()
        try:
            await client.get("/api/auth/me")  # logs in and stores the session cookie
            cookie = {"Cookie": f"mpvm_app_session={client._cookie}"}
            statuses = []
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=main.app), base_url="http://testserver", headers=cookie
            ) as raw:
                statuses.append(
                    (
                        await raw.post(
                            "/api/remediation/cases/start",
                            json={"asset_id": "web-1", "vulnerability_selector": "id:V-3094"},
                        )
                    ).status_code
                )
                statuses.append((await raw.post("/api/asset-cards/web-1/refresh-scan", json={})).status_code)
                statuses.append((await raw.delete("/api/asset-cards/web-1")).status_code)
            return statuses
        finally:
            await client.aclose()

    assert asyncio.run(run()) == [403, 403, 403]


def test_a_wrong_password_is_reported_without_leaking_secrets(seeded):
    async def run() -> ApiError:
        client = AppClient(
            make_settings(username="mcp-viewer", password="definitely-wrong-1"),
            transport=httpx2.ASGITransport(app=main.app),
        )
        try:
            with pytest.raises(ApiError) as caught:
                await client.get("/api/vulnerabilities")
            return caught.value
        finally:
            await client.aclose()

    error = asyncio.run(run())
    assert error.status == 401 and error.code == "INVALID_CREDENTIALS"
    assert "definitely-wrong-1" not in str(error)
