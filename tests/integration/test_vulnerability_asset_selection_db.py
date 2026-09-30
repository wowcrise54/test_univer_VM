"""Asset selection must remain scoped when drilling into a vulnerability."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import db, main
from app.repositories.vulnerabilities import VulnerabilityAnalyticsRepository

pytestmark = pytest.mark.integration
SELECTOR = "id:shared-vulnerability"


@pytest.fixture()
def two_assets(test_db):
    current = db.now_utc()
    with db.connect() as conn:
        for asset_id in ("asset-a", "asset-b"):
            conn.execute(
                """INSERT INTO asset_cards(asset_id, display_name, asset_type, first_seen, last_seen)
                   VALUES (%s, %s, 'host', %s, %s)""",
                (asset_id, asset_id, current, current),
            )
            group = conn.execute(
                """INSERT INTO asset_card_vulnerability_groups
                   (asset_id, source_type, collection_type, collection_id, name,
                    vulnerability_count, group_order, updated_at)
                   VALUES (%s, 'os', 'os', 'os-1', 'Linux', 1, 0, %s) RETURNING id""",
                (asset_id, current),
            ).fetchone()
            conn.execute(
                """INSERT INTO asset_card_vulnerabilities
                   (asset_id, group_id, vulnerability_instance_id, vulnerability_id, cve_name,
                    name, severity, updated_at)
                   VALUES (%s, %s, %s, 'shared-vulnerability', 'CVE-2026-1001',
                           'Shared finding', 'high', %s)""",
                (asset_id, group["id"], f"finding-{asset_id}", current),
            )


def test_host_drilldown_filters_asset_before_count_and_pagination(two_assets):
    repository = VulnerabilityAnalyticsRepository()
    selected = repository.hosts(selector=SELECTOR, asset_id="asset-b", limit=1)
    assert selected["total"] == 1
    assert [row["asset_id"] for row in selected["rows"]] == ["asset-b"]
    assert selected["selection"]["affected_hosts"] == 1
    assert selected["selection"]["findings"] == 1
    assert repository.hosts(selector=SELECTOR, asset_id="asset-b", offset=1)["rows"] == []
    assert repository.hosts(selector=SELECTOR, asset_id="missing")["total"] == 0
    assert repository.hosts(selector=SELECTOR, asset_id="asset-b' OR 1=1 --")["total"] == 0


def test_unfiltered_host_drilldown_preserves_existing_contract(two_assets):
    result = VulnerabilityAnalyticsRepository().hosts(selector=SELECTOR)
    assert result["total"] == 2
    assert {row["asset_id"] for row in result["rows"]} == {"asset-a", "asset-b"}
    assert result["selection"]["affected_hosts"] == 2


def test_http_drilldown_keeps_summary_list_and_hosts_on_same_asset(two_assets):
    with patch.object(main.app_auth, "get_session_user", return_value={"id": 1, "role": "viewer"}):
        client = TestClient(main.app)
        summary = client.get("/api/vulnerabilities/summary", params={"asset_id": "asset-b"})
        listing = client.get("/api/vulnerabilities", params={"asset_id": "asset-b"})
        hosts = client.get("/api/vulnerabilities/hosts", params={"selector": SELECTOR, "asset_id": "asset-b"})
    assert summary.status_code == listing.status_code == hosts.status_code == 200
    assert summary.json()["totals"]["affected_hosts"] == 1
    assert listing.json()["rows"][0]["affected_hosts"] == 1
    assert hosts.json()["total"] == 1
    assert [row["asset_id"] for row in hosts.json()["rows"]] == ["asset-b"]
