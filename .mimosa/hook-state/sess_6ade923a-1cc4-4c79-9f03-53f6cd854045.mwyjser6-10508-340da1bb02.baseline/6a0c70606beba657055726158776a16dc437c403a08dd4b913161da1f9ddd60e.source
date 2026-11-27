"""The stored ``selector`` column always equals the reference selector formula."""

import pytest

from app import db
from app.repositories.vulnerabilities import (
    VULNERABILITY_SELECTOR_REFERENCE_SQL,
    VulnerabilityAnalyticsRepository,
)

pytestmark = pytest.mark.integration

# (source_type, group name, vulnerability_id, cve_name, name, instance_id, expected selector)
CASES = [
    ("os", "Linux", "  pass-1  ", "CVE-2026-1", "x", "i1", "id:pass-1"),
    ("docker", "nginx", "pass-1", None, None, "i2", "id:pass-1|source:docker"),
    ("os", "Linux", "", " cve-2026-2 ", "x", "i3", "cve:CVE-2026-2"),
    ("docker", "Linux", "  ", "cve-2026-3", None, "i4", "cve:CVE-2026-3|source:docker"),
    ("software", "Some  Package", None, None, "Heap   overflow\t in\nlib", "i5",
     "name:heap overflow in lib|source:software|object:some package"),
    ("software", None, None, "", "Привилегии  Ядро", "i6", "name:привилегии ядро|source:software|object:"),
    ("software", "Pkg", None, None, None, " inst-7 ", "instance:inst-7"),
    ("software", "Pkg", None, None, None, None, None),
]


@pytest.fixture()
def findings(test_db):
    current = db.now_utc()
    ids: list[int] = []
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO asset_cards(asset_id, display_name, asset_type, first_seen, last_seen) "
            "VALUES ('asset-1', 'asset-1', 'host', %s, %s)",
            (current, current),
        )
        for index, (source, group_name, vid, cve, name, instance, _expected) in enumerate(CASES):
            group_id = conn.execute(
                """INSERT INTO asset_card_vulnerability_groups
                   (asset_id, source_type, collection_type, collection_id, name, vulnerability_count,
                    group_order, updated_at)
                   VALUES ('asset-1', %s, %s, %s, %s, 1, %s, %s) RETURNING id""",
                (source, source, f"c-{index}", group_name, index, current),
            ).fetchone()["id"]
            ids.append(
                conn.execute(
                    """INSERT INTO asset_card_vulnerabilities
                       (asset_id, group_id, vulnerability_instance_id, vulnerability_id, cve_name, name, updated_at)
                       VALUES ('asset-1', %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (group_id, instance, vid, cve, name, current),
                ).fetchone()["id"]
            )
    return ids


def _selectors() -> dict[int, str | None]:
    with db.connect() as conn:
        return {row["id"]: row["selector"] for row in conn.execute("SELECT id, selector FROM asset_card_vulnerabilities")}


def _mismatches_against_reference() -> int:
    with db.connect() as conn:
        return conn.execute(
            f"""SELECT count(*) AS n FROM asset_card_vulnerabilities AS finding
                JOIN asset_card_vulnerability_groups AS vulnerability_group
                  ON vulnerability_group.id = finding.group_id
                WHERE finding.selector IS DISTINCT FROM ({VULNERABILITY_SELECTOR_REFERENCE_SQL})"""
        ).fetchone()["n"]


def test_insert_fills_selector_matching_the_reference_formula(findings):
    stored = _selectors()
    assert [stored[i] for i in findings] == [case[-1] for case in CASES]
    assert _mismatches_against_reference() == 0


def test_updating_a_source_column_refreshes_the_selector(findings):
    with db.connect() as conn:
        conn.execute("UPDATE asset_card_vulnerabilities SET vulnerability_id = 'renamed' WHERE id = %s", (findings[0],))
        conn.execute("UPDATE asset_card_vulnerabilities SET cve_name = 'cve-2030-9' WHERE id = %s", (findings[2],))
    stored = _selectors()
    assert stored[findings[0]] == "id:renamed"
    assert stored[findings[2]] == "cve:CVE-2030-9"  # vulnerability_id is empty, so cve_name decides
    with db.connect() as conn:
        conn.execute("UPDATE asset_card_vulnerabilities SET cve_name = 'cve-2030-9' WHERE id = %s", (findings[3],))
    assert _selectors()[findings[3]] == "cve:CVE-2030-9|source:docker"
    assert _mismatches_against_reference() == 0


def test_changing_a_group_refreshes_the_selectors_of_its_findings(findings):
    with db.connect() as conn:
        conn.execute(
            "UPDATE asset_card_vulnerability_groups SET source_type = 'docker' WHERE collection_id = 'c-0'"
        )
        conn.execute(
            "UPDATE asset_card_vulnerability_groups SET name = 'Renamed  Package' WHERE collection_id = 'c-4'"
        )
    stored = _selectors()
    assert stored[findings[0]] == "id:pass-1|source:docker"
    assert stored[findings[4]] == "name:heap overflow in lib|source:software|object:renamed package"
    assert _mismatches_against_reference() == 0


def test_selector_filter_uses_the_stored_value(findings):
    hosts = VulnerabilityAnalyticsRepository().hosts(selector="id:pass-1|source:docker")
    assert hosts["total"] == 1
    assert hosts["rows"][0]["asset_id"] == "asset-1"


def test_card_save_through_copy_stores_selectors(test_db):
    card = {
        "asset_id": "host-1",
        "vulnerabilities": {"sources": [{
            "source": "docker", "collection_type": "docker", "groups": [{
                "collection_id": "docker-1", "name": "web", "items": [{
                    "vulnerability_id": "passport-1", "vulnerability_instance_id": "finding-1",
                }],
            }],
        }]},
    }
    db.upsert_asset_card(card)
    assert list(_selectors().values()) == ["id:passport-1|source:docker"]
    assert _mismatches_against_reference() == 0
