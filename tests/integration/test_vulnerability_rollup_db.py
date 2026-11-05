"""The selector rollup stays exact under every kind of write and serves the unfiltered list."""

import json

import pytest

from app import db
from app.repositories import vulnerabilities as vulnerabilities_module
from app.repositories.vulnerabilities import VulnerabilityAnalyticsRepository

pytestmark = pytest.mark.integration

ROLLUP_COLUMNS = (
    "selector, vulnerability_id, cve, name, severity_rank, cvss_score, affected_hosts, findings, "
    "affected_objects, components, sources, docker_containers, docker_images, severity_ranks, cves"
)
HOST_COLUMNS = (
    "asset_id, findings, unique_vulnerabilities, high_risk_vulnerabilities, severity_rank, cvss_score, "
    "sources, findings_critical, findings_high, findings_medium, findings_low, findings_unknown"
)


def _drift() -> int:
    """Rows that differ between the stored rollups and a fresh aggregate of the findings."""
    with db.connect() as conn:
        return conn.execute(
            f"""SELECT
                (SELECT count(*) FROM (SELECT {ROLLUP_COLUMNS} FROM vulnerability_rollup
                                       EXCEPT SELECT {ROLLUP_COLUMNS} FROM vulnerability_rollup_source) AS stale)
              + (SELECT count(*) FROM (SELECT {ROLLUP_COLUMNS} FROM vulnerability_rollup_source
                                       EXCEPT SELECT {ROLLUP_COLUMNS} FROM vulnerability_rollup) AS missing)
              + (SELECT count(*) FROM (SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup
                                       EXCEPT SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup_source) AS stale_hosts)
              + (SELECT count(*) FROM (SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup_source
                                       EXCEPT SELECT {HOST_COLUMNS} FROM vulnerability_host_rollup) AS missing_hosts) AS n"""
        ).fetchone()["n"]


def _insert_group(conn, asset_id, source, name, order, group_json=None):
    return conn.execute(
        """INSERT INTO asset_card_vulnerability_groups
           (asset_id, source_type, collection_type, collection_id, name, vulnerability_count,
            group_order, group_json, updated_at)
           VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s) RETURNING id""",
        (asset_id, source, source, f"{source}-{order}", name, order, json.dumps(group_json or {}), db.now_utc()),
    ).fetchone()["id"]


def _insert_finding(conn, asset_id, group_id, instance, vid=None, cve=None, name=None, severity="high",
                    cvss=None, finding_json=None):
    return conn.execute(
        """INSERT INTO asset_card_vulnerabilities
           (asset_id, group_id, vulnerability_instance_id, vulnerability_id, cve_name, name, severity,
            cvss_score, vulnerability_json, updated_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (asset_id, group_id, instance, vid, cve, name, severity, cvss, json.dumps(finding_json or {}), db.now_utc()),
    ).fetchone()["id"]


@pytest.fixture()
def dataset(test_db):
    current = db.now_utc()
    ids: dict[str, int] = {}
    with db.connect() as conn:
        for number, asset_id in enumerate(("asset-a", "asset-b", "asset-c"), start=1):
            conn.execute(
                "INSERT INTO asset_cards(asset_id, display_name, asset_type, first_seen, last_seen) "
                "VALUES (%s, %s, 'host', %s, %s)",
                (asset_id, asset_id, current, f"2026-11-0{number}"),
            )
        a_os = _insert_group(conn, "asset-a", "os", "Ubuntu", 0)
        a_soft = _insert_group(conn, "asset-a", "software", "OpenSSL  package", 1)
        a_docker = _insert_group(conn, "asset-a", "docker", "web", 2, {"image_name": "nginx:1"})
        b_os = _insert_group(conn, "asset-b", "os", "Windows", 0)
        b_soft = _insert_group(conn, "asset-b", "software", "OpenSSL package", 1)
        c_docker = _insert_group(conn, "asset-c", "docker", "api", 0)
        ids["a_soft"] = a_soft
        # The same vulnerability on several hosts, groups and severities.
        _insert_finding(conn, "asset-a", a_os, "a1", vid="P-1", cve="CVE-2026-0001", name="Kernel",
                        severity="critical", cvss=9.8)
        _insert_finding(conn, "asset-b", b_os, "b1", vid="P-1", cve="CVE-2026-0001", name="Kernel",
                        severity="high", cvss=7.5)
        _insert_finding(conn, "asset-a", a_soft, "a2", vid="P-2", severity="medium", cvss=5.0)
        _insert_finding(conn, "asset-a", a_soft, "a3", vid="P-2", severity="low", cvss=2.0)
        _insert_finding(conn, "asset-b", b_soft, "b2", vid="P-2", severity=None)
        # Selectors derived from cve, from name and from the instance id only.
        _insert_finding(conn, "asset-a", a_soft, "a4", cve="cve-2026-0003", severity="Critical")
        _insert_finding(conn, "asset-b", b_soft, "b3", name="Heap   overflow", severity="high")
        _insert_finding(conn, "asset-b", b_os, "b4", severity="weird")
        # Docker findings carry container and image names in their JSON.
        _insert_finding(conn, "asset-a", a_docker, "a5", vid="P-3", severity="high",
                        finding_json={"container_name": "web-1", "docker_image": {"image_name": "nginx:1"}})
        _insert_finding(conn, "asset-c", c_docker, "c1", vid="P-3", severity="high",
                        finding_json={"docker_container": {"container_name": "api-1"}, "image_id": "sha256:abc"})
        # A finding without any identity is ignored by every aggregate.
        _insert_finding(conn, "asset-c", c_docker, "  ", severity="high")
    return ids


def test_rollup_is_backfilled_and_matches_the_live_aggregate(dataset):
    with db.connect() as conn:
        count = conn.execute("SELECT count(*) AS n FROM vulnerability_rollup").fetchone()["n"]
    # P-1, P-2, cve:..0003, name:heap overflow, instance:b4 (weird severity), P-3
    assert count == 6
    assert _drift() == 0


@pytest.mark.parametrize("sort_by", [None, "affected_hosts", "findings", "severity", "cvss_score", "name", "cve"])
@pytest.mark.parametrize("sort_dir", ["asc", "desc"])
def test_rollup_list_equals_the_live_aggregate(dataset, monkeypatch, sort_by, sort_dir):
    repository = VulnerabilityAnalyticsRepository()
    monkeypatch.setattr(vulnerabilities_module, "ROLLUP_ENABLED", False)
    live = repository.list(limit=50, sort_by=sort_by, sort_dir=sort_dir)
    monkeypatch.setattr(vulnerabilities_module, "ROLLUP_ENABLED", True)
    fast = repository.list(limit=50, sort_by=sort_by, sort_dir=sort_dir)
    assert fast == live
    assert fast["total"] == 6


def test_rollup_pagination_matches_the_live_aggregate(dataset, monkeypatch):
    repository = VulnerabilityAnalyticsRepository()
    pages = {}
    for enabled in (False, True):
        monkeypatch.setattr(vulnerabilities_module, "ROLLUP_ENABLED", enabled)
        pages[enabled] = [repository.list(limit=2, offset=offset) for offset in (0, 2, 4, 6)]
    assert pages[True] == pages[False]


def test_filtered_and_fix_sorted_lists_use_the_live_aggregate(dataset, monkeypatch):
    calls = []
    monkeypatch.setattr(
        VulnerabilityAnalyticsRepository, "_rollup_page", lambda *args, **kwargs: calls.append(1) or (0, [])
    )
    repository = VulnerabilityAnalyticsRepository()
    assert repository.list(severity="critical")["total"] == 2
    repository.list(sort_by="has_fix")
    repository.list(sort_by="last_seen")
    assert calls == []


def test_inserts_deletes_and_updates_keep_the_rollup_exact(dataset):
    with db.connect() as conn:
        group = _insert_group(conn, "asset-b", "software", "Brand new", 9)
        new_id = _insert_finding(conn, "asset-b", group, "n1", vid="P-9", severity="critical", cvss=10)
    assert _drift() == 0
    with db.connect() as conn:
        conn.execute("UPDATE asset_card_vulnerabilities SET severity = 'low', cvss_score = 1 WHERE id = %s", (new_id,))
        conn.execute("UPDATE asset_card_vulnerabilities SET vulnerability_id = 'P-1' WHERE id = %s", (new_id,))
    assert _drift() == 0
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_card_vulnerabilities WHERE id = %s", (new_id,))
    assert _drift() == 0
    with db.connect() as conn:
        gone = conn.execute("SELECT count(*) AS n FROM vulnerability_rollup WHERE selector = 'id:P-9'").fetchone()["n"]
    assert gone == 0


def test_group_and_card_deletes_cascade_into_the_rollup(dataset):
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_card_vulnerability_groups WHERE id = %s", (dataset["a_soft"],))
    assert _drift() == 0
    with db.connect() as conn:
        conn.execute("DELETE FROM asset_cards WHERE asset_id = 'asset-b'")
    assert _drift() == 0
    with db.connect() as conn:
        left = conn.execute("SELECT affected_hosts FROM vulnerability_rollup").fetchall()
    assert left and all(row["affected_hosts"] >= 1 for row in left)


def test_changing_a_group_refreshes_the_rollup(dataset):
    with db.connect() as conn:
        conn.execute("UPDATE asset_card_vulnerability_groups SET name = 'Renamed' WHERE id = %s", (dataset["a_soft"],))
    assert _drift() == 0


def _card(asset_id, instance, vulnerability_id):
    return {
        "asset_id": asset_id,
        "vulnerabilities": {"sources": [{
            "source": "os", "collection_type": "os", "groups": [{
                "collection_id": "os-1", "name": "Linux", "items": [{
                    "vulnerability_id": vulnerability_id, "vulnerability_instance_id": instance,
                }],
            }],
        }]},
    }


def test_card_save_and_delete_through_the_application_keep_the_rollup_exact(test_db):
    db.upsert_asset_card(_card("host-1", "f1", "P-1"))
    db.upsert_asset_card(_card("host-2", "f2", "P-1"))
    assert _drift() == 0
    with db.connect() as conn:
        row = conn.execute(
            "SELECT affected_hosts, findings FROM vulnerability_rollup WHERE selector = 'id:P-1'"
        ).fetchone()
    assert (row["affected_hosts"], row["findings"]) == (2, 2)
    db.upsert_asset_card(_card("host-1", "f1", "P-2"))  # replaces host-1's findings
    assert _drift() == 0
    db.delete_asset_card("host-2")
    assert _drift() == 0
    with db.connect() as conn:
        selectors = [r["selector"] for r in conn.execute("SELECT selector FROM vulnerability_rollup")]
    assert selectors == ["id:P-2"]


def _both_summaries(monkeypatch):
    repository = VulnerabilityAnalyticsRepository()
    monkeypatch.setattr(vulnerabilities_module, "ROLLUP_ENABLED", False)
    live = repository.summary()
    monkeypatch.setattr(vulnerabilities_module, "ROLLUP_ENABLED", True)
    return live, repository.summary()


def test_rollup_summary_equals_the_live_aggregate(dataset, monkeypatch):
    live, fast = _both_summaries(monkeypatch)
    assert fast == live
    assert fast["totals"]["affected_hosts"] == 3
    assert [row["severity"] for row in fast["by_severity"]] == ["critical", "high", "medium", "low", "unknown"]
    assert fast["top_hosts"] and fast["top_vulnerabilities"]


def test_rollup_summary_equals_the_live_aggregate_after_more_writes(dataset, monkeypatch):
    with db.connect() as conn:
        group = _insert_group(conn, "asset-c", "software", "New package", 5)
        _insert_finding(conn, "asset-c", group, "x1", vid="P-1", severity="low")
        _insert_finding(conn, "asset-c", group, "x2", cve="CVE-2026-0001", severity="critical", cvss=9.9)
        conn.execute("DELETE FROM asset_card_vulnerabilities WHERE vulnerability_instance_id = 'a5'")
    live, fast = _both_summaries(monkeypatch)
    assert _drift() == 0
    assert fast == live


def test_rollup_summary_equals_the_live_aggregate_on_an_empty_database(test_db, monkeypatch):
    live, fast = _both_summaries(monkeypatch)
    assert fast == live
    assert fast["totals"]["findings"] == 0 and fast["by_severity"] == []


def test_filtered_summary_uses_the_live_aggregate(dataset, monkeypatch):
    calls = []
    monkeypatch.setattr(
        VulnerabilityAnalyticsRepository, "_rollup_summary_rows", lambda *args, **kwargs: calls.append(1)
    )
    result = VulnerabilityAnalyticsRepository().summary(severity="critical")
    assert calls == []
    assert result["totals"]["findings"] == 2
