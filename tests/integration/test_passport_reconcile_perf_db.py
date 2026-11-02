"""Passport reconciliation is scoped to relevant passports; field catalog is per asset."""
import json

import pytest

from app import db

pytestmark = pytest.mark.integration


def _passport(conn, internal_id, name, cves, now, detail=None):
    conn.execute(
        """
        INSERT INTO vulnerability_passports(internal_id, name, cves_json, raw_record_json, raw_detail_json, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (internal_id, name, json.dumps([{"displayName": c} for c in cves]), "{}", detail, now, now),
    )


def _finding(conn, asset_id, group_id, instance, vulnerability_id, cve, now):
    return conn.execute(
        """
        INSERT INTO asset_card_vulnerabilities(asset_id, group_id, vulnerability_instance_id, vulnerability_id, cve_name, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """,
        (asset_id, group_id, instance, vulnerability_id, cve, now),
    ).fetchone()["id"]


def test_reconcile_links_by_id_and_by_cve_and_ignores_unrelated_passports(test_db):
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO asset_cards(asset_id,display_name,os_name,first_seen,last_seen) VALUES('a','a','Ubuntu 22.04',%s,%s)",
            (now, now),
        )
        group_id = conn.execute(
            """
            INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at)
            VALUES('a','host','c','g1',0,%s) RETURNING id
            """,
            (now,),
        ).fetchone()["id"]
        _passport(conn, "P-ID", "by id", ["CVE-1-1"], now)
        _passport(conn, "P-GENERIC", "generic", ["CVE-2-2"], now)
        _passport(conn, "P-UBUNTU", "ubuntu fix", ["CVE-2-2"], now, detail="ubuntu")
        _passport(conn, "P-DEBIAN", "debian fix", ["CVE-2-2"], now, detail="debian")
        _passport(conn, "P-OTHER", "unrelated", ["CVE-9-9"], now)
        _passport(conn, "P-NOCVE", "no cve", [], now)
        f1 = _finding(conn, "a", group_id, "i1", "P-ID", None, now)
        f2 = _finding(conn, "a", group_id, "i2", None, "cve-2-2", now)
        f3 = _finding(conn, "a", group_id, "i3", None, "CVE-404", now)
        db.reconcile_asset_card_vulnerability_passport_links(conn, None, now, asset_id="a")
        links = {
            r["asset_vulnerability_id"]: (r["passport_internal_id"], r["match_method"])
            for r in conn.execute("SELECT * FROM asset_card_vulnerability_passports").fetchall()
        }
    assert links[f1] == ("P-ID", "vulner_id")
    assert links[f2] == ("P-UBUNTU", "cve_os")
    assert f3 not in links


def test_search_field_catalog_matches_search_index_and_is_replaced_per_asset(test_db):
    now = db.now_utc()
    with db.connect() as conn:
        for asset_id, host in (("a", "alpha"), ("b", "beta")):
            conn.execute(
                "INSERT INTO asset_cards(asset_id,display_name,hostname,first_seen,last_seen) VALUES(%s,%s,%s,%s,%s)",
                (asset_id, asset_id, host, now, now),
            )
            db.replace_asset_card_search_index(
                conn, asset_id, {"asset_id": asset_id, "display_name": asset_id, "hostname": host}, now
            )
        # Re-indexing must not duplicate catalog rows.
        db.replace_asset_card_search_index(conn, "a", {"asset_id": "a", "hostname": "alpha2"}, now)
    fields = {(r["field_path"], r["value_type"]): r for r in db.list_asset_card_search_fields(q="hostname")["rows"]}
    host = fields[("asset.hostname", "text")]
    assert host["asset_count"] == 2
    assert host["sample_value"] == "alpha2"
    expected = {
        (r["field_path"], r["value_type"]): r["asset_count"]
        for r in db.list_asset_card_search_fields(limit=500)["rows"]
    }
    with db.connect() as conn:
        raw = conn.execute(
            "SELECT field_path, value_type, COUNT(DISTINCT asset_id) AS n FROM asset_card_search_fields GROUP BY 1, 2"
        ).fetchall()
    assert {(r["field_path"], r["value_type"]): r["n"] for r in raw} == expected
