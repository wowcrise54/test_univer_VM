"""Passport reconciliation is scoped to relevant passports; field catalog is per asset."""
import itertools
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


def test_passport_cve_table_follows_passport_writes_and_tolerates_bad_json(test_db):
    now = db.now_utc()

    def cves():
        with db.connect() as conn:
            return sorted(
                (r["passport_internal_id"], r["cve_name"])
                for r in conn.execute("SELECT * FROM vulnerability_passport_cves").fetchall()
            )

    with db.connect() as conn:
        _passport(conn, "P1", "one", ["cve-1-1", "CVE-1-1", "CVE-2-2"], now)
        _passport(conn, "P2", "none", [], now)
        conn.execute(
            "INSERT INTO vulnerability_passports(internal_id, cves_json, first_seen, last_seen) VALUES ('BAD', 'not json', %s, %s)",
            (now, now),
        )
    assert cves() == [("P1", "CVE-1-1"), ("P1", "CVE-2-2")]
    with db.connect() as conn:
        conn.execute("UPDATE vulnerability_passports SET cves_json = %s WHERE internal_id = 'P1'", (json.dumps(["cve-3-3"]),))
    assert cves() == [("P1", "CVE-3-3")]
    with db.connect() as conn:
        conn.execute("DELETE FROM vulnerability_passports WHERE internal_id = 'P1'")
    assert cves() == []


def test_passport_os_family_follows_passport_text(test_db):
    now = db.now_utc()

    def family(internal_id):
        with db.connect() as conn:
            row = conn.execute(
                "SELECT os_family FROM vulnerability_passport_os_family WHERE passport_internal_id = %s",
                (internal_id,),
            ).fetchone()
        return row["os_family"] if row else "missing"

    with db.connect() as conn:
        _passport(conn, "W", "Windows fix", [], now)
        _passport(conn, "G", "generic", [], now)
        _passport(conn, "D", "generic", [], now, detail="patched in Debian")
    assert (family("W"), family("G"), family("D")) == ("windows", None, "debian")
    with db.connect() as conn:
        conn.execute("UPDATE vulnerability_passports SET raw_detail_json = 'red hat advisory' WHERE internal_id = 'D'")
    assert family("D") == "rhel"


def _links(conn):
    return {
        r["asset_vulnerability_id"]: r["passport_internal_id"]
        for r in conn.execute("SELECT * FROM asset_card_vulnerability_passports").fetchall()
    }


def test_reconcile_limited_to_changed_passports_leaves_other_links_alone(test_db):
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
        _passport(conn, "OLD", "generic", ["CVE-1-1"], now)
        _passport(conn, "OTHER", "other", ["CVE-9-9"], now)
        changed = _finding(conn, "a", group_id, "i1", None, "CVE-1-1", now)
        untouched = _finding(conn, "a", group_id, "i2", None, "CVE-9-9", now)
        # A deliberately stale link: only a full relink would repair it.
        conn.execute(
            "INSERT INTO asset_card_vulnerability_passports VALUES (%s, 'OLD', 'stale', %s)", (untouched, now)
        )
        db.reconcile_asset_card_vulnerability_passport_links(conn, None, now, asset_id="a")
        assert _links(conn) == {changed: "OLD", untouched: "OTHER"}
        conn.execute(
            "INSERT INTO asset_card_vulnerability_passports VALUES (%s, 'OLD', 'stale', %s) ON CONFLICT DO NOTHING", (untouched, now)
        )
        conn.execute("DELETE FROM asset_card_vulnerability_passports WHERE asset_vulnerability_id = %s", (untouched,))
        conn.execute(
            "INSERT INTO asset_card_vulnerability_passports VALUES (%s, 'OLD', 'stale', %s)", (untouched, now)
        )
        _passport(conn, "NEW", "ubuntu fix", ["CVE-1-1"], now, detail="ubuntu")
        assert db.reconcile_asset_card_vulnerability_passport_links(conn, ["NEW"], now) == 1
        links = _links(conn)
    assert links[changed] == "NEW"
    assert links[untouched] == "OLD"


def test_reconcile_without_scope_relinks_every_asset_in_chunks(test_db, monkeypatch):
    monkeypatch.setattr(db, "_RECONCILE_FULL_CHUNK_FINDINGS", 1)
    now = db.now_utc()
    with db.connect() as conn:
        _passport(conn, "P", "generic", ["CVE-1-1"], now)
        findings = []
        for asset in ("a", "b", "c"):
            conn.execute("INSERT INTO asset_cards(asset_id,display_name,first_seen,last_seen) VALUES(%s,%s,%s,%s)", (asset, asset, now, now))
            group_id = conn.execute(
                """
                INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at)
                VALUES(%s,'host','c','g',0,%s) RETURNING id
                """,
                (asset, now),
            ).fetchone()["id"]
            findings.append(_finding(conn, asset, group_id, f"i-{asset}", None, "CVE-1-1", now))
        assert db.reconcile_asset_card_vulnerability_passport_links(conn, None, now) == 3
        assert set(_links(conn)) == set(findings)


def test_upsert_passports_saves_in_batches_and_reports_progress(test_db, monkeypatch):
    monkeypatch.setattr(db, "PASSPORT_SAVE_BATCH_SIZE", 2)
    events = []
    result = db.upsert_vulnerability_passports(
        [{"internal_id": f"P{i}", "name": f"n{i}"} for i in range(5)],
        progress=lambda stage, done, total: events.append((stage, done, total)),
    )
    assert result["saved"] == 5
    assert [e for e in events if e[0] == "save"] == [("save", 2, 5), ("save", 4, 5), ("save", 5, 5)]
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM vulnerability_passports").fetchone()["n"] == 5


def _passport_state(internal_id):
    with db.connect() as conn:
        return conn.execute(
            "SELECT last_seen, source_pdql, name FROM vulnerability_passports WHERE internal_id = %s",
            (internal_id,),
        ).fetchone()


def _cve_rows():
    with db.connect() as conn:
        return sorted(
            (r["passport_internal_id"], r["cve_name"])
            for r in conn.execute("SELECT * FROM vulnerability_passport_cves").fetchall()
        )


def test_upsert_rewrites_only_changed_passports(test_db, monkeypatch):
    ticks = itertools.count()
    monkeypatch.setattr(db, "now_utc", lambda: f"2026-11-04T10:00:00.{next(ticks):06d}+00:00")
    passports = [
        {"internal_id": "P1", "name": "one", "cves": [{"displayName": "CVE-1-1"}]},
        {"internal_id": "P2", "name": "two", "cves": [{"displayName": "CVE-2-2"}]},
    ]
    first = db.upsert_vulnerability_passports(passports, source_pdql="q1")
    assert first["saved"] == 2 and first["changed"] == 2
    assert _cve_rows() == [("P1", "CVE-1-1"), ("P2", "CVE-2-2")]
    seen_before = _passport_state("P1")["last_seen"]

    # A trigger run would restore the deleted rows; unchanged passports must not run it.
    with db.connect() as conn:
        conn.execute("DELETE FROM vulnerability_passport_cves")
    again = db.upsert_vulnerability_passports(passports, source_pdql="q2")
    assert again["saved"] == 2 and again["changed"] == 0 and again["passport_links"] == 0
    assert _cve_rows() == []
    state = _passport_state("P1")
    assert state["last_seen"] != seen_before and state["source_pdql"] == "q2"

    passports[1] = {"internal_id": "P2", "name": "two", "cves": [{"displayName": "CVE-3-3"}]}
    changed = db.upsert_vulnerability_passports(passports, source_pdql="q2")
    assert changed["changed"] == 1
    assert _cve_rows() == [("P2", "CVE-3-3")]


def test_upsert_tolerates_repeated_internal_ids(test_db):
    result = db.upsert_vulnerability_passports(
        [{"internal_id": "P1", "name": "old"}, {"internal_id": "P1", "name": "new"}]
    )
    assert result["saved"] == 1
    assert _passport_state("P1")["name"] == "new"


def test_reconcile_of_very_many_passports_relinks_every_asset_instead(test_db, monkeypatch):
    monkeypatch.setattr(db, "_RECONCILE_TARGETED_MAX_PASSPORTS", 1)
    now = db.now_utc()
    with db.connect() as conn:
        conn.execute("INSERT INTO asset_cards(asset_id,display_name,first_seen,last_seen) VALUES('a','a',%s,%s)", (now, now))
        group_id = conn.execute(
            """
            INSERT INTO asset_card_vulnerability_groups(asset_id,source_type,collection_type,collection_id,group_order,updated_at)
            VALUES('a','host','c','g',0,%s) RETURNING id
            """,
            (now,),
        ).fetchone()["id"]
        _passport(conn, "P1", "one", ["CVE-1-1"], now)
        _passport(conn, "P2", "two", ["CVE-2-2"], now)
        _passport(conn, "OTHER", "other", ["CVE-9-9"], now)
        unrelated = _finding(conn, "a", group_id, "i-other", None, "CVE-9-9", now)
        # Only a relink of every finding (not just those of P1/P2) removes this stale link.
        conn.execute("INSERT INTO asset_card_vulnerability_passports VALUES (%s, 'P1', 'stale', %s)", (unrelated, now))
        db.reconcile_asset_card_vulnerability_passport_links(conn, ["P1", "P2"], now)
        assert _links(conn) == {unrelated: "OTHER"}
