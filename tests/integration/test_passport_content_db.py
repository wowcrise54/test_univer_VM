from __future__ import annotations

import pytest

from app import db
from app.repositories.passport_content import partition_details

pytestmark = pytest.mark.integration


def _insert_passport(identifier: str, raw: str, when: str = "2026-01-01T00:00:00+00:00") -> None:
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO vulnerability_passports "
            "(internal_id, raw_detail_json, first_seen, last_seen, detail_updated_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (identifier, raw, when, when, when),
        )


def test_partition_details_compares_json_semantically_and_refreshes_unchanged(test_db):
    _insert_passport("same", '{"b": 2, "a": 1}')
    current = "2026-02-01T00:00:00+00:00"
    with db.connect() as conn:
        changed = partition_details(conn, [("same", {"a": 1, "b": 2})], current)
    assert changed == []
    with db.connect() as conn:
        row = conn.execute(
            "SELECT raw_detail_json, first_seen, last_seen, detail_updated_at "
            "FROM vulnerability_passports WHERE internal_id='same'"
        ).fetchone()
    assert row["raw_detail_json"] == '{"b": 2, "a": 1}'
    assert row["first_seen"] == "2026-01-01T00:00:00+00:00"
    assert row["last_seen"] == current
    assert row["detail_updated_at"] == current


def test_partition_details_preserves_list_order_and_marks_new_changed_and_corrupt(test_db):
    _insert_passport("changed", '{"items": [1, 2]}')
    _insert_passport("corrupt", "not-json")
    details = [
        ("new", {"items": [1]}),
        ("changed", {"items": [2, 1]}),
        ("corrupt", {"valid": True}),
    ]
    with db.connect() as conn:
        assert partition_details(conn, details, "2026-02-01T00:00:00+00:00") == details


def test_partition_details_does_not_update_content_for_equal_json(test_db):
    _insert_passport("same", '{"a": 1}')
    with db.connect() as conn:
        conn.execute("CREATE TEMP TABLE passport_content_audit (count integer NOT NULL DEFAULT 0)")
        conn.execute("INSERT INTO passport_content_audit DEFAULT VALUES")
        conn.execute(
            """CREATE OR REPLACE FUNCTION passport_content_audit_fn() RETURNS trigger
               LANGUAGE plpgsql AS $$ BEGIN
                 UPDATE passport_content_audit SET count = count + 1;
                 RETURN NEW;
               END $$"""
        )
        conn.execute(
            """CREATE TRIGGER passport_content_audit_trigger
               AFTER UPDATE OF raw_detail_json ON vulnerability_passports
               FOR EACH ROW EXECUTE FUNCTION passport_content_audit_fn()"""
        )
        try:
            assert partition_details(conn, [("same", {"a": 1})], "2026-02-01T00:00:00+00:00") == []
            assert conn.execute("SELECT count FROM passport_content_audit").fetchone()["count"] == 0
        finally:
            conn.execute("DROP TRIGGER IF EXISTS passport_content_audit_trigger ON vulnerability_passports")
            conn.execute("DROP FUNCTION IF EXISTS passport_content_audit_fn()")


def test_bulk_detail_save_preserves_loaded_and_processed_counts(test_db):
    db.upsert_vulnerability_passports([{"internal_id": "same", "name": "same"}, {"internal_id": "new", "name": "new"}])
    db.upsert_vulnerability_passport_detail("same", {"name": "same"})
    job = db.create_vulnerability_passport_detail_job(
        "content-test-job", requested_count=2, eligible_count=2, skipped_fresh_count=0
    )
    result = db.save_vulnerability_passport_detail_job_batch(
        job["job_id"],
        details=[("same", {"name": "same"}), ("new", {"name": "new"})],
        errors=[],
    )
    assert result["processed_count"] == 2
    assert result["loaded_count"] == 2
    assert result["failed_count"] == 0


def test_empty_partition_and_json_boolean_are_not_confused_with_numbers(test_db):
    _insert_passport("p", '{"exploited": true}')
    with db.connect() as conn:
        assert partition_details(conn, [], "2026-02-01T00:00:00+00:00") == []
        assert partition_details(conn, [("p", {"exploited": 1})], "2026-02-01T00:00:00+00:00") == [
            ("p", {"exploited": 1}),
        ]


def test_equivalent_numbers_do_not_rewrite_detail_content(test_db):
    detail = {"score": 1, "nested": [2, {"value": 3.0}]}
    db.upsert_vulnerability_passports([{"internal_id": "p", "score": "1"}])
    db.upsert_vulnerability_passport_detail("p", detail)
    with db.connect() as conn:
        assert partition_details(conn, [("p", {"score": 1.0, "nested": [2.0, {"value": 3}]})],
                                 "2026-02-01T00:00:00+00:00") == []


def test_equal_detail_repair_overwritten_normalized_catalog_fields(test_db):
    detail = {
        "name": "Detailed OpenSSL vulnerability",
        "severityRating": "Critical",
        "score": "9.8",
        "issueTime": "2026-01-02T00:00:00Z",
        "packageId": "openssl",
        "packageVersion": "3.0.2",
    }
    db.upsert_vulnerability_passports([{"internal_id": "grid-row", "name": "Grid name"}])
    db.upsert_vulnerability_passport_detail("grid-row", detail)
    db.upsert_vulnerability_passports([{"internal_id": "grid-row", "name": "Grid name changed"}])

    with db.connect() as conn:
        changed = partition_details(conn, [("grid-row", detail)], "2026-02-01T00:00:00+00:00")
    assert changed == [("grid-row", detail)]
    assert db.upsert_vulnerability_passport_details(changed) == 1
    with db.connect() as conn:
        row = conn.execute(
            "SELECT name, severity, score, package_id, package_version FROM vulnerability_passports WHERE internal_id = %s",
            ("grid-row",),
        ).fetchone()
    assert row == {
        "name": "Detailed OpenSSL vulnerability", "severity": "Critical", "score": "9.8",
        "package_id": "openssl", "package_version": "3.0.2",
    }


def test_reissued_detail_is_preserved_but_not_marked_fresh_for_new_id(test_db):
    original = {"internal_id": "old", "external_id": "EXT", "package_id": "pkg", "package_version": "1"}
    db.upsert_vulnerability_passports([original])
    db.upsert_vulnerability_passport_detail("old", {"description": "old evidence"})
    before = db.get_vulnerability_passport("old")
    assert before["detail_updated_at"] is not None
    db.upsert_vulnerability_passports([{**original, "internal_id": "new"}], full_catalog=True)
    replacement = db.get_vulnerability_passport("new")
    assert replacement["raw_detail"] == before["raw_detail"]
    assert replacement["first_seen"] == before["first_seen"]
    assert replacement["detail_updated_at"] is None
    assert db.vulnerability_passport_detail_refresh_candidates(["new"], ttl_hours=24)["eligible"] == ["new"]
