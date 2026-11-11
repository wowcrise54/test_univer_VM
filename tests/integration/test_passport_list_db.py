"""DB tests for the passport catalog list: ordering, summary fields, filters, and the total cache.

The list endpoint is the hottest read on the 500k-row ``vulnerability_passports``
table. These tests pin the behavior that the performance changes must not
touch: the default ordering semantics, the ``short_description``/``has_detail``
summary fields, the severity filter equivalence, pagination clamping, and the
total staying correct across every catalog write path.
"""

from __future__ import annotations

import json
import re

import pytest

from app import db
from app.repositories.passports import catalog, counts
from app.repositories.passports.details import upsert_vulnerability_passport_detail
from app.repositories.passports.trends import replace_vulnerability_passport_trends

pytestmark = pytest.mark.integration

_PASSPORT_INSERT = """
    INSERT INTO vulnerability_passports (
        internal_id, name, severity, score, issue_time, package_id,
        package_version, cves_json, raw_detail_json, first_seen, last_seen
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

_WHEN = "2026-01-01T00:00:00+00:00"


def _insert_passport(
    internal_id: str,
    *,
    name: str | None = None,
    severity: str | None = None,
    score: str | None = None,
    issue_time: str | None = None,
    package_id: str | None = None,
    package_version: str | None = None,
    detail: dict | None = None,
) -> None:
    with db.connect() as conn:
        conn.execute(
            _PASSPORT_INSERT,
            (
                internal_id,
                name,
                severity,
                score,
                issue_time,
                package_id,
                package_version,
                "[]",
                json.dumps(detail, ensure_ascii=False) if detail is not None else None,
                _WHEN,
                _WHEN,
            ),
        )


_SEV_RANK = {"critical": 1, "high": 2, "medium": 3, "low": 4, "none": 5}
_SCORE_RE = re.compile(r"^[0-9]+([.][0-9]+)?$")


def _score_value(score: str | None) -> float | None:
    """Python twin of the SQL score expression (comma decimals, regex guard)."""
    if score is None:
        return None
    candidate = score.replace(",", ".")
    return float(candidate) if _SCORE_RE.match(candidate) else None


def _reference_order_key(row: dict) -> tuple:
    """Reference of the default ORDER BY: (sev rank, score DESC NULLS LAST, name NULLS LAST, internal_id)."""
    sev_rank = _SEV_RANK.get((row["severity"] or "").lower(), 6)
    score = _score_value(row["score"])
    score_key = (0, -score) if score is not None else (1, 0.0)
    name_key = (0, row["name"]) if row["name"] is not None else (1, "")
    return (sev_rank, score_key, name_key, row["internal_id"])


def _list_ids(**kwargs) -> list[str]:
    result = catalog.list_vulnerability_passports(limit=200, **kwargs)
    return [row["internal_id"] for row in result["rows"]]


def test_list_default_ordering_matches_reference_semantics(test_db):
    cases = [
        ("p-crit-alpha", "alpha", "CRITICAL", "10.0"),
        ("p-crit-zeta", "zeta", "critical", "9.9"),
        ("p-high-comma", "comma", "high", "7,8"),
        ("p-high-bad", "hbad", "high", "abc"),
        ("p-high-null", "hnull", "high", None),
        ("p-med-beta", "beta", "medium", "5.5"),
        ("p-tie-a", "tie-a", "medium", "5.5"),
        ("p-tie-b", "tie-b", "medium", "5.5"),
        ("p-low", None, "low", None),
        ("p-none", "none-name", "none", "0"),
        ("p-weird", "weird", "info", "1"),
        ("p-null-sev", "nullsev", None, "100"),
    ]
    for internal_id, name, severity, score in cases:
        _insert_passport(internal_id, name=name, severity=severity, score=score)

    with db.connect() as conn:
        stored = [
            dict(row)
            for row in conn.execute(
                "SELECT internal_id, name, severity, score FROM vulnerability_passports"
            ).fetchall()
        ]
    expected = [row["internal_id"] for row in sorted(stored, key=_reference_order_key)]
    # Hand-computed: score DESC within severity rank, NULL scores/last, name ASC tie-break.
    assert expected == [
        "p-crit-alpha", "p-crit-zeta",
        "p-high-comma", "p-high-bad", "p-high-null",
        "p-med-beta", "p-tie-a", "p-tie-b",
        "p-low", "p-none",
        "p-null-sev", "p-weird",
    ]
    assert _list_ids() == expected
    assert catalog.list_vulnerability_passports(limit=200)["total"] == len(cases)


def test_list_summary_keeps_short_description_and_has_detail(test_db):
    _insert_passport("s-desc", name="d1", detail={"description": "Broken pipe in nginx worker"})
    _insert_passport("s-vuln", name="d2", detail={"vulnerabilityDescription": "XSS in foobar", "name": "foobar"})
    _insert_passport("s-plain", name="d3")

    rows = {row["internal_id"]: row for row in catalog.list_vulnerability_passports(limit=200)["rows"]}
    assert rows["s-desc"]["has_detail"] is True
    assert rows["s-desc"]["short_description"] == "Broken pipe in nginx worker"
    assert rows["s-vuln"]["has_detail"] is True
    assert rows["s-vuln"]["short_description"] == "XSS in foobar"
    assert rows["s-plain"]["has_detail"] is False
    assert rows["s-plain"]["short_description"] is None


def test_list_severity_filter_case_insensitive_and_null_safe(test_db):
    _insert_passport("f-high-1", severity="High")
    _insert_passport("f-high-2", severity="HIGH")
    _insert_passport("f-high-3", severity="high")
    _insert_passport("f-null", severity=None)
    _insert_passport("f-med", severity="medium")

    assert _list_ids(severity="high") == ["f-high-1", "f-high-2", "f-high-3"] or set(
        _list_ids(severity="high")
    ) == {"f-high-1", "f-high-2", "f-high-3"}
    assert catalog.list_vulnerability_passports(severity="high", limit=200)["total"] == 3
    assert _list_ids(severity="MEDIUM") == ["f-med"]
    assert _list_ids(severity="unknown") == []
    # NULL severity never matches a non-empty filter.
    assert "f-null" not in _list_ids(severity="high")
    assert "f-null" not in _list_ids(severity="unknown")


def test_list_total_stays_correct_across_write_paths(test_db):
    base_key = counts.passport_total_key(None, None, None)
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 0
    assert counts.cached_passport_total(base_key) == 0

    catalog.upsert_vulnerability_passports(
        [
            {"internal_id": "c1", "name": "n1", "severity": "high"},
            {"internal_id": "c2", "name": "n2", "severity": "medium"},
        ]
    )
    assert counts.cached_passport_total(base_key) is None, "upsert must invalidate the total cache"
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 2
    assert counts.cached_passport_total(base_key) == 2

    # Detail refresh of an existing row changes no filter column: total unchanged.
    upsert_vulnerability_passport_detail("c1", {"description": "detail c1"})
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 2

    # A detail fetch for an unknown passport INSERTS a new row: total must grow.
    upsert_vulnerability_passport_detail("c3-new", {"description": "detail c3"})
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 3

    # Filtered total: only the high row, and a new high row invalidates it.
    high_key = counts.passport_total_key(None, "high", None)
    assert catalog.list_vulnerability_passports(severity="high", limit=1)["total"] == 1
    assert counts.cached_passport_total(high_key) == 1
    catalog.upsert_vulnerability_passports([{"internal_id": "c4", "name": "n4", "severity": "High"}])
    assert catalog.list_vulnerability_passports(severity="high", limit=1)["total"] == 2

    # Trends replacement can create passport rows: total must reflect them.
    replace_vulnerability_passport_trends(
        [
            {
                "internal_id": "t1-trend",
                "name": "trend pkg",
                "severity": "high",
                "score": "8.0",
                "description": "trend",
            }
        ],
        source_pdql="test-trends",
    )
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 5

    # Deletion invalidates too.
    assert catalog.delete_vulnerability_passport("c1") is True
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 4
    assert catalog.delete_vulnerability_passport("nope") is False
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 4


def test_list_limit_offset_clamping_unchanged(test_db):
    for index in range(3):
        _insert_passport(f"clamp-{index}")

    result = catalog.list_vulnerability_passports(limit=9999, offset=-5)
    assert result["limit"] == 200
    assert result["offset"] == 0
    assert len(result["rows"]) == 3

    assert catalog.list_vulnerability_passports(limit=0)["limit"] == 1
    assert catalog.list_vulnerability_passports(limit=5, offset=2)["rows"] == catalog.list_vulnerability_passports(
        limit=200, offset=2
    )["rows"][:5]


def _insert_five_passports() -> list[str]:
    ids = [f"off-{index:02d}" for index in range(5)]
    for index, internal_id in enumerate(ids):
        _insert_passport(internal_id, name=f"off-{index:02d}", score=str(10 - index))
    return ids


def test_list_offset_equal_total_returns_empty(test_db):
    _insert_five_passports()

    result = catalog.list_vulnerability_passports(limit=50, offset=5)
    assert result["rows"] == []
    assert result["total"] == 5
    assert result["offset"] == 5
    assert result["limit"] == 50


def test_list_offset_beyond_total_returns_empty(test_db):
    _insert_five_passports()

    result = catalog.list_vulnerability_passports(limit=50, offset=500)
    assert result["rows"] == []
    assert result["total"] == 5
    assert result["offset"] == 500


def test_list_valid_pages_unaffected_by_offset_short_circuit(test_db):
    _insert_five_passports()

    page_two = catalog.list_vulnerability_passports(limit=50, offset=2)
    assert len(page_two["rows"]) == 3
    assert page_two["total"] == 5
    assert page_two["offset"] == 2

    page_zero = catalog.list_vulnerability_passports(limit=50, offset=0)
    assert len(page_zero["rows"]) == 5
    assert page_zero["total"] == 5


def test_list_empty_table_returns_empty_without_error(test_db):
    result = catalog.list_vulnerability_passports(limit=50, offset=0)
    assert result["total"] == 0
    assert result["rows"] == []
    assert result["offset"] == 0


def test_list_sort_by_variants_unchanged(test_db):
    _insert_passport("sb-1", name="bbb", issue_time="2026-01-02T00:00:00+00:00")
    _insert_passport("sb-2", name="aaa", issue_time="2026-01-03T00:00:00+00:00")
    _insert_passport("sb-3", name="ccc", issue_time="2026-01-01T00:00:00+00:00")

    assert _list_ids(sort_by="name") == ["sb-2", "sb-1", "sb-3"]
    assert _list_ids(sort_by="name", sort_dir="desc") == ["sb-3", "sb-1", "sb-2"]
    assert _list_ids(sort_by="issue_time") == ["sb-3", "sb-1", "sb-2"]
    assert _list_ids(sort_by="issue_time", sort_dir="desc") == ["sb-2", "sb-1", "sb-3"]


def test_count_cache_is_bounded_and_safe_on_overflow(test_db):
    for index in range(520):
        _insert_passport(f"b-{index:03d}")
    # Distinct q filters overflow the memo; every total must still be exact.
    for index in range(counts._MAX_ENTRIES + 1):
        assert catalog.list_vulnerability_passports(q=f"b-{index:03d}", limit=1)["total"] == 1
    assert catalog.list_vulnerability_passports(limit=1)["total"] == 520
