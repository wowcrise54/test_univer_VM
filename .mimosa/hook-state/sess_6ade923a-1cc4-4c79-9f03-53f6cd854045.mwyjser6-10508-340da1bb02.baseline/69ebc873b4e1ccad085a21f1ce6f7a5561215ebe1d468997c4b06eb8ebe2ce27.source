"""The dashboard ``q`` search keeps its semantics and can use the trigram indexes."""

import pytest

from app import db
from app.repositories.vulnerabilities import VulnerabilityAnalyticsRepository, _filtered_findings_cte

pytestmark = pytest.mark.integration

FINDINGS = [
    # (asset, group name, vulnerability_id, cve_name, name)
    ("asset-a", "OpenSSL package", "vid-alpha", "CVE-2026-1001", "Heap overflow"),
    ("asset-a", "Kernel", "vid-beta", "CVE-2026-1002", "Privilege escalation"),
    ("asset-b", "Chrome", "vid-gamma", "CVE-2026-1003", "Use after free"),
    ("asset-b", "OpenSSL package", "vid-delta", None, None),
]


@pytest.fixture()
def seeded(test_db):
    current = db.now_utc()
    with db.connect() as conn:
        groups: dict[tuple[str, str], int] = {}
        for asset_id in ("asset-a", "asset-b"):
            conn.execute(
                """INSERT INTO asset_cards(asset_id, display_name, asset_type, first_seen, last_seen)
                   VALUES (%s, %s, 'host', %s, %s)""",
                (asset_id, asset_id, current, current),
            )
        for index, (asset_id, group_name, vid, cve, name) in enumerate(FINDINGS):
            if (asset_id, group_name) not in groups:
                groups[(asset_id, group_name)] = conn.execute(
                    """INSERT INTO asset_card_vulnerability_groups
                       (asset_id, source_type, collection_type, collection_id, name,
                        vulnerability_count, group_order, updated_at)
                       VALUES (%s, 'software', 'software', %s, %s, 1, %s, %s) RETURNING id""",
                    (asset_id, f"c-{len(groups)}", group_name, len(groups), current),
                ).fetchone()["id"]
            conn.execute(
                """INSERT INTO asset_card_vulnerabilities
                   (asset_id, group_id, vulnerability_instance_id, vulnerability_id, cve_name,
                    name, severity, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, 'high', %s)""",
                (asset_id, groups[(asset_id, group_name)], f"inst-{index}", vid, cve, name, current),
            )


def _found(q: str) -> set[str]:
    rows = VulnerabilityAnalyticsRepository().list(q=q, limit=50)["rows"]
    return {row["vulnerability_id"] for row in rows}


@pytest.mark.parametrize(
    ("q", "expected"),
    [
        ("vid-alp", {"vid-alpha"}),  # vulnerability_id
        ("CVE-2026-1002", {"vid-beta"}),  # cve_name
        ("USE AFTER", {"vid-gamma"}),  # name, case-insensitive
        ("openssl", {"vid-alpha", "vid-delta"}),  # group name, also reaches findings without cve/name
        ("1003", {"vid-gamma"}),
        ("does-not-exist", set()),
    ],
)
def test_search_matches_each_searched_column(seeded, q, expected):
    assert _found(q) == expected


def test_finding_matching_several_columns_is_counted_once(seeded):
    # "vid" is in every vulnerability_id; "alpha" appears only in one of them.
    result = VulnerabilityAnalyticsRepository().list(q="vid-alpha", limit=50)
    assert result["total"] == 1
    assert result["rows"][0]["findings"] == 1


def test_search_text_is_a_bound_parameter(seeded):
    assert _found("x' OR 1=1 --") == set()


def test_search_sql_can_use_the_trigram_indexes(seeded):
    cte, params = _filtered_findings_cte(q="vid-alpha", include_details=False)
    with db.connect() as conn:
        conn.execute("SET LOCAL enable_seqscan = off")
        plan = "\n".join(
            next(iter(row.values()))
            for row in conn.execute(f"EXPLAIN {cte} SELECT selector FROM filtered_findings", params).fetchall()
        )
    # Plans on a near-empty table are unstable for the other branches (the planner
    # may pick a btree there), so only the vulnerability_id branch is pinned. The
    # existence of every trigram index is checked by the migration tests and their
    # effect was measured on a lab database (see migration 0035).
    assert "idx_asset_card_vulnerabilities_vulnerability_id_trgm" in plan, plan
