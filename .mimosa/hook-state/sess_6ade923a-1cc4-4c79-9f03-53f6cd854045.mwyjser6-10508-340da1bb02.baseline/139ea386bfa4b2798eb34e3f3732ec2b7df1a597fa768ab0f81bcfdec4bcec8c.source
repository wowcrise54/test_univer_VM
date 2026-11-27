"""Local group lifecycle uses the actual search index and PostgreSQL transactions."""
import psycopg
import pytest

from app import db
from app.repositories.asset_groups import AssetGroupRepository
from app.services.asset_groups import AssetGroupService

pytestmark = pytest.mark.integration
MISSING_GROUP = "00000000-0000-0000-0000-000000000000"


@pytest.fixture
def groups(test_db):
    now = db.now_utc()
    with db.connect() as conn:
        for asset_id in ("asset-a", "asset-b"):
            card = {"asset_id": asset_id, "display_name": asset_id, "ip_address": "10.0.0.1" if asset_id == "asset-a" else "10.0.1.1"}
            conn.execute("INSERT INTO asset_cards(asset_id,display_name,ip_address,first_seen,last_seen) VALUES(%s,%s,%s,%s,%s)", (asset_id, asset_id, card["ip_address"], now, now))
            db.replace_asset_card_search_index(conn, asset_id, card, now)
    return AssetGroupService(AssetGroupRepository())


def create(groups, name="Group", assets=None, parent=None):
    return groups.create_from_asset_ids(name=name, description=" Description ", parent_id=parent, asset_ids=assets or ["asset-a"], actor="operator")


def test_group_creation_calculates_indexed_members_and_deduplicates_asset_ids(groups):
    group = create(groups, assets=[" asset-a ", "asset-a", " ", "asset-b"])
    assert group["status"] == "ready" and group["member_count"] == 2
    assert group["description"] == "Description" and group["created_by"] == "operator"
    assert group["evaluation"]["status"] == "completed"
    assert groups.target_asset_ids(group["group_id"]) == ["asset-a", "asset-b"]
    members = groups.members(group["group_id"], limit=1, offset=1)
    assert members["total"] == 2 and members["rows"][0]["asset_id"] == "asset-b"
    assert members["rows"][0]["membership_source"] == "rule"
    assert members["rows"][0]["matches"][0]["field_path"] == "asset.assetId"
    preview = groups.preview(group["query"], limit=1)
    assert preview["total"] == 2 and len(preview["rows"]) == 1


def test_group_tree_hierarchy_metadata_updates_and_query_recalculation(groups):
    root = create(groups, "Parent")
    child = create(groups, "Child", parent=root["group_id"])
    tree = groups.tree()
    assert tree["total"] == 2 and tree["rows"][0]["children"][0]["group_id"] == child["group_id"]
    renamed = groups.update(child["group_id"], {"name": " Renamed ", "description": " Updated ", "parent_id": None})
    assert renamed["name"] == "Renamed" and renamed["description"] == "Updated"
    assert renamed["status"] == "ready" and renamed["parent_id"] is None
    assert groups.update(child["group_id"], {"unknown": "ignored"})["definition_version"] == renamed["definition_version"]
    query = {"combinator": "and", "match_scope": "host", "rules": [{"field_path": "asset.assetId", "operator": "equals", "value": "asset-b"}]}
    stale = groups.update(child["group_id"], {"query": query})
    assert stale["status"] == "stale" and stale["definition_version"] == renamed["definition_version"] + 1
    with pytest.raises(ValueError, match="Recalculate"):
        groups.target_asset_ids(child["group_id"])
    groups.evaluate(child["group_id"])
    assert groups.target_asset_ids(child["group_id"]) == ["asset-b"]
    assert groups.update(MISSING_GROUP, {"name": "Missing"}) is None
    assert groups.update(MISSING_GROUP, {}) is None


def test_group_parent_cycles_and_unknown_parent_cannot_modify_hierarchy(groups):
    root = create(groups, "Parent")
    child = create(groups, "Child", parent=root["group_id"])
    with pytest.raises(ValueError, match="own parent"):
        groups.update(root["group_id"], {"parent_id": root["group_id"]})
    with pytest.raises(ValueError, match="cycle"):
        groups.update(root["group_id"], {"parent_id": child["group_id"]})
    for action in (lambda: create(groups, "Invalid", parent=MISSING_GROUP), lambda: groups.update(child["group_id"], {"parent_id": MISSING_GROUP})):
        with pytest.raises(ValueError, match="Parent asset group not found"):
            action()
    assert groups.get(root["group_id"])["parent_id"] is None
    assert groups.get(child["group_id"])["parent_id"] == root["group_id"]
    assert groups.tree()["total"] == 2


def test_duplicate_group_name_rolls_back_and_leaves_existing_members(groups):
    original = create(groups, "Production")
    with pytest.raises(psycopg.errors.UniqueViolation):
        create(groups, "Production", assets=["asset-b"])
    assert groups.tree()["total"] == 1
    assert groups.target_asset_ids(original["group_id"]) == ["asset-a"]


def test_manual_includes_excludes_and_removal_require_recalculation(groups):
    group = create(groups)
    key = group["group_id"]
    groups.set_override(key, "asset-b", "include", actor="operator")
    groups.set_override(key, "asset-a", "exclude", actor="operator")
    with pytest.raises(ValueError, match="Recalculate"):
        groups.target_asset_ids(key)
    groups.evaluate(key)
    assert groups.target_asset_ids(key) == ["asset-b"]
    assert groups.members(key)["rows"][0]["membership_source"] == "manual_include"
    replacement = groups.set_override(key, "asset-a", "include", actor="other")
    assert replacement["action"] == "include" and replacement["created_by"] == "other"
    groups.evaluate(key)
    assert groups.target_asset_ids(key) == ["asset-a", "asset-b"]
    assert groups.delete_override(key, "asset-b") is True
    assert groups.delete_override(key, "asset-b") is False
    groups.evaluate(key)
    assert groups.target_asset_ids(key) == ["asset-a"]
    with pytest.raises(ValueError, match="Unsupported"):
        groups.set_override(key, "asset-a", "invalid", actor="operator")
    with pytest.raises(LookupError, match="Asset card not found"):
        groups.set_override(key, "missing-asset", "include", actor="operator")


def test_empty_group_recalculation_and_archival_hide_it_from_active_tree(groups):
    group = create(groups, assets=["unknown-asset"])
    assert group["member_count"] == 0 and groups.target_asset_ids(group["group_id"]) == []
    assert groups.members(group["group_id"], limit=999, offset=-1) == {"rows": [], "total": 0, "limit": 500, "offset": 0}
    assert groups.archive(group["group_id"]) is True
    assert groups.archive(group["group_id"]) is False
    assert groups.archive(MISSING_GROUP) is False
    assert groups.tree() == {"rows": [], "total": 0}
    assert len(db.list_asset_groups(include_archived=True)) == 1
    for action in (groups.target_asset_ids, groups.evaluate):
        with pytest.raises(LookupError, match="not found"):
            action(group["group_id"])
        with pytest.raises(LookupError, match="not found"):
            action(MISSING_GROUP)
    with pytest.raises(LookupError, match="not found"):
        groups.members(MISSING_GROUP)
    with pytest.raises(LookupError, match="not found"):
        groups.set_override(MISSING_GROUP, "asset-a", "include", actor=None)


def test_failed_evaluation_persists_error_and_can_be_retried(groups, monkeypatch):
    group = create(groups)
    original = db.query_asset_cards_by_fields
    def broken_index(*args, **kwargs):
        raise RuntimeError("Search index unavailable")
    monkeypatch.setattr(db, "query_asset_cards_by_fields", broken_index)
    with pytest.raises(RuntimeError, match="Search index unavailable"):
        groups.evaluate(group["group_id"])
    failed = groups.get(group["group_id"])
    assert failed["status"] == "error" and failed["last_error"] == "Search index unavailable"
    with db.connect() as conn:
        run = conn.execute("SELECT * FROM asset_group_evaluations WHERE group_id=%s AND status='failed'", (group["group_id"],)).fetchone()
        assert run["error"] == "Search index unavailable" and run["finished_at"] is not None
    monkeypatch.setattr(db, "query_asset_cards_by_fields", original)
    groups.evaluate(group["group_id"])
    assert groups.get(group["group_id"])["last_error"] is None
    assert groups.target_asset_ids(group["group_id"]) == ["asset-a"]


def test_bulk_archival_deduplicates_groups_and_reports_missing_groups(groups):
    group = create(groups)
    result = groups.bulk_action([group["group_id"], group["group_id"], MISSING_GROUP], "archive")
    assert result["processed"] == 2 and result["succeeded"] == 1 and result["failed"] == 1
    assert result["results"][1]["success"] is False


def test_precheck_statistics_and_false_runs_use_persisted_scan_results(groups):
    assert groups.precheck_stats() == {"runs": 0, "success": 0, "false": 0, "unknown": 0}
    assert groups.precheck_runs(limit=5) == {"rows": [], "total": 0}
    db.record_scan_task(mp_task_id="precheck-1", payload={"name": "Precheck"}, status="precheck_failed", remote_response={"successful_target_count": 1, "false_target_count": 2, "false_targets": ["10.0.0.1", "10.0.0.2"], "audit_task_id": "audit-1"})
    db.record_scan_task(mp_task_id="legacy", payload={}, status="precheck_finished", remote_response={})
    db.record_scan_task(mp_task_id="ordinary", payload={}, status="finished", remote_response={})
    assert groups.precheck_stats() == {"runs": 2, "success": 1, "false": 2, "unknown": 1}
    runs = groups.precheck_runs(limit=1)
    assert runs["total"] == 1 and runs["rows"][0]["mp_task_id"] == "precheck-1"
    assert runs["rows"][0]["retryable"] is True and runs["rows"][0]["false_target_count"] == 2