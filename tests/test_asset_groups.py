from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app import auth, db
from app.services.asset_groups import AssetGroupService


def test_cidr_rule_compiles_to_postgres_network_match() -> None:
    sql, params, scope = db.compile_asset_query_rule({
        "field_path": "asset.ipAddress",
        "operator": "in_cidr",
        "value": "10.20.3.4/16",
    })

    assert "value_text_normalized::inet <<= %s::cidr" in sql
    assert params == ["asset.ipAddress", "10.20.0.0/16"]
    assert scope == "entity"


@pytest.mark.parametrize("field_path,value", [("asset.hostname", "10.0.0.0/8"), ("asset.ipAddress", "invalid")])
def test_cidr_rule_rejects_unsupported_field_or_network(field_path: str, value: str) -> None:
    with pytest.raises(ValueError):
        db.compile_asset_query_rule({"field_path": field_path, "operator": "in_cidr", "value": value})


def test_service_builds_group_tree() -> None:
    repository = MagicMock()
    repository.list.return_value = [
        {"group_id": "child", "parent_id": "root", "name": "Linux"},
        {"group_id": "root", "parent_id": None, "name": "Production"},
    ]

    result = AssetGroupService(repository).tree()

    assert result["total"] == 2
    assert result["rows"][0]["group_id"] == "root"
    assert result["rows"][0]["children"][0]["group_id"] == "child"


def test_service_evaluates_group_immediately_after_creation() -> None:
    repository = MagicMock()
    repository.create.return_value = {"group_id": "group-1", "status": "stale"}
    repository.evaluate.return_value = {"evaluation_id": "evaluation-1", "status": "completed"}
    repository.get.return_value = {"group_id": "group-1", "status": "ready", "member_count": 4}

    result = AssetGroupService(repository).create(
        actor="operator",
        name="Production Linux",
        description="",
        parent_id=None,
        query={"combinator": "and", "match_scope": "host", "rules": []},
    )

    repository.evaluate.assert_called_once_with("group-1")
    assert result["status"] == "ready"
    assert result["evaluation"]["evaluation_id"] == "evaluation-1"


def test_asset_group_permissions_are_explicit_and_role_appropriate() -> None:
    assert auth.required_permission("GET", "/api/asset-groups/tree") == "asset_groups.read"
    assert auth.required_permission("POST", "/api/asset-groups/preview") == "asset_groups.manage"
    assert auth.required_permission("POST", "/api/asset-groups/group-1/evaluate") == "asset_groups.manage"
    assert "asset_groups.read" in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "asset_groups.manage" not in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "asset_groups.manage" in auth.BUILTIN_ROLE_PERMISSIONS["operator"]


def test_service_runs_bulk_group_action_and_reports_each_result() -> None:
    repository = MagicMock()
    repository.evaluate.side_effect = [
        {"evaluation_id": "evaluation-1", "status": "completed"},
        RuntimeError("index unavailable"),
    ]

    result = AssetGroupService(repository).bulk_action(["group-1", "group-2"], "evaluate")

    assert result["processed"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert result["results"][1]["group_id"] == "group-2"
    assert result["results"][1]["success"] is False


def test_service_returns_persisted_precheck_statistics() -> None:
    repository = MagicMock()
    repository.precheck_stats.return_value = {
        "runs": 3, "success": 7, "false": 2, "unknown": 1,
    }

    result = AssetGroupService(repository).precheck_stats()

    assert result == {"runs": 3, "success": 7, "false": 2, "unknown": 1}
