from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app import auth, main
from app.api.schemas import AssetGroupCreateRequest, AssetGroupDeleteRequest


def test_create_asset_group_waits_for_remote_operation_and_returns_group() -> None:
    client = MagicMock()
    client.create_dynamic_asset_group.return_value = "operation-1"
    client.wait_for_asset_group_creation.return_value = "group-1"
    client.get_asset_group_hierarchy.return_value = [{"id": "group-1", "name": "Linux", "children": []}]
    client.find_asset_group.return_value = {"id": "group-1", "name": "Linux", "children": []}

    with patch.object(main, "require_mpvm", return_value=(client, "token")):
        result = main.create_asset_group(AssetGroupCreateRequest(name="Linux", predicate="(ImageSet)"))

    assert result["id"] == "group-1"
    assert result["operation_id"] == "operation-1"
    client.create_dynamic_asset_group.assert_called_once_with(
        "token",
        name="Linux",
        predicate="(ImageSet)",
        parent_id="00000000-0000-0000-0000-000000000002",
        description=None,
    )
    client.wait_for_asset_group_creation.assert_called_once()


def test_delete_asset_group_requires_exact_group_name() -> None:
    client = MagicMock()
    client.get_asset_group_hierarchy.return_value = [{"id": "group-1", "name": "Production"}]
    client.find_asset_group.return_value = {"id": "group-1", "name": "Production"}

    with patch.object(main, "require_mpvm", return_value=(client, "token")), pytest.raises(HTTPException) as exc:
        main.delete_asset_group("group-1", AssetGroupDeleteRequest(confirm_name="production"))

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "ASSET_GROUP_CONFIRMATION_MISMATCH"
    client.remove_asset_groups.assert_not_called()


def test_asset_group_permissions_are_explicit_and_role_appropriate() -> None:
    assert auth.required_permission("GET", "/api/asset-groups") == "asset_groups.read"
    assert auth.required_permission("POST", "/api/asset-groups") == "asset_groups.manage"
    assert auth.required_permission("POST", "/api/asset-groups/group-1/delete") == "asset_groups.manage"
    assert "asset_groups.read" in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "asset_groups.manage" not in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "asset_groups.manage" in auth.BUILTIN_ROLE_PERMISSIONS["operator"]
