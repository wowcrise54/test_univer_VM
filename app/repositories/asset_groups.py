from __future__ import annotations

from typing import Any

from .. import db


class AssetGroupRepository:
    def list(self) -> list[dict[str, Any]]:
        return db.list_asset_groups()

    def get(self, group_id: str) -> dict[str, Any] | None:
        return db.get_asset_group(group_id)

    def create(self, **values: Any) -> dict[str, Any]:
        return db.create_local_asset_group(**values)

    def update(self, group_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        return db.update_local_asset_group(group_id, changes)

    def archive(self, group_id: str) -> bool:
        return db.archive_local_asset_group(group_id)

    def preview(self, query: dict[str, Any], *, limit: int) -> dict[str, Any]:
        return db.preview_local_asset_group(query, limit=limit)

    def evaluate(self, group_id: str) -> dict[str, Any]:
        return db.evaluate_local_asset_group(group_id)

    def members(self, group_id: str, **pagination: Any) -> dict[str, Any]:
        return db.list_local_asset_group_members(group_id, **pagination)

    def member_ids(self, group_id: str) -> list[str]:
        return db.list_local_asset_group_member_ids(group_id)

    def set_override(self, group_id: str, asset_id: str, action: str, *, actor: str | None) -> dict[str, Any]:
        return db.set_local_asset_group_override(group_id, asset_id, action, actor=actor)

    def delete_override(self, group_id: str, asset_id: str) -> bool:
        return db.delete_local_asset_group_override(group_id, asset_id)

    def precheck_stats(self) -> dict[str, int]:
        return db.get_precheck_statistics()

    def precheck_runs(self, *, limit: int) -> dict[str, Any]:
        return db.list_precheck_false_runs(limit=limit)
