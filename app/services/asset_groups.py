from __future__ import annotations

from typing import Any

from ..repositories.asset_groups import AssetGroupRepository


class AssetGroupService:
    def __init__(self, repository: AssetGroupRepository) -> None:
        self._repository = repository

    def tree(self) -> dict[str, Any]:
        groups = self._repository.list()
        nodes = {item["group_id"]: {**item, "children": []} for item in groups}
        roots = []
        for item in nodes.values():
            parent = nodes.get(item.get("parent_id"))
            if parent:
                parent["children"].append(item)
            else:
                roots.append(item)
        return {"rows": roots, "total": len(groups)}

    def get(self, group_id: str) -> dict[str, Any] | None:
        return self._repository.get(group_id)

    def create(self, *, actor: str | None = None, **values: Any) -> dict[str, Any]:
        group = self._repository.create(created_by=actor, **values)
        evaluation = self._repository.evaluate(group["group_id"])
        refreshed = self._repository.get(group["group_id"])
        if not refreshed:
            raise LookupError("Asset group not found after creation.")
        return {**refreshed, "evaluation": evaluation}

    def create_from_asset_ids(
        self, *, name: str, description: str, parent_id: str | None,
        asset_ids: list[str], actor: str | None,
    ) -> dict[str, Any]:
        unique_ids = list(dict.fromkeys(value.strip() for value in asset_ids if value.strip()))
        if not unique_ids:
            raise ValueError("No affected assets were found for this vulnerability.")
        return self.create(
            actor=actor,
            name=name,
            description=description,
            parent_id=parent_id,
            query={
                "combinator": "and",
                "match_scope": "host",
                "rules": [{"field_path": "asset.assetId", "operator": "in", "value": unique_ids}],
            },
        )

    def update(self, group_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        return self._repository.update(group_id, changes)

    def archive(self, group_id: str) -> bool:
        return self._repository.archive(group_id)

    def preview(self, query: dict[str, Any], *, limit: int) -> dict[str, Any]:
        return self._repository.preview(query, limit=limit)

    def evaluate(self, group_id: str) -> dict[str, Any]:
        return self._repository.evaluate(group_id)

    def members(self, group_id: str, **pagination: Any) -> dict[str, Any]:
        if not self._repository.get(group_id):
            raise LookupError("Asset group not found.")
        return self._repository.members(group_id, **pagination)

    def set_override(self, group_id: str, asset_id: str, action: str, *, actor: str | None) -> dict[str, Any]:
        if not self._repository.get(group_id):
            raise LookupError("Asset group not found.")
        return self._repository.set_override(group_id, asset_id, action, actor=actor)

    def delete_override(self, group_id: str, asset_id: str) -> bool:
        return self._repository.delete_override(group_id, asset_id)

    def bulk_action(self, group_ids: list[str], action: str) -> dict[str, Any]:
        if action not in {"evaluate", "archive"}:
            raise ValueError("Unsupported bulk action.")

        results = []
        for group_id in dict.fromkeys(group_ids):
            try:
                if action == "evaluate":
                    value = self._repository.evaluate(group_id)
                else:
                    if not self._repository.archive(group_id):
                        raise LookupError("Asset group not found.")
                    value = {"archived": True}
                results.append({"group_id": group_id, "success": True, "result": value})
            except Exception as exc:
                results.append({"group_id": group_id, "success": False, "error": str(exc)})
        succeeded = sum(item["success"] for item in results)
        return {"processed": len(results), "succeeded": succeeded, "failed": len(results) - succeeded, "results": results}

    def precheck_stats(self) -> dict[str, int]:
        return self._repository.precheck_stats()

    def precheck_runs(self, *, limit: int) -> dict[str, Any]:
        return self._repository.precheck_runs(limit=limit)
