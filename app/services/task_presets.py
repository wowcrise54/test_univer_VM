from __future__ import annotations

import builtins
from collections.abc import Callable
from typing import Any

from ..repositories.task_presets import TaskPresetRepository

LookupsProvider = Callable[[], dict[str, builtins.list[dict[str, Any]]]]
GroupsProvider = Callable[[], builtins.list[dict[str, Any]]]

OS_TRANSPORTS = {"windows": "windows", "linux": "ssh"}


def flatten_asset_groups(groups: builtins.list[dict[str, Any]]) -> builtins.list[dict[str, Any]]:
    """Flatten the MP VM group hierarchy into ``{id, name, path}`` rows in tree order."""
    result: builtins.list[dict[str, Any]] = []

    def walk(items: builtins.list[Any], parents: builtins.list[str]) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            group_id = str(item.get("id") or "").strip()
            name = str(item.get("name") or group_id).strip()
            path = [*parents, name]
            if group_id:
                result.append({"id": group_id, "name": name, "path": " / ".join(path)})
            children = item.get("children")
            if isinstance(children, list):
                walk(children, path)

    walk(groups, [])
    return result


def _ids(items: builtins.list[dict[str, Any]] | None) -> set[str]:
    return {str(item.get("id")) for item in items or [] if item.get("id")}


class TaskPresetService:
    def __init__(self, repository: TaskPresetRepository) -> None:
        self._repository = repository
        self.lookups_provider: LookupsProvider | None = None
        self.groups_provider: GroupsProvider | None = None

    def configure(self, *, lookups_provider: LookupsProvider, groups_provider: GroupsProvider) -> None:
        self.lookups_provider = lookups_provider
        self.groups_provider = groups_provider

    def list_for_user(self, user: dict[str, Any], *, can_manage: bool, include_archived: bool = False) -> dict[str, Any]:
        role_ids = None if can_manage else user_role_ids(user)
        return {"rows": self._repository.list(role_ids=role_ids, include_archived=include_archived and can_manage)}

    def get_for_user(self, preset_id: str, user: dict[str, Any], *, can_manage: bool) -> dict[str, Any]:
        preset = self._repository.get(preset_id)
        if not preset or (not can_manage and not (set(preset["role_ids"]) & set(user_role_ids(user)))):
            raise LookupError("Task preset not found.")
        if not can_manage and not preset["is_active"]:
            raise LookupError("Task preset not found.")
        return preset

    def lookups(self) -> dict[str, Any]:
        if not self.lookups_provider:
            raise RuntimeError("Task preset lookups are not configured.")
        lookups = self.lookups_provider()
        return {
            key: [{"id": item.get("id"), "name": item.get("name")} for item in lookups.get(key) or [] if item.get("id")]
            for key in ("credentials", "scopes", "scanner_profiles", "agents")
        }

    def asset_groups(self) -> dict[str, Any]:
        if not self.groups_provider:
            raise RuntimeError("Task preset asset groups are not configured.")
        return {"rows": flatten_asset_groups(self.groups_provider())}

    def create(self, values: dict[str, Any], role_ids: builtins.list[int], *, actor: str | None) -> dict[str, Any]:
        clean = self._validated(values, role_ids)
        return self._repository.create(clean, role_ids, actor=actor)

    def update(
        self, preset_id: str, values: dict[str, Any], role_ids: builtins.list[int], *,
        expected_version: int, actor: str | None,
    ) -> dict[str, Any]:
        clean = self._validated(values, role_ids)
        preset = self._repository.update(preset_id, clean, role_ids, expected_version=expected_version, actor=actor)
        if not preset:
            raise LookupError("Task preset not found.")
        return preset

    def archive(self, preset_id: str, *, expected_version: int, actor: str | None) -> dict[str, Any]:
        preset = self._repository.archive(preset_id, expected_version=expected_version, actor=actor)
        if not preset:
            raise LookupError("Task preset not found.")
        return preset

    @staticmethod
    def draft_from_task(task: dict[str, Any]) -> dict[str, Any]:
        """Turn a saved scanner task into an unsaved preset draft for the admin form."""
        raw_payload = task.get("payload")
        payload: dict[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}
        transports = (payload.get("overrides") or {}).get("transports") or {}
        transport = "ssh" if "terminal" in transports else "windows"
        trigger = payload.get("triggerParameters") if isinstance(payload.get("triggerParameters"), dict) else None
        denied = payload.get("deniedScanSettings") if isinstance(payload.get("deniedScanSettings"), dict) else None
        include: dict[str, Any] = payload["include"] if isinstance(payload.get("include"), dict) else {}
        host_discovery: dict[str, Any] = (
            payload["hostDiscovery"] if isinstance(payload.get("hostDiscovery"), dict) else {}
        )
        return {
            "name": str(payload.get("name") or task.get("name") or "")[:120],
            "description": str(payload.get("description") or ""),
            "os_family": "linux" if transport == "ssh" else "windows",
            "scope_id": payload.get("scope") or task.get("scope_id"),
            "profile_id": payload.get("profile") or task.get("profile_id"),
            "credential_id": task.get("credential_id"),
            "credential_transport": transport,
            "agent_ids": list((payload.get("agents") or {}).get("agentIds") or []),
            "host_discovery_enabled": bool(host_discovery.get("enabled")),
            "host_discovery_profile_id": host_discovery.get("profile"),
            "is_fqdn_priority": bool(payload.get("isFqdnPriority", True)),
            "time_zone": (trigger or {}).get("timeZone") or "+05:00",
            "trigger_parameters": trigger if trigger and trigger.get("isEnabled") else None,
            "denied_scan_settings": denied if denied and denied.get("isEnabled") else None,
            "allowed_asset_groups": [{"id": str(value)} for value in include.get("assetsGroups") or []],
            "source_task_id": task.get("mp_task_id"),
        }

    def _validated(self, values: dict[str, Any], role_ids: builtins.list[int]) -> dict[str, Any]:
        clean = dict(values)
        clean["name"] = str(clean.get("name") or "").strip()
        if not clean["name"]:
            raise ValueError("Название пресета не может быть пустым.")
        clean["name_prefix"] = str(clean.get("name_prefix") or "").strip()
        clean["credential_id"] = clean.get("credential_id") or None
        clean["host_discovery_profile_id"] = clean.get("host_discovery_profile_id") or None
        if clean.get("credential_id") and clean.get("credential_transport") != OS_TRANSPORTS[clean["os_family"]]:
            raise ValueError("Транспорт учётной записи не соответствует ОС пресета (Windows — windows, Linux — ssh).")
        if not role_ids:
            raise ValueError("Укажите хотя бы одну роль, которой доступен пресет.")
        missing_roles = set(role_ids) - self._repository.existing_role_ids(role_ids)
        if missing_roles:
            raise ValueError(f"Роли не найдены: {', '.join(str(value) for value in sorted(missing_roles))}.")
        groups = clean.get("allowed_asset_groups") or []
        unique_groups = list({str(group["id"]): group for group in groups}.values())
        if not unique_groups:
            raise ValueError("Укажите хотя бы одну разрешённую группу активов.")
        clean["allowed_asset_groups"] = unique_groups
        self._check_mpvm_references(clean)
        return clean

    def _check_mpvm_references(self, clean: dict[str, Any]) -> None:
        """Reject IDs that MP VM does not know and refresh the cached group names."""
        if self.lookups_provider:
            lookups = self.lookups_provider()
            profiles = _ids(lookups.get("scanner_profiles"))
            checks = [
                ("scope_id", _ids(lookups.get("scopes")), "Область (scope)"),
                ("profile_id", profiles, "Профиль сканирования"),
                ("credential_id", _ids(lookups.get("credentials")), "Учётная запись"),
                ("host_discovery_profile_id", profiles, "Профиль HostDiscovery"),
            ]
            for key, known, label in checks:
                value = clean.get(key)
                if value and str(value) not in known:
                    raise ValueError(f"{label} {value} не найден(а) в MP VM.")
            precheck_profile = (clean.get("start_options") or {}).get("precheck_profile_id")
            if precheck_profile and str(precheck_profile) not in profiles:
                raise ValueError(f"Профиль precheck {precheck_profile} не найден в MP VM.")
        if self.groups_provider:
            known_groups = {group["id"]: group for group in flatten_asset_groups(self.groups_provider())}
            unknown = [str(group["id"]) for group in clean["allowed_asset_groups"] if str(group["id"]) not in known_groups]
            if unknown:
                raise ValueError(f"Группы активов не найдены в MP VM: {', '.join(unknown)}.")
            clean["allowed_asset_groups"] = [known_groups[str(group["id"])] for group in clean["allowed_asset_groups"]]


def user_role_ids(user: dict[str, Any] | None) -> builtins.list[int]:
    return sorted({int(role["id"]) for role in (user or {}).get("roles") or [] if role.get("id") is not None})
