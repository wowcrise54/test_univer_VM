from __future__ import annotations

import builtins
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ..domain.errors import DomainError
from ..domain.scan_targets import normalize_scan_targets
from ..mpvm_client import build_scanner_task_payload
from ..repositories.task_presets import TaskPresetRepository
from .task_presets import user_role_ids

RemoteCreate = Callable[[dict[str, Any]], str]
RemoteUpdate = Callable[[str, dict[str, Any]], dict[str, Any]]
TaskStarter = Callable[[str, dict[str, Any], str | None, str | None], dict[str, Any]]
TaskAction = Callable[[str], dict[str, Any]]
TaskDeleter = Callable[[str, str | None], dict[str, Any]]

MAX_TASK_NAME = 200


class TeamTaskPersistError(RuntimeError):
    """The task exists in MP VM, but the local record could not be saved."""

    def __init__(self, mp_task_id: str, cause: Exception) -> None:
        super().__init__(f"Scanner task {mp_task_id} was created in MP VM but not saved locally: {cause}")
        self.mp_task_id = mp_task_id


class TeamTasksService:
    """Scanner tasks of a team: built only from presets and scoped by the preset roles."""

    def __init__(self, presets: TaskPresetRepository) -> None:
        self._presets = presets
        self._inflight: dict[str, int] = {}
        self._inflight_lock = threading.Lock()
        self.create_remote: RemoteCreate | None = None
        self.update_remote: RemoteUpdate | None = None
        self.start_task: TaskStarter | None = None
        self.stop_task: TaskAction | None = None
        self.delete_task: TaskDeleter | None = None

    def configure(
        self, *, create_remote: RemoteCreate, update_remote: RemoteUpdate, start_task: TaskStarter,
        stop_task: TaskAction, delete_task: TaskDeleter,
    ) -> None:
        self.create_remote = create_remote
        self.update_remote = update_remote
        self.start_task = start_task
        self.stop_task = stop_task
        self.delete_task = delete_task

    @staticmethod
    def _scope(user: dict[str, Any], unrestricted: bool) -> builtins.list[int] | None:
        return None if unrestricted else user_role_ids(user)

    def list(self, user: dict[str, Any], *, unrestricted: bool) -> dict[str, Any]:
        return {"rows": self._presets.list_team_tasks(role_ids=self._scope(user, unrestricted))}

    def get(self, task_id: str, user: dict[str, Any], *, unrestricted: bool) -> dict[str, Any]:
        task = self._presets.get_team_task(task_id, role_ids=self._scope(user, unrestricted))
        if not task:
            raise LookupError("Team scanner task not found.")
        return task

    def create(
        self, user: dict[str, Any], *, preset_id: str, asset_group_ids: builtins.list[str],
        name: str | None, description: str | None, unrestricted: bool, idempotency_key: str | None = None,
        targets: builtins.list[str] | None = None,
    ) -> dict[str, Any]:
        """Create the MP VM task; returns ``{"task", "operation_id", "idempotent_replay"}``."""
        if idempotency_key:
            replay = self._presets.operation_by_key(idempotency_key)
            if replay:
                return self._create_replay(replay, user, unrestricted=unrestricted)
        preset = self._active_preset(preset_id, user, unrestricted=unrestricted)
        groups, selected_targets = self._selection(preset, asset_group_ids, targets or [])
        task_name = self._task_name(preset, name, groups, selected_targets)
        payload = self._payload(preset, name=task_name, description=description or "", groups=groups,
                                targets=selected_targets)
        operation_id = str(uuid.uuid4())
        operation = {
            "kind": "team_task_create", "source_id": operation_id, "subject_type": "scan_task_preset",
            "subject_id": preset["preset_id"], "subject_label": task_name, "idempotency_key": idempotency_key,
            "request": {"preset_id": preset["preset_id"], "asset_group_ids": [group["id"] for group in groups],
                        "targets": selected_targets, "requested_by": user.get("username")},
        }
        self._presets.register_operation(
            operation_id, **operation, status="running", stage="creating_remote_task", progress_percent=10,
            message="Создание задачи сканирования в MP VM по пресету.",
        )
        assert self.create_remote is not None
        try:
            mp_task_id = self.create_remote(payload)
        except Exception as exc:
            self._finish_operation(operation_id, operation, status="failed", message="MP VM не создал задачу.",
                                   error={"message": str(exc)[:1000]})
            raise
        try:
            self._presets.record_task(mp_task_id, payload, status="created", remote_response={"id": mp_task_id})
            self._presets.attach_task(
                mp_task_id, preset_id=preset["preset_id"], preset_version=int(preset["version"]),
                asset_groups=groups, targets=selected_targets, actor=user.get("username"),
            )
        except Exception as exc:
            # Never delete the remote task here: it stays for manual reconciliation.
            self._finish_operation(
                operation_id, operation, status="needs_attention",
                message=f"Задача {mp_task_id} создана в MP VM, но не сохранена локально.",
                error={"message": str(exc)[:1000], "mp_task_id": mp_task_id},
            )
            raise TeamTaskPersistError(mp_task_id, exc) from exc
        self._finish_operation(operation_id, operation, status="completed", message="Задача создана по пресету.",
                               result={"mp_task_id": mp_task_id})
        return {"task": self.get(mp_task_id, user, unrestricted=True), "operation_id": operation_id,
                "idempotent_replay": False}

    def _create_replay(self, replay: dict[str, Any], user: dict[str, Any], *, unrestricted: bool) -> dict[str, Any]:
        if replay.get("kind") != "team_task_create":
            raise DomainError("IDEMPOTENCY_KEY_CONFLICT", "Ключ идемпотентности использован другой операцией.",
                              status_code=409)
        mp_task_id = (replay.get("result") or {}).get("mp_task_id")
        if replay.get("status") != "completed" or not mp_task_id:
            raise DomainError("IDEMPOTENCY_KEY_CONFLICT", "Предыдущая попытка с этим ключом не завершилась успешно.",
                              status_code=409, context={"operation_id": replay.get("operation_id")})
        return {"task": self.get(str(mp_task_id), user, unrestricted=unrestricted),
                "operation_id": replay.get("operation_id"), "idempotent_replay": True}

    def _finish_operation(self, operation_id: str, operation: dict[str, Any], *, status: str, message: str,
                          **values: Any) -> None:
        self._presets.register_operation(
            operation_id, **operation, status=status, stage=status, progress_percent=100, message=message,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"), **values,
        )

    def update(
        self, task_id: str, user: dict[str, Any], *, asset_group_ids: builtins.list[str],
        name: str | None, description: str | None, unrestricted: bool, targets: builtins.list[str] | None = None,
    ) -> dict[str, Any]:
        task = self.get(task_id, user, unrestricted=unrestricted)
        preset = self._active_preset(str(task["preset_id"]), user, unrestricted=True)
        groups, selected_targets = self._selection(preset, asset_group_ids, targets or [])
        task_name = (self._task_name(preset, name, groups, selected_targets) if name is not None
                     else str(task.get("name") or task_id))
        payload_description = description if description is not None else str((task.get("payload") or {}).get("description") or "")
        payload = self._payload(preset, name=task_name, description=payload_description, groups=groups,
                                targets=selected_targets)
        assert self.update_remote is not None
        response = self.update_remote(task_id, payload)
        self._presets.record_task(task_id, payload, status="updated", remote_response=response)
        self._presets.attach_task(
            task_id, preset_id=preset["preset_id"], preset_version=int(preset["version"]),
            asset_groups=groups, targets=selected_targets, actor=user.get("username"),
        )
        return self.get(task_id, user, unrestricted=True)

    def start(
        self, task_id: str, user: dict[str, Any], *, idempotency_key: str | None, unrestricted: bool,
    ) -> dict[str, Any]:
        task = self.get(task_id, user, unrestricted=unrestricted)
        preset = self._active_preset(str(task["preset_id"]), user, unrestricted=True)
        groups, task_targets = self._task_selection(task)
        # The current preset is authoritative: rotated credentials or profiles reach old tasks too.
        payload = self._payload(
            preset, name=str(task.get("name") or task_id),
            description=str((task.get("payload") or {}).get("description") or ""), groups=groups,
            targets=task_targets,
        )
        self._presets.record_task(task_id, payload, status="preset_synced", remote_response=task.get("last_remote_response"))
        self._presets.attach_task(
            task_id, preset_id=preset["preset_id"], preset_version=int(preset["version"]),
            asset_groups=groups, targets=task_targets, actor=user.get("username"),
        )
        assert self.start_task is not None
        with self._reserve_slot(preset, task_id):
            return self.start_task(task_id, dict(preset.get("start_options") or {}), idempotency_key, user.get("username"))

    def stop(self, task_id: str, user: dict[str, Any], *, unrestricted: bool) -> dict[str, Any]:
        self.get(task_id, user, unrestricted=unrestricted)
        assert self.stop_task is not None
        return self.stop_task(task_id)

    def delete(
        self, task_id: str, user: dict[str, Any], *, idempotency_key: str | None, unrestricted: bool,
    ) -> dict[str, Any]:
        self.get(task_id, user, unrestricted=unrestricted)
        assert self.delete_task is not None
        return self.delete_task(task_id, idempotency_key)

    def _active_preset(self, preset_id: str, user: dict[str, Any], *, unrestricted: bool) -> dict[str, Any]:
        preset = self._presets.get(preset_id)
        if not preset or (not unrestricted and not (set(preset["role_ids"]) & set(user_role_ids(user)))):
            raise LookupError("Task preset not found.")
        if not preset["is_active"]:
            raise DomainError("PRESET_INACTIVE", "Пресет в архиве: создание и запуск задач по нему недоступны.",
                              status_code=409, context={"preset_id": preset_id})
        return preset

    @classmethod
    def _selection(
        cls, preset: dict[str, Any], asset_group_ids: builtins.list[str], targets: builtins.list[str],
    ) -> tuple[builtins.list[dict[str, Any]], builtins.list[str]]:
        groups = cls._selected_groups(preset, asset_group_ids)
        selected_targets = cls._typed_targets(targets)
        if not groups and not selected_targets:
            raise ValueError("Выберите хотя бы одну группу активов, IP-адрес или FQDN.")
        return groups, selected_targets

    @staticmethod
    def _selected_groups(preset: dict[str, Any], asset_group_ids: builtins.list[str]) -> builtins.list[dict[str, Any]]:
        requested = list(dict.fromkeys(str(value).strip() for value in asset_group_ids if str(value).strip()))
        if not requested:
            return []
        limit = int(preset.get("max_groups_per_task") or 1)
        if len(requested) > limit:
            raise ValueError(f"Пресет разрешает не больше {limit} групп в одной задаче.")
        allowed = {str(group["id"]): group for group in preset.get("allowed_asset_groups") or []}
        forbidden = [value for value in requested if value not in allowed]
        if forbidden:
            raise ValueError(f"Группы не разрешены пресетом: {', '.join(forbidden)}.")
        return [allowed[value] for value in requested]

    @staticmethod
    def _typed_targets(targets: builtins.list[str]) -> builtins.list[str]:
        """Engineers type any IP, network, range or FQDN; only the format is checked."""
        return normalize_scan_targets(value for value in targets if str(value).strip())

    @staticmethod
    def _task_selection(task: dict[str, Any]) -> tuple[builtins.list[dict[str, Any]], builtins.list[str]]:
        groups = task.get("preset_asset_groups") or []
        targets = task.get("preset_targets") or []
        if not groups and not targets:
            raise DomainError("TEAM_TASK_GROUPS_MISSING",
                              "У задачи не сохранены группы активов и цели. Измените задачу.",
                              status_code=409, context={"task_id": task.get("mp_task_id")})
        return [dict(group) for group in groups], [str(value) for value in targets]

    @staticmethod
    def _task_name(
        preset: dict[str, Any], name: str | None, groups: builtins.list[dict[str, Any]],
        targets: builtins.list[str],
    ) -> str:
        base = (name or "").strip()
        if not base:
            stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
            labels = [str(group.get("name") or group["id"]) for group in groups] + targets
            base = f"{', '.join(labels)} {stamp}"
        prefix = str(preset.get("name_prefix") or "").strip()
        full = base if not prefix or base.startswith(prefix) else f"{prefix} {base}"
        return full[:MAX_TASK_NAME]

    @staticmethod
    def _payload(
        preset: dict[str, Any], *, name: str, description: str, groups: builtins.list[dict[str, Any]],
        targets: builtins.list[str],
    ) -> dict[str, Any]:
        if preset.get("host_discovery_enabled") and not preset.get("host_discovery_profile_id"):
            # Presets saved before the profile became required; MP VM would answer "Value cannot be null".
            raise DomainError(
                "PRESET_HOST_DISCOVERY_PROFILE_MISSING",
                "В пресете включён HostDiscovery без профиля. Администратору нужно выбрать профиль в пресете.",
                status_code=409, context={"preset_id": preset.get("preset_id")},
            )
        return build_scanner_task_payload(
            name=name,
            description=description,
            scope_id=preset["scope_id"],
            profile_id=preset["profile_id"],
            include_targets=list(targets),
            agent_ids=list(preset.get("agent_ids") or []),
            credential_id=preset.get("credential_id"),
            credential_transport=preset.get("credential_transport") or "windows",
            host_discovery_enabled=bool(preset.get("host_discovery_enabled")),
            host_discovery_profile_id=preset.get("host_discovery_profile_id"),
            time_zone=preset.get("time_zone") or "+05:00",
            is_fqdn_priority=bool(preset.get("is_fqdn_priority", True)),
            trigger_parameters=preset.get("trigger_parameters"),
            denied_scan_settings=preset.get("denied_scan_settings"),
            include_asset_group_ids=[str(group["id"]) for group in groups],
        )

    def _reserve_slot(self, preset: dict[str, Any], task_id: str) -> _Slot:
        return _Slot(self, preset, task_id)


class _Slot:
    """Counts a start in flight so concurrent starts respect ``max_active_tasks``."""

    def __init__(self, service: TeamTasksService, preset: dict[str, Any], task_id: str) -> None:
        self._service = service
        self._preset_id = str(preset["preset_id"])
        self._limit = preset.get("max_active_tasks")
        self._task_id = task_id

    def __enter__(self) -> None:
        service = self._service
        with service._inflight_lock:
            if self._limit:
                active = service._presets.count_active_tasks(self._preset_id, exclude_task_id=self._task_id)
                active += service._inflight.get(self._preset_id, 0)
                if active >= int(self._limit):
                    raise DomainError(
                        "PRESET_CONCURRENCY_LIMIT",
                        f"По пресету уже выполняется задач: {active}. Дождитесь завершения одной из них.",
                        status_code=409, context={"preset_id": self._preset_id, "limit": int(self._limit)},
                    )
            service._inflight[self._preset_id] = service._inflight.get(self._preset_id, 0) + 1

    def __exit__(self, *_: object) -> None:
        service = self._service
        with service._inflight_lock:
            remaining = service._inflight.get(self._preset_id, 1) - 1
            if remaining > 0:
                service._inflight[self._preset_id] = remaining
            else:
                service._inflight.pop(self._preset_id, None)
