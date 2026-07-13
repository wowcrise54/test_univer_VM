from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
from croniter import croniter

from .. import db
from ..core.config import Settings
from ..core.runtime import OperationRunner
from .repository import AutomationRepository

StepHandler = Callable[[str, dict[str, Any], dict[str, Any], str, int], dict[str, Any]]
SUPPORTED_STEP_TYPES = {
    "scanner_task_start",
    "pdql_export",
    "passport_sync",
    "asset_card_build",
    "asset_query",
    "notification",
}


class AutomationService:
    def __init__(
        self,
        repository: AutomationRepository,
        runner: OperationRunner,
        settings: Settings,
        step_handler: StepHandler,
        service_account_ready: Callable[[], bool],
        housekeeping: Callable[[], None] | None = None,
    ) -> None:
        self.repository = repository
        self.runner = runner
        self.settings = settings
        self.step_handler = step_handler
        self.service_account_ready = service_account_ready
        self.housekeeping = housekeeping
        self._scheduler_stop = threading.Event()
        self._scheduler_future: Future[Any] | None = None

    @staticmethod
    def normalize_step_config(step_type: str, config: dict[str, Any] | None) -> dict[str, Any]:
        normalized = dict(config or {})
        if step_type == "pdql_export":
            normalized.setdefault("delete_assets_after_export", False)
        return normalized

    @staticmethod
    def validate_definition(definition: dict[str, Any]) -> dict[str, Any]:
        steps = definition.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError("Runbook must contain at least one step.")
        if len(steps) > 50:
            raise ValueError("Runbook cannot contain more than 50 steps.")
        seen: set[str] = set()
        normalized = []
        for index, raw in enumerate(steps):
            if not isinstance(raw, dict):
                raise ValueError(f"Step {index + 1} must be an object.")
            step_type = str(raw.get("type") or "")
            if step_type not in SUPPORTED_STEP_TYPES:
                raise ValueError(f"Unsupported step type: {step_type}")
            step_id = str(raw.get("step_id") or f"step-{index + 1}").strip()
            if not step_id or step_id in seen:
                raise ValueError(f"Step ID must be unique: {step_id}")
            seen.add(step_id)
            retries = int(raw.get("max_retries") or 0)
            if retries < 0 or retries > 3:
                raise ValueError("max_retries must be between 0 and 3.")
            on_error = raw.get("on_error") or "stop"
            if on_error not in {"stop", "continue"}:
                raise ValueError("on_error must be stop or continue.")
            config = AutomationService.normalize_step_config(
                step_type,
                raw.get("config") if isinstance(raw.get("config"), dict) else {},
            )
            forbidden = AutomationService._forbidden_config_keys(config)
            if forbidden:
                raise ValueError(f"Runbook config cannot store credentials or secrets: {', '.join(sorted(forbidden))}")
            normalized.append(
                {
                    "step_id": step_id,
                    "type": step_type,
                    "config": config,
                    "condition": raw.get("condition") if isinstance(raw.get("condition"), dict) else None,
                    "on_error": on_error,
                    "max_retries": retries,
                }
            )
        return {"steps": normalized}

    @staticmethod
    def _forbidden_config_keys(value: Any, path: str = "") -> set[str]:
        forbidden_names = {"password", "secret", "client_secret", "access_token", "authorization", "cookie"}
        found: set[str] = set()
        if isinstance(value, dict):
            for key, nested in value.items():
                current = f"{path}.{key}" if path else str(key)
                if str(key).lower() in forbidden_names:
                    found.add(current)
                found.update(AutomationService._forbidden_config_keys(nested, current))
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                found.update(AutomationService._forbidden_config_keys(nested, f"{path}[{index}]"))
        return found

    @staticmethod
    def definition_hash(definition: dict[str, Any]) -> str:
        payload = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def is_destructive(definition: dict[str, Any]) -> bool:
        return any(
            step.get("type") == "pdql_export" and bool((step.get("config") or {}).get("delete_assets_after_export"))
            for step in definition.get("steps") or []
        )

    def create_runbook(self, name: str, description: str, definition: dict[str, Any]) -> dict[str, Any]:
        normalized = self.validate_definition(definition)
        result = self.repository.create_runbook(
            name=name.strip(), description=description.strip(), definition=normalized
        )
        self.repository.audit("runbook.created", runbook_id=result["runbook_id"])
        return result

    def update_runbook(
        self, runbook_id: str, name: str, description: str, definition: dict[str, Any]
    ) -> dict[str, Any] | None:
        normalized = self.validate_definition(definition)
        result = self.repository.update_runbook(
            runbook_id, name=name.strip(), description=description.strip(), definition=normalized
        )
        if result:
            self.repository.audit("runbook.updated", runbook_id=runbook_id)
        return result

    def publish(self, runbook_id: str, confirm_name: str | None) -> dict[str, Any] | None:
        runbook = self.repository.get_runbook(runbook_id)
        if not runbook:
            return None
        definition = self.validate_definition(runbook["draft"])
        destructive = self.is_destructive(definition)
        if destructive and confirm_name != runbook["name"]:
            raise PermissionError("Destructive runbook publication requires exact runbook name confirmation.")
        digest = self.definition_hash(definition)
        result = self.repository.publish_runbook(
            runbook_id, definition=definition, definition_hash=digest, destructive_approved=destructive
        )
        self.repository.audit(
            "runbook.published", runbook_id=runbook_id, details={"hash": digest, "destructive": destructive}
        )
        return result

    def start_run(
        self,
        runbook_id: str,
        *,
        dry_run: bool = False,
        trigger_type: str = "manual",
        schedule_id: str | None = None,
        scheduled_for: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        replay = self.repository.get_run_by_idempotency_key(idempotency_key)
        if replay:
            return {**replay, "idempotent_replay": True}
        version = self.repository.get_version(runbook_id)
        if not version:
            raise ValueError("Runbook has no published version.")
        if self.is_destructive(version["definition"]) and not version["destructive_approved"]:
            raise PermissionError("Destructive runbook version is not approved.")
        run = self.repository.create_run(
            runbook_id=runbook_id,
            version=version["version"],
            definition=version["definition"],
            trigger_type=trigger_type,
            dry_run=dry_run,
            schedule_id=schedule_id,
            scheduled_for=scheduled_for,
            idempotency_key=idempotency_key,
        )
        runbook = self.repository.get_runbook(runbook_id)
        if not runbook:
            raise ValueError("Runbook not found.")
        db.register_operation(
            run["run_id"],
            kind="automation_run",
            source_id=run["run_id"],
            status="queued",
            stage="queued",
            subject_type="runbook",
            subject_id=runbook_id,
            subject_label=runbook["name"],
            message="Runbook queued.",
            request={"version": version["version"], "dry_run": dry_run},
        )
        self.repository.audit(
            "run.started", runbook_id=runbook_id, run_id=run["run_id"], details={"trigger": trigger_type}
        )
        self.runner.submit("automation-run", self.execute_run, run["run_id"])
        return run

    def execute_run(self, run_id: str) -> None:
        run = self.repository.get_run(run_id)
        if not run:
            return
        definition = run["definition"]
        context: dict[str, Any] = {"steps": {}}
        persisted_steps = {int(item["step_index"]): item for item in run.get("steps") or []}
        for item in persisted_steps.values():
            if item["status"] == "completed":
                context["steps"][item["step_id"]] = item.get("output") or {}
        warnings = 0
        self.repository.set_run_status(run_id, "running", current_step=0)
        db.register_operation(
            run_id, kind="automation_run", source_id=run_id, status="running", stage="running", progress_percent=0
        )
        try:
            for index, step in enumerate(definition.get("steps") or []):
                if persisted_steps.get(index, {}).get("status") == "completed":
                    continue
                current = self.repository.get_run(run_id, include_steps=False)
                if current and current.get("cancel_requested"):
                    self.repository.set_step_status(run_id, index, "cancelled")
                    self._finish_run(run_id, "cancelled", context)
                    return
                if not self._condition_matches(step.get("condition"), context):
                    self.repository.set_step_status(run_id, index, "skipped", output={"reason": "condition"})
                    continue
                attempts = 0
                last_error = None
                step_config = self.normalize_step_config(
                    str(step.get("type") or ""),
                    step.get("config") if isinstance(step.get("config"), dict) else {},
                )
                while attempts <= int(step.get("max_retries") or 0):
                    attempts += 1
                    self.repository.set_run_status(run_id, "running", current_step=index)
                    self.repository.set_step_status(run_id, index, "running", attempts=attempts)
                    try:
                        if run["dry_run"]:
                            output = {"dry_run": True, "planned_config": step_config}
                        elif step["type"] == "notification":
                            output = self._notification_step(step, run)
                        else:
                            output = self.step_handler(step["type"], step_config, context, run_id, index)
                        self.repository.set_step_status(
                            run_id,
                            index,
                            "completed",
                            attempts=attempts,
                            output=output,
                            child_operation_id=(
                                str(output.get("operation_id"))
                                if isinstance(output, dict) and output.get("operation_id") is not None
                                else None
                            ),
                        )
                        context["steps"][step["step_id"]] = output
                        last_error = None
                        break
                    except Exception as exc:
                        last_error = str(exc)[:2000]
                        if attempts <= int(step.get("max_retries") or 0):
                            time.sleep(min(2**attempts, 10))
                if last_error:
                    status = "warning" if step.get("on_error") == "continue" else "failed"
                    self.repository.set_step_status(run_id, index, status, attempts=attempts, error=last_error)
                    if status == "failed":
                        self._finish_run(run_id, "failed", context, error=last_error)
                        return
                    warnings += 1
                progress = round((index + 1) * 100 / max(1, len(definition.get("steps") or [])))
                db.register_operation(
                    run_id,
                    kind="automation_run",
                    source_id=run_id,
                    status="running",
                    stage=f"step_{index + 1}",
                    progress_percent=progress,
                )
            self._finish_run(run_id, "completed_with_warnings" if warnings else "completed", context)
        except Exception as exc:
            self._finish_run(run_id, "needs_attention", context, error=str(exc)[:2000])

    def resume_runs(self) -> None:
        for run in self.repository.resumable_runs():
            if not run:
                continue
            if run.get("cancel_requested"):
                self._finish_run(run["run_id"], "cancelled", {"steps": {}})
                continue
            if any(step.get("status") == "running" for step in run.get("steps") or []):
                self._finish_run(
                    run["run_id"],
                    "needs_attention",
                    {"steps": {}},
                    error="Application restarted while a remote step outcome was ambiguous.",
                )
                continue
            self.runner.submit("automation-run", self.execute_run, run["run_id"])

    def _finish_run(self, run_id: str, status: str, context: dict[str, Any], error: str | None = None) -> None:
        self.repository.set_run_status(run_id, status, result=context, error=error)
        operation_status = "completed_with_errors" if status == "completed_with_warnings" else status
        db.register_operation(
            run_id,
            kind="automation_run",
            source_id=run_id,
            status=operation_status,
            stage=status,
            progress_percent=100,
            error={"message": error} if error else None,
            result=context,
            finished_at=db.now_utc(),
        )
        run = self.repository.get_run(run_id, include_steps=False) or {}
        level = (
            "info"
            if status == "completed"
            else "warning"
            if status in {"completed_with_warnings", "cancelled"}
            else "error"
        )
        self.notify(
            level=level,
            title=f"Runbook: {status}",
            message=error or f"Automation run finished with status {status}.",
            event_type=f"automation.{status}",
            runbook_id=run.get("runbook_id"),
            run_id=run_id,
        )
        self.repository.audit(
            f"run.{status}", runbook_id=run.get("runbook_id"), run_id=run_id, details={"error": error}
        )

    def _notification_step(self, step: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
        config = step.get("config") or {}
        notification = self.notify(
            level=str(config.get("level") or "info"),
            title=str(config.get("title") or "Runbook notification"),
            message=str(config.get("message") or "Automation notification"),
            event_type="automation.step.notification",
            runbook_id=run["runbook_id"],
            run_id=run["run_id"],
        )
        return {"notification_id": notification["notification_id"]}

    def notify(
        self,
        *,
        level: str,
        title: str,
        message: str,
        event_type: str,
        runbook_id: str | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        notification = self.repository.create_notification(
            level=level,
            title=title,
            message=message,
            event_type=event_type,
            runbook_id=runbook_id,
            run_id=run_id,
        )
        if self.settings.automation_webhook_url:
            self.repository.queue_webhook(notification["notification_id"])
        return notification

    @staticmethod
    def next_run(cron_expression: str, timezone_name: str, *, after: datetime | None = None) -> str:
        try:
            zone = ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown timezone: {timezone_name}") from exc
        base = (after or datetime.now(UTC)).astimezone(zone)
        try:
            value = croniter(cron_expression, base).get_next(datetime)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"Invalid cron expression: {cron_expression}") from exc
        return value.astimezone(UTC).isoformat(timespec="seconds")

    def start_scheduler(self) -> None:
        if self._scheduler_future and not self._scheduler_future.done():
            return
        self._scheduler_stop.clear()
        self._scheduler_future = self.runner.submit("automation-scheduler", self._scheduler_loop)

    def stop_scheduler(self) -> None:
        self._scheduler_stop.set()

    def _scheduler_loop(self) -> None:
        while not self._scheduler_stop.wait(self.settings.automation_scheduler_poll_seconds):
            try:
                self.scheduler_tick()
                self.webhook_tick()
                if self.housekeeping:
                    self.housekeeping()
            except Exception:
                continue

    def scheduler_tick(self, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        for schedule in self.repository.due_schedules(current.isoformat(timespec="seconds")):
            scheduled_for = datetime.fromisoformat(schedule["next_run_at"])
            next_at = self.next_run(schedule["cron_expression"], schedule["timezone"], after=current)
            reason = None
            if (current - scheduled_for).total_seconds() > self.settings.automation_scheduler_poll_seconds * 2:
                reason = "missed"
            elif self.repository.has_active_run(schedule["runbook_id"]):
                reason = "overlap"
            elif not self.service_account_ready():
                reason = "service_account_unavailable"
            if reason:
                version = self.repository.get_version(schedule["runbook_id"])
                if version:
                    schedule_key = f"schedule:{schedule['schedule_id']}:{schedule['next_run_at']}"
                    skipped = self.repository.get_run_by_idempotency_key(schedule_key)
                    if skipped is None:
                        skipped = self.repository.create_run(
                            runbook_id=schedule["runbook_id"],
                            version=version["version"],
                            definition=version["definition"],
                            trigger_type="schedule",
                            dry_run=False,
                            schedule_id=schedule["schedule_id"],
                            scheduled_for=schedule["next_run_at"],
                            idempotency_key=schedule_key,
                            status="skipped",
                        )
                    self.repository.audit(
                        "run.skipped",
                        runbook_id=schedule["runbook_id"],
                        run_id=skipped["run_id"],
                        details={"reason": reason, "scheduled_for": schedule["next_run_at"]},
                    )
                    self.notify(
                        level="warning",
                        title="Плановый запуск пропущен",
                        message=f"Runbook не запущен: {reason}.",
                        event_type="automation.skipped",
                        runbook_id=schedule["runbook_id"],
                        run_id=skipped["run_id"],
                    )
                self.repository.advance_schedule(
                    schedule["schedule_id"],
                    scheduled_at=schedule["next_run_at"],
                    next_run_at=next_at,
                    status=f"skipped:{reason}",
                )
                continue
            self.start_run(
                schedule["runbook_id"],
                trigger_type="schedule",
                schedule_id=schedule["schedule_id"],
                scheduled_for=schedule["next_run_at"],
                idempotency_key=f"schedule:{schedule['schedule_id']}:{schedule['next_run_at']}",
            )
            self.repository.advance_schedule(
                schedule["schedule_id"], scheduled_at=schedule["next_run_at"], next_run_at=next_at, status="queued"
            )

    def webhook_tick(self, now: datetime | None = None) -> None:
        if not self.settings.automation_webhook_url:
            return
        current = now or datetime.now(UTC)
        delays = [60, 300, 1800]
        for delivery in self.repository.due_webhooks(current.isoformat(timespec="seconds")):
            attempt = int(delivery["attempt"]) + 1
            payload = {
                "event_id": delivery["notification_id"],
                "level": delivery["level"],
                "title": delivery["title"],
                "message": delivery["message"],
                "event_type": delivery["event_type"],
                "runbook_id": delivery.get("runbook_id"),
                "run_id": delivery.get("run_id"),
                "details": delivery.get("details") or {},
                "created_at": delivery["notification_created_at"],
            }
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            signature = hmac.new(
                self.settings.automation_webhook_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            try:
                response = requests.post(
                    self.settings.automation_webhook_url,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-MPVM-Event-ID": delivery["notification_id"],
                        "X-MPVM-Signature": f"sha256={signature}",
                    },
                    timeout=15,
                )
                if 200 <= response.status_code < 300:
                    self.repository.finish_webhook_attempt(
                        delivery["delivery_id"],
                        attempt=attempt,
                        status="delivered",
                        response_status=response.status_code,
                    )
                    continue
                error = f"HTTP {response.status_code}"
                response_status = response.status_code
            except requests.RequestException as exc:
                error = str(exc)[:1000]
                response_status = None
            if attempt >= 4:
                self.repository.finish_webhook_attempt(
                    delivery["delivery_id"],
                    attempt=attempt,
                    status="failed",
                    response_status=response_status,
                    error=error,
                )
            else:
                retry_at = current + timedelta(seconds=delays[attempt - 1])
                self.repository.finish_webhook_attempt(
                    delivery["delivery_id"],
                    attempt=attempt,
                    status="pending",
                    next_attempt_at=retry_at.isoformat(timespec="seconds"),
                    response_status=response_status,
                    error=error,
                )

    @staticmethod
    def _condition_matches(condition: dict[str, Any] | None, context: dict[str, Any]) -> bool:
        if not condition:
            return True
        source = context.get("steps", {}).get(condition.get("step_id"), {})
        value: Any = source
        for part in str(condition.get("field") or "").split("."):
            if part:
                value = value.get(part) if isinstance(value, dict) else None
        expected = condition.get("value")
        operator = condition.get("operator") or "eq"
        if operator == "truthy":
            return bool(value)
        if operator == "eq":
            return value == expected
        if operator == "ne":
            return value != expected
        try:
            return {"gt": value > expected, "gte": value >= expected, "lt": value < expected, "lte": value <= expected}[
                operator
            ]
        except (KeyError, TypeError):
            return False
