from __future__ import annotations

import builtins
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..repositories.vm_workflows import ACTIVE, TERMINAL, VmWorkflowRepository

if TYPE_CHECKING:
    from ..core.runtime import OperationRunner

Starter = Callable[[str, dict[str, Any], str], dict[str, Any]]
VerificationStarter = Callable[[str, builtins.list[str], dict[str, Any]], dict[str, Any]]
OperationAction = Callable[[str], Any]
OPERATION_TERMINAL = {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}


class VmWorkflowService:
    """Durable orchestration over the existing operation and scan-postprocess engines."""

    def __init__(
        self, repository: VmWorkflowRepository, runner: OperationRunner, remediation: Any,
        coverage: Any | None = None, risk: Any | None = None,
    ) -> None:
        self.repository = repository
        self.runner = runner
        self.remediation = remediation
        self.coverage = coverage
        self.risk = risk
        self.scan_starter: Starter | None = None
        self.verification_starter: VerificationStarter | None = None
        self.operation_canceller: OperationAction | None = None
        self.status_provider: Callable[[], dict[str, Any]] | None = None
        self._scheduled: set[str] = set()
        self._lock = threading.Lock()

    def configure(
        self, *, scan_starter: Starter, verification_starter: VerificationStarter,
        operation_canceller: OperationAction, status_provider: Callable[[], dict[str, Any]],
    ) -> None:
        self.scan_starter = scan_starter
        self.verification_starter = verification_starter
        self.operation_canceller = operation_canceller
        self.status_provider = status_provider

    def overview(self) -> dict[str, Any]:
        result = self.repository.overview()
        result["system"] = self.status_provider() if self.status_provider else {"state": "unknown"}
        result["coverage"] = self.coverage.summary() if self.coverage else {}
        result["risk"] = self.risk.summary() if self.risk else {}
        result["recent_workflows"] = self.repository.list(limit=8)["rows"]
        return result

    def list(self, **filters: Any) -> dict[str, Any]:
        return self.repository.list(**filters)

    def get(self, workflow_id: str) -> dict[str, Any] | None:
        return self.repository.get(workflow_id)

    def start_scan(
        self, *, task_id: str, options: dict[str, Any], actor: str | None, idempotency_key: str | None,
    ) -> tuple[dict[str, Any], bool]:
        workflow, replay = self.repository.create(
            kind="scan", request={"task_id": task_id, "options": options}, requested_by=actor,
            idempotency_key=idempotency_key,
        )
        if not replay:
            self._schedule(workflow["workflow_id"])
        return workflow, replay

    def track_scan(
        self, *, task_id: str, operation_id: str, options: dict[str, Any], actor: str | None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        existing = self.repository.by_operation(operation_id)
        if existing:
            return existing
        workflow, _ = self.repository.create(
            kind="scan", request={"task_id": task_id, "options": options, "existing_operation": operation_id},
            requested_by=actor, idempotency_key=(f"workflow:{idempotency_key}" if idempotency_key else None),
        )
        self.repository.update_step(workflow["workflow_id"], "validation", status="completed", progress_percent=100)
        self.repository.update_step(workflow["workflow_id"], "scan", status="completed", progress_percent=100)
        self.repository.update_run(
            workflow["workflow_id"], status="running", stage="postprocess", progress_percent=35,
            task_id=task_id, operation_id=operation_id,
        )
        self.repository.update_step(
            workflow["workflow_id"], "postprocess", status="running", operation_id=operation_id,
            message="Сканирование запущено; ожидается постобработка.",
        )
        self._schedule(workflow["workflow_id"], monitor_only=True)
        return self.repository.get(workflow["workflow_id"]) or workflow

    def start_verification(
        self, *, campaign_id: str, options: dict[str, Any], actor: str | None, idempotency_key: str | None,
    ) -> tuple[dict[str, Any] | None, bool, builtins.list[str]]:
        targets = self.repository.campaign_targets(campaign_id)
        if targets is None:
            return None, False, []
        active = self.repository.active_for_campaign(campaign_id)
        if active:
            return active, True, targets
        workflow, replay = self.repository.create(
            kind="verification", request={"campaign_id": campaign_id, "asset_ids": targets, "options": options},
            requested_by=actor, idempotency_key=idempotency_key,
        )
        if not replay:
            self.repository.update_run(workflow["workflow_id"], campaign_id=campaign_id)
            if not targets:
                self.repository.update_step(workflow["workflow_id"], "targets", status="completed", progress_percent=100,
                                            message="В кампании нет кейсов, ожидающих проверки.")
                self.repository.update_step(workflow["workflow_id"], "scan", status="skipped")
                self.repository.update_step(workflow["workflow_id"], "postprocess", status="skipped")
                self.repository.update_step(workflow["workflow_id"], "reconcile", status="completed", progress_percent=100)
                self.repository.update_run(workflow["workflow_id"], status="completed", stage="completed", progress_percent=100,
                                           result={"asset_ids": [], "message": "Nothing to verify."})
                return self.repository.get(workflow["workflow_id"]), False, targets
            self.repository.set_campaign_verification(campaign_id, workflow["workflow_id"], "queued")
            self._schedule(workflow["workflow_id"])
        return self.repository.get(workflow["workflow_id"]), replay, targets

    def cancel(self, workflow_id: str) -> dict[str, Any] | None:
        workflow = self.repository.request_cancel(workflow_id)
        if not workflow:
            return None
        self.runner.cancellations.cancel("vm-workflow", workflow_id)
        if self.operation_canceller:
            for operation_id in self._operation_ids(workflow):
                try:
                    self.operation_canceller(operation_id)
                except Exception:
                    pass
        return self.repository.get(workflow_id)

    def retry(self, workflow_id: str, actor: str | None, idempotency_key: str | None) -> tuple[dict[str, Any] | None, bool]:
        source = self.repository.get(workflow_id)
        if not source or not source.get("can_retry"):
            return None, False
        request = source.get("request") or {}
        workflow, replay = self.repository.create(
            kind=source["kind"], request=request, requested_by=actor, idempotency_key=idempotency_key,
            retry_of=workflow_id,
        )
        if not replay:
            if source["kind"] == "verification":
                self.repository.update_run(workflow["workflow_id"], campaign_id=request.get("campaign_id"))
                self.repository.set_campaign_verification(request["campaign_id"], workflow["workflow_id"], "queued")
            failed_step = next(
                (step for step in source.get("steps") or [] if step.get("status") == "failed"), None,
            )
            operation_ids = self._operation_ids(source)
            if failed_step and failed_step.get("step_key") == "reconcile" and operation_ids:
                self._resume_reconciliation(workflow["workflow_id"], source, operation_ids)
            else:
                self._schedule(workflow["workflow_id"])
        return self.repository.get(workflow["workflow_id"]), replay

    def _resume_reconciliation(
        self, workflow_id: str, source: dict[str, Any], operation_ids: builtins.list[str],
    ) -> None:
        """Reuse persisted child results when only the final reconciliation failed."""
        steps = source.get("steps") or []
        for step in steps:
            step_key = str(step["step_key"])
            if step_key == "reconcile":
                continue
            status = "skipped" if step.get("status") == "skipped" else "completed"
            self.repository.update_step(
                workflow_id, step_key, status=status, progress_percent=100,
                operation_id=step.get("operation_id"), result=step.get("result") or {},
                message="Результат переиспользован из предыдущей попытки.",
            )
        self.repository.update_step(
            workflow_id, "reconcile", status="pending", progress_percent=0,
            message="Повтор сверки с сохранёнными результатами.",
        )
        self.repository.update_run(
            workflow_id, status="running", stage="reconcile", progress_percent=90,
            task_id=source.get("task_id"), campaign_id=source.get("campaign_id"),
            operation_id=operation_ids[0] if len(operation_ids) == 1 else None,
            result={"operation_ids": operation_ids, "resumed_from": source["workflow_id"]},
        )
        self._schedule(workflow_id, monitor_only=True)

    def resume(self) -> None:
        for workflow in self.repository.active():
            self._schedule(workflow["workflow_id"], monitor_only=bool(workflow.get("operation_id")))

    def _schedule(self, workflow_id: str, monitor_only: bool = False) -> None:
        with self._lock:
            if workflow_id in self._scheduled:
                return
            self._scheduled.add(workflow_id)
        future = self.runner.submit("vm-workflow", self._run, workflow_id, monitor_only)
        future.add_done_callback(lambda _: self._forget(workflow_id))

    def _forget(self, workflow_id: str) -> None:
        with self._lock:
            self._scheduled.discard(workflow_id)

    def _run(self, workflow_id: str, monitor_only: bool) -> None:
        token = self.runner.cancellations.register("vm-workflow", workflow_id)
        try:
            workflow = self.repository.get(workflow_id)
            if not workflow or workflow["status"] not in ACTIVE:
                return
            if workflow.get("cancel_requested"):
                self._finish_cancelled(workflow)
                return
            self.repository.update_run(workflow_id, status="running", stage=workflow.get("stage") or "starting")
            operation_ids = self._operation_ids(workflow)
            if not monitor_only and not operation_ids:
                operation_ids = self._start(workflow_id, workflow)
            self._monitor(workflow_id, operation_ids, token)
        except Exception as exc:
            current = self.repository.get(workflow_id)
            if current and current["status"] not in TERMINAL:
                steps = current.get("steps") or []
                active_step = next((step for step in steps if step.get("status") == "running"), None)
                active_step = active_step or next((step for step in steps if step.get("status") == "pending"), None)
                self.repository.update_step(
                    workflow_id, active_step["step_key"] if active_step else "scan",
                    status="failed", error={"message": str(exc)},
                )
                self.repository.update_run(
                    workflow_id, status="failed", stage="failed", error={"message": str(exc)}, progress_percent=current.get("progress_percent", 0),
                )
                if current.get("campaign_id"):
                    self.repository.set_campaign_verification(current["campaign_id"], workflow_id, "failed", str(exc))
        finally:
            self.runner.cancellations.remove("vm-workflow", workflow_id)

    def _start(self, workflow_id: str, workflow: dict[str, Any]) -> builtins.list[str]:
        request = workflow.get("request") or {}
        if workflow["kind"] == "scan":
            if not self.scan_starter:
                raise RuntimeError("VM scan starter is not configured.")
            self.repository.update_step(workflow_id, "validation", status="running", message="Проверка задачи MP VM.")
            result = self.scan_starter(str(request["task_id"]), request.get("options") or {}, workflow_id)
            if result.get("status") != "started":
                raise RuntimeError(str(result.get("error") or f"Scan was not started: {result.get('status')}"))
            operation_id = str(result.get("operation_id") or result.get("postprocess_run_id"))
            self.repository.update_step(workflow_id, "validation", status="completed", progress_percent=100)
            self.repository.update_step(workflow_id, "scan", status="completed", progress_percent=100, result={"task_id": request["task_id"]})
            self.repository.update_step(workflow_id, "postprocess", status="running", operation_id=operation_id)
            self.repository.update_run(
                workflow_id, stage="postprocess", progress_percent=35, task_id=request["task_id"], operation_id=operation_id,
            )
            return [operation_id]
        if not self.verification_starter:
            raise RuntimeError("VM verification starter is not configured.")
        assets = builtins.list(dict.fromkeys(request.get("asset_ids") or []))
        self.repository.update_step(workflow_id, "targets", status="completed", progress_percent=100, result={"asset_ids": assets})
        self.repository.update_step(workflow_id, "scan", status="running", message=f"Запуск проверок для {len(assets)} активов.")
        if workflow.get("campaign_id"):
            self.repository.set_campaign_verification(workflow["campaign_id"], workflow_id, "running")
        result = self.verification_starter(workflow_id, assets, request.get("options") or {})
        operation_ids = [str(value) for value in result.get("operation_ids") or [] if value]
        errors = result.get("errors") or []
        if not operation_ids and errors:
            raise RuntimeError("; ".join(str(item.get("message") or item) for item in errors))
        self.repository.update_step(workflow_id, "scan", status="completed", progress_percent=100, result=result)
        self.repository.update_step(workflow_id, "postprocess", status="running", message="Ожидание обновления карточек.")
        self.repository.update_run(
            workflow_id, stage="postprocess", progress_percent=35,
            operation_id=operation_ids[0] if len(operation_ids) == 1 else None,
            result={"operation_ids": operation_ids, "start_errors": errors},
        )
        return operation_ids

    def _monitor(self, workflow_id: str, operation_ids: builtins.list[str], token: threading.Event) -> None:
        if not operation_ids:
            raise RuntimeError("Workflow has no child operations.")
        while True:
            current = self.repository.get(workflow_id)
            if not current:
                return
            if token.is_set() or current.get("cancel_requested"):
                self._finish_cancelled(current)
                return
            operations = [self._operation(value) for value in operation_ids]
            known = [item for item in operations if item]
            if not known:
                time.sleep(1)
                continue
            average = sum(int(item.get("progress_percent") or 0) for item in known) / len(operation_ids)
            self.repository.update_step(workflow_id, "postprocess", progress_percent=round(average), message=self._progress_message(known))
            self.repository.update_run(workflow_id, progress_percent=min(90, 35 + round(average * 0.55)))
            if all(item.get("status") in OPERATION_TERMINAL for item in known) and len(known) == len(operation_ids):
                failed = [item for item in known if item.get("status") != "completed"]
                self._reconcile(workflow_id, current, known, failed)
                return
            time.sleep(1)

    def _reconcile(
        self, workflow_id: str, workflow: dict[str, Any], operations: builtins.list[dict[str, Any]],
        failed: builtins.list[dict[str, Any]],
    ) -> None:
        self.repository.update_step(workflow_id, "postprocess", status="completed" if not failed else "failed", progress_percent=100,
                                    result={"operations": operations}, error={"failed_operation_ids": [item["operation_id"] for item in failed]})
        self.repository.update_step(workflow_id, "reconcile", status="running", message="Сверка находок и пересчёт состояния.")
        request = workflow.get("request") or {}
        assets = builtins.list(dict.fromkeys(request.get("asset_ids") or []))
        if assets:
            totals = {"created": 0, "reopened": 0, "resolved": 0}
            for asset_id in assets:
                result = self.remediation.reconcile_asset(asset_id)
                for key in totals:
                    totals[key] += int(result.get(key) or 0)
        else:
            totals = self.remediation.reconcile_all()
        self.repository.update_step(workflow_id, "reconcile", status="completed", progress_percent=100, result=totals)
        start_errors = (workflow.get("result") or {}).get("start_errors") or []
        failed_assets = [str(item.get("subject", {}).get("id") or "") for item in failed]
        failed_assets.extend(str(item.get("asset_id") or "") for item in start_errors)
        if workflow.get("campaign_id"):
            self.repository.finalize_campaign_verification(workflow["campaign_id"], workflow_id, [value for value in failed_assets if value])
        status = "completed_with_errors" if failed or start_errors else "completed"
        self.repository.update_run(
            workflow_id, status=status, stage="completed", progress_percent=100,
            result={"operation_ids": [item["operation_id"] for item in operations], "reconciliation": totals,
                    "failed_operation_ids": [item["operation_id"] for item in failed], "start_errors": start_errors},
        )

    def _finish_cancelled(self, workflow: dict[str, Any]) -> None:
        workflow_id = workflow["workflow_id"]
        for step in workflow.get("steps") or []:
            if step["status"] in {"pending", "running"}:
                self.repository.update_step(workflow_id, step["step_key"], status="cancelled")
        self.repository.update_run(workflow_id, status="cancelled", stage="cancelled")
        if workflow.get("campaign_id"):
            self.repository.set_campaign_verification(workflow["campaign_id"], workflow_id, "failed", "Проверка отменена.")

    @staticmethod
    def _operation(operation_id: str) -> dict[str, Any] | None:
        from .. import db
        return db.get_operation(operation_id, sync_sources=True)

    @staticmethod
    def _operation_ids(workflow: dict[str, Any]) -> builtins.list[str]:
        result = workflow.get("result") or {}
        values = result.get("operation_ids") or []
        if workflow.get("operation_id") and workflow["operation_id"] not in values:
            values = [workflow["operation_id"], *values]
        return [str(value) for value in dict.fromkeys(values) if value]

    @staticmethod
    def _progress_message(operations: builtins.list[dict[str, Any]]) -> str:
        completed = sum(item.get("status") in OPERATION_TERMINAL for item in operations)
        return f"Обработано операций: {completed} из {len(operations)}."
