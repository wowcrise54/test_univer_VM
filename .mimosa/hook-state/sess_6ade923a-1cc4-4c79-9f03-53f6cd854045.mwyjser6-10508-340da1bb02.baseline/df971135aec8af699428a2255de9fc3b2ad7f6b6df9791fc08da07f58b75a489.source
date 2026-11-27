from __future__ import annotations

import asyncio
import copy
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from typing import Any, Literal, cast

import requests
from fastapi import BackgroundTasks, HTTPException

from .. import db
from ..api.schemas import (
    AssetCardFieldQueryRequest,
    AssetCardRefreshScanRequest,
    PdqlExportRequest,
    StartScannerTaskRequest,
    VulnerabilityPassportQueryRequest,
)
from ..automations import AutomationStepCancelled
from ..mpvm.common import as_dict, http_error
from ..mpvm.scanner_task_rows import remote_scanner_task_templates
from ..mpvm_client import MpVmApiError
from .main_host import host


def resolve_asset_card_refresh_template(
    asset_id: str,
    template_task_id: str | None = None,
) -> dict[str, Any]:
    local = db.get_asset_card_refresh_template(asset_id, template_task_id)
    if local and isinstance(local.get("payload"), dict):
        return local

    client, token = host.require_mpvm()
    try:
        remote = remote_scanner_task_templates(
            client,
            token,
            main_filter=template_task_id,
            max_tasks=200 if template_task_id else 50,
        )
    except (MpVmApiError, requests.RequestException) as exc:
        raise http_error(exc) from exc


    selected = next(
        (item for item in remote if not template_task_id or item["mp_task_id"] == template_task_id),
        None,
    )
    if not selected:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SCANNER_TASK_TEMPLATE_REQUIRED",
                "message": (
                    "Выберите сохранённую задачу MP VM с заполненными scope и scanner profile; "
                    "её настройки нужны для повторного сканирования карточек."
                ),
            },
        )
    return db.record_scan_task(
        mp_task_id=selected["mp_task_id"],
        payload=selected["payload"],
        status="imported_as_refresh_template",
        remote_response={"source": "remote_scanner_tasks"},
    )


def build_asset_refresh_task_payload(
    template_payload: dict[str, Any],
    *,
    asset_id: str,
    target_ip: str,
    display_name: str,
) -> dict[str, Any]:
    task_payload = copy.deepcopy(template_payload)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    task_payload["name"] = f"Asset card refresh {display_name} {stamp}"[:250]
    task_payload["description"] = f"Automatic refresh scan for local asset card {asset_id}; target {target_ip}."
    include = as_dict(task_payload.get("include"))
    include.update({"assets": [], "targets": [target_ip], "assetsGroups": []})
    task_payload["include"] = include
    exclude = as_dict(task_payload.get("exclude"))
    exclude.update({"assets": [], "targets": [], "assetsGroups": []})
    task_payload["exclude"] = exclude
    trigger = task_payload.get("triggerParameters")
    if isinstance(trigger, dict):
        trigger["isEnabled"] = False
    return task_payload


def run_background_tasks(background_tasks: BackgroundTasks) -> None:
    if background_tasks.tasks:
        asyncio.run(background_tasks())


def wait_for_automation_operation(
    operation_id: str,
    timeout_seconds: float,
    *,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    terminal = {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}
    while time.monotonic() < deadline:
        if cancel_check and cancel_check():
            raise AutomationStepCancelled("Automation run was cancelled.")
        operation = db.get_operation(operation_id)
        if operation and operation.get("status") in terminal:
            if operation["status"] == "cancelled":
                raise AutomationStepCancelled(f"Operation {operation_id} was cancelled.")
            if operation["status"] not in {"completed", "completed_with_errors"}:
                raise RuntimeError(operation.get("message") or f"Operation {operation_id} failed.")
            return operation
        time.sleep(2)
    raise TimeoutError(f"Operation {operation_id} did not finish within {timeout_seconds} seconds.")


def execute_automation_step(
    step_type: str,
    config: dict[str, Any],
    _context: dict[str, Any],
    run_id: str,
    step_index: int,
) -> dict[str, Any]:
    idempotency_key = f"automation:{run_id}:{step_index}"
    register_child = _context.get("_register_child_operation")
    cancel_check = _context.get("_is_cancel_requested")
    if step_type == "scanner_task_start":
        task_id = str(config.get("task_id") or "").strip()
        if not task_id:
            raise ValueError("scanner_task_start requires task_id.")
        background = BackgroundTasks()
        options = StartScannerTaskRequest(**(config.get("options") or {}))
        result = host.start_scanner_task(task_id, background, options, idempotency_key=idempotency_key)
        host.run_background_tasks(background)
        operation_id = result.get("operation_id") or result.get("postprocess_run_id")
        if operation_id and callable(register_child):
            register_child(str(operation_id))
        if operation_id and bool(config.get("wait", True)):
            operation = host.wait_for_automation_operation(
                str(operation_id),
                float(config.get("timeout_seconds") or 7200),
                cancel_check=cancel_check if callable(cancel_check) else None,
            )
            return {**result, "operation_id": operation_id, "operation": operation}
        return {**result, "operation_id": operation_id}
    if step_type == "pdql_export":
        return host.export_pdql(PdqlExportRequest(**config))
    if step_type == "passport_sync":
        background = BackgroundTasks()
        result = host.query_vulnerability_passports(VulnerabilityPassportQueryRequest(**config), background)
        host.run_background_tasks(background)
        operation_id = (result.get("detail_job") or {}).get("job_id")
        return {**result, "operation_id": operation_id}
    if step_type == "asset_card_build":
        selection = str(config.get("selection") or "asset").strip()
        if selection not in {"asset", "stale", "all"}:
            raise ValueError("asset_card_build selection must be asset, stale or all.")
        if selection in {"stale", "all"}:
            return refresh_asset_cards_for_automation(
                selection=cast(Literal["all", "stale"], selection),
                config=config,
                register_child=register_child if callable(register_child) else None,
                cancel_check=cancel_check if callable(cancel_check) else None,
                run_id=run_id,
                step_index=step_index,
            )
        asset_id = str(config.get("asset_id") or "").strip()
        if not asset_id:
            raise ValueError("asset_card_build requires asset_id when selection=asset.")
        return host.refresh_one_asset_card_for_automation(
            asset_id=asset_id,
            config=config,
            register_child=register_child if callable(register_child) else None,
            cancel_check=cancel_check if callable(cancel_check) else None,
            idempotency_key=idempotency_key,
        )
    if step_type == "asset_query":
        return host.asset_card_query(AssetCardFieldQueryRequest(**config))
    raise ValueError(f"Unsupported automation step: {step_type}")


def refresh_one_asset_card_for_automation(
    *,
    asset_id: str,
    config: dict[str, Any],
    register_child: Callable[[str], Any] | None,
    cancel_check: Callable[[], bool] | None,
    idempotency_key: str,
) -> dict[str, Any]:
    if cancel_check and cancel_check():
        raise AutomationStepCancelled("Automation run was cancelled.")
    background = BackgroundTasks()
    start_options = as_dict(config.get("start_options"))
    result = host.refresh_asset_card_by_scan(
        asset_id,
        AssetCardRefreshScanRequest(
            template_task_id=str(config.get("template_task_id") or "").strip() or None,
            start_options=StartScannerTaskRequest(**start_options),
        ),
        background,
        idempotency_key=idempotency_key,
    )
    host.run_background_tasks(background)
    operation_id = result.get("operation_id") or result.get("postprocess_run_id")
    if operation_id and register_child:
        register_child(str(operation_id))
    if operation_id and bool(config.get("wait", True)):
        operation = host.wait_for_automation_operation(
            str(operation_id),
            float(config.get("timeout_seconds") or 14400),
            cancel_check=cancel_check,
        )
        return {**result, "operation_id": operation_id, "operation": operation}
    return {**result, "operation_id": operation_id}


def refresh_asset_card_batch(
    *,
    selection: Literal["all", "stale"],
    config: dict[str, Any],
    register_child: Callable[[str], Any] | None,
    cancel_check: Callable[[], bool] | None,
    idempotency_prefix: str,
    progress_callback: Callable[[int, int, int, str | None], Any] | None = None,
) -> dict[str, Any]:
    requested_limit = config.get("max_assets")
    max_assets = int(requested_limit) if requested_limit is not None and requested_limit != "" else None
    if max_assets is not None and max_assets < 1:
        raise ValueError("max_assets must be greater than zero.")
    requested_parallelism = config.get("parallelism")
    parallelism = (
        host.ASSET_CARD_REFRESH_WORKERS
        if requested_parallelism is None or requested_parallelism == ""
        else min(int(requested_parallelism), host.ASSET_CARD_REFRESH_WORKERS)
    )
    if parallelism < 1:
        raise ValueError("parallelism must be greater than zero.")

    rows: list[dict[str, Any]] = []
    offset = 0
    page_size = 500
    while max_assets is None or len(rows) < max_assets:
        if cancel_check and cancel_check():
            raise AutomationStepCancelled("Automation run was cancelled.")
        limit = page_size if max_assets is None else min(page_size, max_assets - len(rows))
        if selection == "stale":
            page = host.CONTAINER.services.coverage.list_assets(q=None, issue="stale", limit=limit, offset=offset)
        else:
            page = host.CONTAINER.services.asset_cards.list(
                q=None,
                limit=limit,
                offset=offset,
                sort_by="last_seen",
                sort_dir="asc",
            )
        page_rows = page.get("rows") if isinstance(page.get("rows"), list) else []
        rows.extend(item for item in page_rows if item.get("asset_id"))
        offset += len(page_rows)
        if len(page_rows) < limit or offset >= int(page.get("total") or 0):
            break

    batch_config = config
    if rows:
        template = host.resolve_asset_card_refresh_template(
            str(rows[0]["asset_id"]),
            str(config.get("template_task_id") or "").strip() or None,
        )
        batch_config = {**config, "template_task_id": template["mp_task_id"]}
    if progress_callback:
        progress_callback(len(rows), 0, 0, None)

    results_by_index: dict[int, dict[str, Any]] = {}
    failures_by_index: dict[int, dict[str, str]] = {}
    child_operation_ids: set[str] = set()
    child_operation_ids_lock = threading.Lock()

    def track_child(child_id: str) -> None:
        clean_child_id = str(child_id).strip()
        if clean_child_id:
            with child_operation_ids_lock:
                child_operation_ids.add(clean_child_id)
        if register_child:
            register_child(child_id)

    def cancel_started_children() -> None:
        with child_operation_ids_lock:
            started_child_ids = tuple(child_operation_ids)
        for child_id in started_child_ids:
            try:
                child = db.get_operation(child_id)
                if child and child.get("can_cancel"):
                    host.cancel_operation(child_id)
            except Exception:
                host.log_exception(
                    "asset-card-bulk-refresh",
                    "bulk_refresh.child_cancel_failed",
                    child_operation_id=child_id,
                )

    def refresh_one(index: int, item: dict[str, Any]) -> tuple[int, str, dict[str, Any]]:
        while not host.ASSET_CARD_REFRESH_SEMAPHORE.acquire(timeout=0.25):
            if cancel_check and cancel_check():
                raise AutomationStepCancelled("Automation run was cancelled.")
        asset_id = str(item["asset_id"])
        try:
            if cancel_check and cancel_check():
                raise AutomationStepCancelled("Automation run was cancelled.")
            result = host.refresh_one_asset_card_for_automation(
                asset_id=asset_id,
                config=batch_config,
                register_child=track_child,
                cancel_check=cancel_check,
                idempotency_key=f"{idempotency_prefix}:{selection}:{index}:{asset_id}",
            )
            return index, asset_id, result
        finally:
            host.ASSET_CARD_REFRESH_SEMAPHORE.release()

    worker_count = min(parallelism, len(rows)) if rows else parallelism
    next_index = 0
    pending: dict[Future[tuple[int, str, dict[str, Any]]], tuple[int, str]] = {}
    cancelled = False
    executor = ThreadPoolExecutor(max_workers=max(1, worker_count), thread_name_prefix="asset-card-refresh")
    try:
        while next_index < len(rows) and len(pending) < worker_count:
            item = rows[next_index]
            asset_id = str(item["asset_id"])
            pending[executor.submit(refresh_one, next_index, item)] = (next_index, asset_id)
            next_index += 1

        while pending:
            if cancel_check and cancel_check():
                cancelled = True
                raise AutomationStepCancelled("Automation run was cancelled.")
            done, _ = wait(tuple(pending), timeout=0.25, return_when=FIRST_COMPLETED)
            if not done:
                continue
            for future in sorted(done, key=lambda item: pending[item][0]):
                index, asset_id = pending.pop(future)
                try:
                    _, _, result = future.result()
                    results_by_index[index] = {"asset_id": asset_id, "operation_id": result.get("operation_id")}
                except AutomationStepCancelled:
                    cancelled = True
                    raise
                except Exception as exc:
                    failures_by_index[index] = {"asset_id": asset_id, "error": str(exc)[:1000]}
                if progress_callback:
                    progress_callback(
                        len(rows),
                        len(results_by_index),
                        len(failures_by_index),
                        asset_id,
                    )
                if next_index < len(rows):
                    item = rows[next_index]
                    next_asset_id = str(item["asset_id"])
                    pending[executor.submit(refresh_one, next_index, item)] = (next_index, next_asset_id)
                    next_index += 1
    except AutomationStepCancelled:
        cancelled = True
        cancel_started_children()
        for future in pending:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=cancelled)
        if cancelled:
            cancel_started_children()

    results = [results_by_index[index] for index in sorted(results_by_index)]
    failures = [failures_by_index[index] for index in sorted(failures_by_index)]

    summary = {
        "selection": selection,
        "stale_days": host.CONTAINER.services.coverage.stale_days,
        "parallelism": worker_count,
        "selected_count": len(rows),
        "completed_count": len(results),
        "failed_count": len(failures),
        "results": results,
        "failures": failures,
    }
    return summary


def refresh_asset_cards_for_automation(
    *,
    selection: Literal["all", "stale"],
    config: dict[str, Any],
    register_child: Callable[[str], Any] | None,
    cancel_check: Callable[[], bool] | None,
    run_id: str,
    step_index: int,
) -> dict[str, Any]:
    summary = refresh_asset_card_batch(
        selection=selection,
        config=config,
        register_child=register_child,
        cancel_check=cancel_check,
        idempotency_prefix=f"automation:{run_id}:{step_index}",
    )
    failures = summary["failures"]
    if failures:
        raise RuntimeError(
            f"Failed to refresh {len(failures)} of {summary['selected_count']} {selection} asset card(s): "
            + "; ".join(f"{item['asset_id']}: {item['error']}" for item in failures[:5])
        )
    return summary


def refresh_stale_asset_cards_for_automation(
    *,
    config: dict[str, Any],
    register_child: Callable[[str], Any] | None,
    cancel_check: Callable[[], bool] | None,
    run_id: str,
    step_index: int,
) -> dict[str, Any]:
    """Compatibility wrapper for callers that explicitly request stale cards."""
    return refresh_asset_cards_for_automation(
        selection="stale",
        config=config,
        register_child=register_child,
        cancel_check=cancel_check,
        run_id=run_id,
        step_index=step_index,
    )


def run_asset_card_bulk_refresh_operation(
    *,
    operation_id: str,
    config: dict[str, Any],
    cancel_event: threading.Event,
) -> None:
    selection = str(config.get("selection") or "all")
    label = "Все карточки активов" if selection == "all" else "Карточки старше порога свежести"
    state: dict[str, Any] = {
        "current_child_operation_id": None,
        "child_operation_ids": [],
    }
    state_lock = threading.Lock()
    operation_update_lock = threading.Lock()

    def state_snapshot(**updates: Any) -> dict[str, Any]:
        with state_lock:
            state.update(updates)
            return copy.deepcopy(state)

    def persist_progress(selected: int, completed: int, failed: int, asset_id: str | None) -> None:
        processed = completed + failed
        with operation_update_lock:
            snapshot = state_snapshot(
                selected_count=selected,
                completed_count=completed,
                failed_count=failed,
                current_asset_id=asset_id,
            )
            db.register_operation(
                operation_id,
                kind="asset_card_bulk_refresh",
                source_id=operation_id,
                status="running",
                stage="refreshing" if selected else "completed",
                progress_percent=round(processed * 100 / selected) if selected else 100,
                subject_type="asset_cards",
                subject_label=label,
                message=(
                    f"Обработано карточек: {processed} из {selected}; ошибок: {failed}."
                    if selected
                    else "Карточек для обновления не найдено."
                ),
                result=snapshot,
            )

    def register_child(child_id: str) -> None:
        with operation_update_lock:
            with state_lock:
                child_ids = state["child_operation_ids"]
                if child_id not in child_ids:
                    child_ids.append(child_id)
                state["current_child_operation_id"] = child_id
                snapshot = copy.deepcopy(state)
            db.register_operation(
                operation_id,
                kind="asset_card_bulk_refresh",
                source_id=operation_id,
                status="running",
                stage="refreshing",
                subject_type="asset_cards",
                subject_label=label,
                message=(
                    f"Запущено дочерних операций: "
                    f"{len(snapshot['child_operation_ids'])}; последняя — {child_id}."
                ),
                result=snapshot,
            )

    try:
        db.register_operation(
            operation_id,
            kind="asset_card_bulk_refresh",
            source_id=operation_id,
            status="running",
            stage="selecting",
            progress_percent=0,
            subject_type="asset_cards",
            subject_label=label,
            message="Формируется список карточек для обновления.",
            started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        worker_config = {**config, "wait": True}
        summary = refresh_asset_card_batch(
            selection="stale" if selection == "stale" else "all",
            config=worker_config,
            register_child=register_child,
            cancel_check=cancel_event.is_set,
            idempotency_prefix=f"bulk-refresh:{operation_id}",
            progress_callback=persist_progress,
        )
        snapshot = state_snapshot(
            **summary,
            current_child_operation_id=None,
        )
        failed = int(summary["failed_count"])
        terminal_status = "completed_with_errors" if failed else "completed"
        db.register_operation(
            operation_id,
            kind="asset_card_bulk_refresh",
            source_id=operation_id,
            status=terminal_status,
            stage=terminal_status,
            progress_percent=100,
            subject_type="asset_cards",
            subject_label=label,
            message=(
                f"Обновлено карточек: {summary['completed_count']} из {summary['selected_count']}; ошибок: {failed}."
            ),
            result=snapshot,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
    except AutomationStepCancelled:
        snapshot = state_snapshot(current_child_operation_id=None)
        db.register_operation(
            operation_id,
            kind="asset_card_bulk_refresh",
            source_id=operation_id,
            status="cancelled",
            stage="cancelled",
            progress_percent=0,
            subject_type="asset_cards",
            subject_label=label,
            message="Массовое обновление карточек остановлено.",
            result=snapshot,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
    except Exception as exc:
        host.log_exception("asset-card-bulk-refresh", "bulk_refresh.failed", operation_id=operation_id)
        snapshot = state_snapshot(current_child_operation_id=None)
        db.register_operation(
            operation_id,
            kind="asset_card_bulk_refresh",
            source_id=operation_id,
            status="failed",
            stage="failed",
            progress_percent=0,
            subject_type="asset_cards",
            subject_label=label,
            message="Не удалось выполнить массовое обновление карточек.",
            error={"message": str(exc)[:1000]},
            result=snapshot,
            finished_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
