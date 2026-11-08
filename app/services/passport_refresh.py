"""Run full passport catalog refreshes without holding an HTTP request open."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, cast

from fastapi import BackgroundTasks

from .. import db
from ..repositories import passport_refresh
from .main_host import host


class RefreshCancelled(Exception):
    pass


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result.get(key, 0 if key == "total" else None)
            for key in ("total", "db", "trend_sync", "detail_job")}


def _finish_pending_details(tasks: BackgroundTasks, status: str) -> None:
    """Dispose of reserved children that never reached their worker."""
    for task in tasks.tasks:
        job_id = task.kwargs.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            continue
        current = db.get_vulnerability_passport_detail_job(job_id)
        if not current or current["status"] not in {"queued", "cancelling"}:
            continue
        event = task.kwargs.get("cancel_event")
        if isinstance(event, threading.Event):
            event.set()
        db.finish_vulnerability_passport_detail_job(
            job_id, status=status, message="Parent refresh stopped before detail start.",
        )
        host.CONTAINER.operation_runner.cancellations.remove("passport-detail", job_id)


def _periodic_status(result: dict[str, Any], cancel_event: threading.Event) -> str:
    child = result.get("detail_job")
    if child:
        child = db.get_vulnerability_passport_detail_job(child["job_id"])
        result["detail_job"] = child
    if cancel_event.is_set() or (child and child.get("status") == "cancelled"):
        return "cancelled"
    if "detail_job" in result and (not child or child.get("status") not in {"completed", "completed_with_errors"}):
        return "failed"
    if (child and child.get("status") == "completed_with_errors") or (result.get("trend_sync") or {}).get("status") == "failed":
        return "completed_with_errors"
    return "completed"


def run(
    operation_id: str,
    payload: Any,
    execute_query: Callable[..., dict[str, Any]],
    submit: Callable[..., Any],
    cancel_event: threading.Event,
    *,
    complete_after_details: bool = False,
) -> None:
    tasks = BackgroundTasks()
    result: dict[str, Any] = {}

    def progress(percent: int, stage: str, message: str) -> None:
        if cancel_event.is_set():
            raise RefreshCancelled()
        passport_refresh.update(
            operation_id, status="running", stage=stage,
            percent=percent, message=message,
        )

    try:
        progress(1, "starting", "Обновление паспортов запущено.")
        result = execute_query(payload, tasks, progress)
        if cancel_event.is_set():
            raise RefreshCancelled()
        if complete_after_details:
            passport_refresh.update(
                operation_id, status="running", stage="details", percent=96,
                message="Проверка деталей паспортов.", result=_summary(result),
            )
            for task in tasks.tasks:
                if cancel_event.is_set():
                    raise RefreshCancelled()
                callback = cast(Callable[..., Any], task.func)
                callback(*task.args, **{**task.kwargs, "parent_cancel_event": cancel_event})
        else:
            for task in tasks.tasks:
                submit("passport-detail", task.func, *task.args, **task.kwargs)
        trend_failed = result.get("trend_sync", {}).get("status") == "failed" if result.get("trend_sync") else False
        status = _periodic_status(result, cancel_event) if complete_after_details else (
            "completed_with_errors" if trend_failed else "completed"
        )
        passport_refresh.update(
            operation_id, status=status,
            stage=status, percent=100,
            message=("Плановая проверка паспортов завершена: " + status) if complete_after_details else (
                "Список сохранён, но тренды не обновлены." if trend_failed else (
                "Обновление списка завершено. Детали загружаются отдельной задачей."
                if result.get("detail_job") else "Обновление паспортов завершено."
                )
            ),
            result=_summary(result),
        )
    except RefreshCancelled:
        _finish_pending_details(tasks, "cancelled")
        passport_refresh.update(operation_id, status="cancelled", stage="cancelled",
                                percent=0, message="Обновление остановлено.", result=_summary(result))
    except Exception as exc:
        _finish_pending_details(tasks, "failed")
        passport_refresh.update(operation_id, status="failed", stage="failed",
                                percent=0, message=f"Ошибка обновления: {exc}"[:2000], result=_summary(result))
