"""Run full passport catalog refreshes without holding an HTTP request open."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from fastapi import BackgroundTasks

from ..repositories import passport_refresh


class RefreshCancelled(Exception):
    pass


def run(
    operation_id: str,
    payload: Any,
    execute_query: Callable[..., dict[str, Any]],
    submit: Callable[..., Any],
    cancel_event: threading.Event,
) -> None:
    tasks = BackgroundTasks()

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
        for task in tasks.tasks:
            submit("passport-detail", task.func, *task.args, **task.kwargs)
        trend_failed = result.get("trend_sync", {}).get("status") == "failed" if result.get("trend_sync") else False
        passport_refresh.update(
            operation_id, status="completed_with_errors" if trend_failed else "completed",
            stage="completed", percent=100,
            message="Список сохранён, но тренды не обновлены." if trend_failed else (
                "Обновление списка завершено. Детали загружаются отдельной задачей."
                if result.get("detail_job") else "Обновление паспортов завершено."
            ),
            result={
                "total": result.get("total", 0),
                "db": result.get("db"),
                "trend_sync": result.get("trend_sync"),
                "detail_job": result.get("detail_job"),
            },
        )
    except RefreshCancelled:
        passport_refresh.update(operation_id, status="cancelled", stage="cancelled",
                                percent=0, message="Обновление остановлено.")
    except Exception as exc:
        passport_refresh.update(operation_id, status="failed", stage="failed",
                                percent=0, message=f"Ошибка обновления: {exc}"[:2000])
