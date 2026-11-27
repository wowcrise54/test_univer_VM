from __future__ import annotations

import os
import threading
from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime
from typing import Any

from ..api.schemas import VulnerabilityPassportQueryRequest
from ..core.config import Settings
from ..core.runtime import OperationRunner
from ..diagnostics import log_event, log_exception
from ..mpvm_client import VULNER_PASSPORT_PDQL
from ..repositories import passport_refresh


class PassportSyncScheduler:
    def __init__(self, *, settings: Settings, runner: OperationRunner,
                 ready: Callable[[], bool],
                 execute: Callable[[str, VulnerabilityPassportQueryRequest, threading.Event], None]) -> None:
        self.settings = settings
        self.runner = runner
        self.ready = ready
        self.execute = execute
        self._stop = threading.Event()
        self._future: Future[Any] | None = None
        self._operation_id: str | None = None
        self._lock = threading.Lock()
        self._connection_unavailable = False

    def start(self) -> None:
        if not self.settings.passport_sync_enabled:
            return
        with self._lock:
            if self._future is not None and not self._future.done():
                return
            self._stop.clear()
            self._future = self.runner.submit("passport-sync-scheduler", self._loop)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            operation_id = self._operation_id
        if operation_id is not None:
            self.runner.cancellations.cancel("passport-refresh", operation_id)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log_exception("passport-sync", "passport.periodic.tick.failed")
            if self._stop.wait(self.settings.automation_scheduler_poll_seconds):
                return

    def tick(self, now: datetime | None = None) -> None:
        if not self.settings.passport_sync_enabled or self._stop.is_set():
            return
        if not self.ready():
            if not self._connection_unavailable:
                log_event("passport-sync", "passport.periodic.skipped", reason="mpvm_unavailable")
                self._connection_unavailable = True
            return
        self._connection_unavailable = False
        payload = VulnerabilityPassportQueryRequest(
            pdql=VULNER_PASSPORT_PDQL,
            utc_offset=os.getenv("MPVM_UTC_OFFSET") or os.getenv("MP10_UTC_OFFSET") or "+05:00",
            limit=None, batch_size=5000, save_to_db=True, load_details=True,
        )
        operation = passport_refresh.reserve_periodic(
            payload.model_dump(), now=now or datetime.now(UTC),
            interval_seconds=self.settings.passport_sync_interval_seconds,
        )
        if operation is None:
            return
        identifier = operation["operation_id"]
        event = self.runner.cancellations.register("passport-refresh", identifier)
        with self._lock:
            self._operation_id = identifier
        try:
            if self._stop.is_set():
                event.set()
                passport_refresh.update(identifier, status="cancelled", stage="cancelled", percent=0,
                                        message="Плановая проверка отменена при остановке приложения.")
                return
            self.execute(identifier, payload, event)
        except Exception:
            passport_refresh.update(identifier, status="failed", stage="failed", percent=0,
                                    message="Не удалось выполнить плановую проверку паспортов.")
            raise
        finally:
            self.runner.cancellations.remove("passport-refresh", identifier)
            with self._lock:
                self._operation_id = None
