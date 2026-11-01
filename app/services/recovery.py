from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from typing import Any


class DatabaseRecovery:
    """Resume unfinished startup steps once, under a process-wide lock.

    Successful steps are checkpoints: a later outage must not interrupt active
    jobs or launch another scheduler. Failed steps must themselves be idempotent.
    A database connection alone never makes an unconfigured process ready.
    A check that finds another one running answers with the last finished
    result, so parallel status requests do not report a healthy database down.
    """

    def __init__(
        self, *, probe: Callable[[], bool],
        steps: Sequence[tuple[str, Callable[[], Any]]] | None = None,
        interval_seconds: float = 5,
    ) -> None:
        self._probe = probe
        self._steps = tuple(steps or ())
        self._configured = steps is not None
        self._completed: set[str] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._interval = interval_seconds
        self._last: dict[str, Any] | None = None

    def configure(self, steps: Sequence[tuple[str, Callable[[], Any]]]) -> None:
        with self._lock:
            self._steps = tuple(steps)
            self._configured = True
            self._completed.clear()
            self._last = None

    def check(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ready": False, "database_ready": False,
            "schema_current": False, "recovery_complete": False,
        }
        if not self._lock.acquire(blocking=False):
            last = self._last
            return dict(last) if last is not None else {**result, "reason": "recovery_in_progress"}
        try:
            self._last = self._run(result)
            return dict(self._last)
        finally:
            self._lock.release()

    def _run(self, result: dict[str, Any]) -> dict[str, Any]:
        try:
            result["schema_current"] = self._probe()
            result["database_ready"] = True
            if not self._configured:
                return {**result, "reason": "startup_pending"}
            for name, step in self._steps:
                if name not in self._completed:
                    step()
                    self._completed.add(name)
            result["recovery_complete"] = True
            result["database_ready"] = False
            result["schema_current"] = False
            result["schema_current"] = self._probe()
            result["database_ready"] = True
            result["ready"] = result["schema_current"]
            if not result["ready"]:
                result["reason"] = "schema_mismatch"
            return result
        except Exception as exc:
            # Reasons are types only; connection strings and raw errors stay out
            # of both public probes and protected status responses.
            return {**result, "ready": False, "reason": type(exc).__name__}

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._monitor, name="database-recovery", daemon=True)
        self._thread.start()

    def _monitor(self) -> None:
        while not self._stop.wait(self._interval):
            self.check()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=15)

