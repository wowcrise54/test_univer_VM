from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from ..diagnostics import log_event, log_exception


@dataclass
class PendingJob:
    kind: str
    job_id: str
    task: Callable[[], Any]
    heartbeat: Callable[[], Any] | None = None
    requires_session: bool = True


class JobRunner:
    """Bounded in-process job runner with deduplication and session gating.

    Jobs remain durable in their PostgreSQL job tables. This class only owns
    process-local execution, so it can later be replaced by an external worker
    without changing handlers or HTTP contracts.
    """

    def __init__(
        self,
        limits: dict[str, int],
        *,
        session_ready: Callable[[], bool],
        heartbeat_seconds: float = 15.0,
    ) -> None:
        self._executors = {
            kind: ThreadPoolExecutor(max_workers=max(1, limit), thread_name_prefix=f"job-{kind}")
            for kind, limit in limits.items()
        }
        self._session_ready = session_ready
        self._heartbeat_seconds = max(1.0, heartbeat_seconds)
        self._lock = threading.RLock()
        self._active: dict[tuple[str, str], Future[Any]] = {}
        self._pending: dict[tuple[str, str], PendingJob] = {}
        self._closed = False

    def submit(
        self,
        kind: str,
        job_id: str,
        task: Callable[[], Any],
        *,
        heartbeat: Callable[[], Any] | None = None,
        requires_session: bool = True,
    ) -> bool:
        key = (kind, str(job_id))
        job = PendingJob(kind, str(job_id), task, heartbeat, requires_session)
        with self._lock:
            if self._closed or key in self._active or key in self._pending:
                return False
            if requires_session and not self._session_ready():
                self._pending[key] = job
                log_event("app", "job.waiting_for_session", job_type=kind, job_id=job_id)
                return True
            self._start_locked(job)
        return True

    def _start_locked(self, job: PendingJob) -> None:
        key = (job.kind, job.job_id)
        executor = self._executors.get(job.kind)
        if executor is None:
            raise KeyError(f"Unknown job kind: {job.kind}")
        future = executor.submit(self._run, job)
        self._active[key] = future
        future.add_done_callback(lambda completed, active_key=key: self._finished(active_key, completed))
        if job.heartbeat:
            threading.Thread(
                target=self._heartbeat_loop,
                args=(key, future, job.heartbeat),
                name=f"job-heartbeat-{job.kind}",
                daemon=True,
            ).start()

    def _run(self, job: PendingJob) -> Any:
        log_event("app", "job.started", job_type=job.kind, job_id=job.job_id)
        started = time.perf_counter()
        try:
            return job.task()
        except Exception:
            log_exception("app", "job.failed", job_type=job.kind, job_id=job.job_id)
            raise
        finally:
            log_event(
                "app",
                "job.finished",
                job_type=job.kind,
                job_id=job.job_id,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )

    def _heartbeat_loop(
        self,
        key: tuple[str, str],
        future: Future[Any],
        heartbeat: Callable[[], Any],
    ) -> None:
        while not future.done():
            if future.done():
                return
            try:
                heartbeat()
            except Exception:
                log_exception("app", "job.heartbeat_failed", job_type=key[0], job_id=key[1])
            if not future.done():
                time.sleep(self._heartbeat_seconds)

    def _finished(self, key: tuple[str, str], future: Future[Any]) -> None:
        with self._lock:
            self._active.pop(key, None)
        try:
            future.result()
        except Exception:
            pass

    def notify_session_ready(self) -> int:
        if not self._session_ready():
            return 0
        with self._lock:
            jobs = list(self._pending.values())
            self._pending.clear()
            for job in jobs:
                self._start_locked(job)
        return len(jobs)

    def cancel_pending(self, kind: str, job_id: str) -> bool:
        with self._lock:
            return self._pending.pop((kind, str(job_id)), None) is not None

    def telemetry(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": [{"kind": kind, "job_id": job_id} for kind, job_id in self._active],
                "waiting_for_session": [{"kind": kind, "job_id": job_id} for kind, job_id in self._pending],
            }

    def shutdown(self, *, wait: bool = False) -> None:
        with self._lock:
            self._closed = True
            self._pending.clear()
        for executor in self._executors.values():
            executor.shutdown(wait=wait, cancel_futures=not wait)
