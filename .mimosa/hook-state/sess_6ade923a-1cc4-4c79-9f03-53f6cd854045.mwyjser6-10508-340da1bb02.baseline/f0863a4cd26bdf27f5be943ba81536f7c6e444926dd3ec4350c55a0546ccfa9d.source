from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any


class CancellationRegistry:
    """Thread-safe registry for cancellation tokens owned by active jobs."""

    def __init__(self) -> None:
        self._events: dict[tuple[str, str], threading.Event] = {}
        self._lock = threading.Lock()

    def register(self, kind: str, operation_id: str) -> threading.Event:
        token = threading.Event()
        with self._lock:
            self._events[(kind, operation_id)] = token
        return token

    def get(self, kind: str, operation_id: str) -> threading.Event | None:
        with self._lock:
            return self._events.get((kind, operation_id))

    def cancel(self, kind: str, operation_id: str) -> bool:
        token = self.get(kind, operation_id)
        if token is None:
            return False
        token.set()
        return True

    def remove(self, kind: str, operation_id: str) -> None:
        with self._lock:
            self._events.pop((kind, operation_id), None)

    def cancel_all(self) -> None:
        with self._lock:
            tokens = list(self._events.values())
            self._events.clear()
        for token in tokens:
            token.set()


class OperationRunner:
    """Lifecycle owner for named in-process executors and cancellation tokens."""

    def __init__(self, worker_limits: dict[str, int]) -> None:
        self._worker_limits = dict(worker_limits)
        self._executors: dict[str, ThreadPoolExecutor] = {}
        self._futures: set[Future[Any]] = set()
        self._lock = threading.Lock()
        self.cancellations = CancellationRegistry()
        self._closed = False

    def start(self) -> None:
        with self._lock:
            self._closed = False

    def submit(self, queue: str, function: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        with self._lock:
            if self._closed:
                self._closed = False
            executor = self._executors.get(queue)
            if executor is None:
                workers = max(1, self._worker_limits.get(queue, 1))
                executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix=queue)
                self._executors[queue] = executor
            future = executor.submit(function, *args, **kwargs)
            self._futures.add(future)
        future.add_done_callback(self._forget)
        return future

    def _forget(self, future: Future[Any]) -> None:
        with self._lock:
            self._futures.discard(future)

    def active_count(self) -> int:
        with self._lock:
            return sum(not future.done() for future in self._futures)

    def shutdown(self, *, wait: bool = False) -> None:
        self.cancellations.cancel_all()
        with self._lock:
            executors = list(self._executors.values())
            self._executors.clear()
            self._closed = True
        for executor in executors:
            executor.shutdown(wait=wait, cancel_futures=True)
