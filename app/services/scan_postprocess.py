from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

import psycopg
import requests
from fastapi import HTTPException

from .. import db
from ..api.schemas import ASSET_CARD_MAX_DEPTH
from ..core import get_settings
from ..diagnostics import log_event, new_trace_id, redact
from ..mpvm.common import as_dict
from ..mpvm.docker_vulnerabilities import docker_dynamic_group_from_options
from ..mpvm.scan_results import (
    normalize_scanned_asset_record,
    scanned_asset_record_is_current,
    successful_scan_target_jobs,
)
from ..mpvm_client import (
    DOCKER_VULNERABILITY_PDQL,
    AuthConfig,
    MpVmApiError,
    has_success_status,
    is_finished,
    is_host_discovery_profile,
)
from .main_host import host

# Defaults are bound when the function is defined, so they cannot come from the
# lazily resolved app.main; they are derived from the same cached settings.
_DEFAULT_DOCKER_GROUP_ITERATIONS = min(10, get_settings().docker_dynamic_group_iterations)
_DEFAULT_DOCKER_GROUP_SETTLE_SECONDS = min(300, get_settings().docker_dynamic_group_settle_seconds)
_DEFAULT_DOCKER_GROUP_TIMEOUT_SECONDS = min(900, get_settings().docker_dynamic_group_timeout_seconds)
_DEFAULT_DOCKER_GROUP_POLL_SECONDS = min(60, get_settings().docker_dynamic_group_poll_seconds)


if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient


SCAN_LOG = logging.getLogger("uvicorn.error")


class ScanPostprocessCancelled(RuntimeError):
    pass


def scan_log(level: int, event: str, **fields: Any) -> None:
    log_event("app", event, level=level, component="scan-postprocess", **fields)
    payload = {"event": event, **{key: value for key, value in fields.items() if value is not None}}
    SCAN_LOG.log(level, "[scan-postprocess] %s", json.dumps(redact(payload), ensure_ascii=False, default=str))


SCAN_POSTPROCESS_FUTURES: dict[str, Future[Any]] = {}


SCAN_POSTPROCESS_FUTURES_LOCK = threading.Lock()


SCAN_POSTPROCESS_CANCEL_EVENTS: dict[str, threading.Event] = {}


_SCAN_REMOVAL_BATCH_SIZE = 20


_SCAN_REMOVAL_BATCHERS: dict[str, _ScanRemovalBatcher] = {}


def cancel_scan_postprocess_run(run_id: str) -> dict[str, Any]:
    run = db.request_scan_postprocess_cancel(run_id)
    if not run:
        current = db.get_scan_postprocess_run(run_id)
        if current:
            return current
        raise HTTPException(status_code=404, detail="Scan post-processing run not found.")

    with SCAN_POSTPROCESS_FUTURES_LOCK:
        SCAN_POSTPROCESS_CANCEL_EVENTS.setdefault(run_id, threading.Event()).set()

    # Stop both the remote scan and a currently running local card build. The
    # worker also observes the durable flag, so this remains safe across races
    # and application restarts.
    try:
        client, token = host.require_mpvm()
        client.stop_scanner_task_best_effort(token, str(run["mp_task_id"]))
    except (HTTPException, MpVmApiError, requests.RequestException):
        scan_log(logging.WARNING, "cancel_remote_stop_deferred", postprocess_run_id=run_id)
    for item in db.list_scan_postprocess_items(run_id):
        build_job_id = str(item.get("build_job_id") or "").strip()
        if build_job_id:
            build_job = db.get_asset_card_build_job(build_job_id)
            if build_job and build_job.get("status") in {"queued", "running", "cancelling"}:
                host.cancel_asset_card_build_job(build_job_id)
    return db.get_scan_postprocess_run(run_id) or run


def schedule_scan_postprocess(run_id: str, auth: AuthConfig, token: str) -> None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        current = SCAN_POSTPROCESS_FUTURES.get(run_id)
        if current and not current.done():
            scan_log(logging.DEBUG, "schedule_skipped_already_running", postprocess_run_id=run_id)
            return
        SCAN_POSTPROCESS_CANCEL_EVENTS.setdefault(run_id, threading.Event())
        future = host.CONTAINER.operation_runner.submit(
            "scan-postprocess",
            run_scan_postprocess,
            run_id=run_id,
            auth=auth,
            token=token,
        )
        SCAN_POSTPROCESS_FUTURES[run_id] = future
        scan_log(logging.INFO, "scheduled", postprocess_run_id=run_id, api_url=auth.api_url)

    def forget(_future: Future[Any]) -> None:
        with SCAN_POSTPROCESS_FUTURES_LOCK:
            if SCAN_POSTPROCESS_FUTURES.get(run_id) is _future:
                SCAN_POSTPROCESS_FUTURES.pop(run_id, None)
            SCAN_POSTPROCESS_CANCEL_EVENTS.pop(run_id, None)

    future.add_done_callback(forget)


def resume_scan_postprocess_runs(*, strict: bool = False) -> None:
    if not host.SESSION.client or not host.SESSION.access_token:
        scan_log(logging.DEBUG, "resume_skipped_no_session")
        return
    try:
        refresh_cleanup_runs = db.list_pending_asset_refresh_task_cleanups()
        docker_cleanup_runs = db.list_pending_docker_group_cleanups()
        runs = db.list_resumable_scan_postprocess_runs()
    except psycopg.Error:
        if strict:
            raise
        SCAN_LOG.exception("[scan-postprocess] failed to list resumable runs")
        return
    scan_log(logging.INFO, "refresh_task_cleanup_resume", pending_count=len(refresh_cleanup_runs))
    for cleanup_run in refresh_cleanup_runs:
        cleanup_auto_created_refresh_task(
            client=host.SESSION.client,
            token=host.SESSION.access_token,
            run_id=str(cleanup_run["run_id"]),
            task_id=str(cleanup_run["mp_task_id"]),
        )
    scan_log(logging.INFO, "docker_group_cleanup_resume", pending_count=len(docker_cleanup_runs))
    for cleanup_run in docker_cleanup_runs:
        host.schedule_scan_docker_group_cleanup(
            run_id=str(cleanup_run["run_id"]),
            auth=host.SESSION.client.auth,
            token=host.SESSION.access_token,
            options=cleanup_run.get("options"),
        )
    scan_log(logging.INFO, "resume_scan", resumable_count=len(runs))
    for run in runs:
        host.schedule_scan_postprocess(str(run["run_id"]), host.SESSION.client.auth, host.SESSION.access_token)


def run_scan_postprocess(*, run_id: str, auth: AuthConfig, token: str) -> None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        SCAN_POSTPROCESS_CANCEL_EVENTS.setdefault(run_id, threading.Event())
    worker_id = str(uuid.uuid4())
    claimed = db.claim_scan_postprocess_run(run_id, worker_id)
    if not claimed:
        scan_log(logging.INFO, "claim_skipped", postprocess_run_id=run_id, worker_id=worker_id)
        return
    client = host.MpVmClient(auth)
    task_id = str(claimed["mp_task_id"])
    options = as_dict(claimed.get("options"))
    started_from = str(claimed["started_from"])
    timeout_seconds = max(1.0, float(options.get("task_timeout_minutes") or 120) * 60)
    poll_seconds = max(1.0, float(options.get("task_poll_seconds") or 15))
    require_clean_jobs = bool(options.get("require_clean_jobs"))
    scan_finished_at: str | None = None
    scan_log(
        logging.INFO,
        "run_started",
        postprocess_run_id=run_id,
        task_id=task_id,
        worker_id=worker_id,
        started_from=started_from,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        require_clean_jobs=require_clean_jobs,
    )
    try:
        if claimed.get("cancel_requested"):
            raise ScanPostprocessCancelled("Scan post-processing was cancelled.")
        raise_if_scan_postprocess_cancelled(run_id)
        monitoring = monitor_successful_scan_jobs(
            client=client,
            auth=auth,
            token=token,
            task_id=task_id,
            started_from=started_from,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
            postprocess_run_id=run_id,
            require_clean_jobs=require_clean_jobs,
            docker_group_options=options,
        )
        scan_finished_at = str(monitoring.get("scan_finished_at") or "") or None
        if not monitoring["successful_job_count"]:
            scan_log(
                logging.ERROR,
                "no_successful_jobs",
                postprocess_run_id=run_id,
                task_id=task_id,
                total_job_count=monitoring["total_job_count"],
            )
            db.update_scan_task_status(
                task_id,
                "postprocess_completed_with_errors",
                {"postprocess_run_id": run_id, "reason": "no successful targets"},
            )
            cleanup_deleted = (
                cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
                if options.get("auto_created_refresh_task")
                else None
            )
            cleanup_text = " Refresh task deleted." if cleanup_deleted else " Refresh task deletion is pending." if cleanup_deleted is False else ""
            host.schedule_scan_docker_group_cleanup(
                run_id=run_id,
                auth=auth,
                token=token,
                options=options,
                scan_finished_at=scan_finished_at,
            )
            db.finish_scan_postprocess_run(
                run_id,
                status="completed_with_errors",
                stage="completed_with_errors",
                message=f"The scanner run has no jobs with errorStatus=success.{cleanup_text}",
            )
            return

        summary = db.refresh_scan_postprocess_counts(run_id) or {}
        failed_count = int(summary.get("failed_count") or 0)
        completed_count = int(summary.get("completed_count") or 0)
        if completed_count and scan_finished_at:
            db.record_completed_scan_evidence(
                run_id,
                mp_task_id=task_id,
                scanned_at=scan_finished_at,
            )
        refresh_result = finalize_asset_card_refresh(run_id, options) if completed_count else None
        final_status = "completed_with_errors" if failed_count else "completed"
        message = f"Completed {completed_count} asset(s); failures: {failed_count}."
        if refresh_result:
            message += f" Asset card refreshed as {refresh_result['asset_id']}."
        db.update_scan_task_status(
            task_id,
            "postprocess_completed_with_errors" if failed_count else "postprocess_completed",
            {"postprocess_run_id": run_id, "completed_count": completed_count, "failed_count": failed_count},
        )
        if options.get("auto_created_refresh_task"):
            cleanup_deleted = cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
            if cleanup_deleted:
                message += " Refresh task deleted."
            else:
                message += " Refresh task deletion is pending."
                if final_status == "completed":
                    final_status = "completed_with_errors"
        host.schedule_scan_docker_group_cleanup(
            run_id=run_id,
            auth=auth,
            token=token,
            options=options,
            scan_finished_at=scan_finished_at,
        )
        db.finish_scan_postprocess_run(run_id, status=final_status, stage=final_status, message=message)
        if completed_count:
            host.capture_vulnerability_snapshot("scan_postprocess", run_id)
        scan_log(
            logging.INFO if final_status == "completed" else logging.ERROR,
            "run_finished",
            postprocess_run_id=run_id,
            task_id=task_id,
            status=final_status,
            completed_count=completed_count,
            failed_count=failed_count,
        )
    except ScanPostprocessCancelled:
        client.stop_scanner_task_best_effort(token, task_id)
        cleanup_deleted = (
            cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
            if options.get("auto_created_refresh_task")
            else None
        )
        cleanup_text = (
            " Refresh task deleted."
            if cleanup_deleted
            else " Refresh task deletion is pending."
            if cleanup_deleted is False
            else ""
        )
        db.update_scan_task_status(task_id, "postprocess_cancelled", {"postprocess_run_id": run_id})
        host.schedule_scan_docker_group_cleanup(
            run_id=run_id,
            auth=auth,
            token=token,
            options=options,
            scan_finished_at=scan_finished_at or db.now_utc(),
        )
        db.finish_scan_postprocess_run(
            run_id,
            status="cancelled",
            stage="cancelled",
            message=f"Scan post-processing cancelled.{cleanup_text}",
        )
        scan_log(logging.INFO, "run_cancelled", postprocess_run_id=run_id, task_id=task_id)
    except Exception as exc:
        error = str(exc)[:4000]
        SCAN_LOG.exception(
            "[scan-postprocess] unhandled failure postprocess_run_id=%s task_id=%s error_type=%s error=%s",
            run_id,
            task_id,
            type(exc).__name__,
            error,
        )
        try:
            partial_items = db.list_scan_postprocess_items(run_id)
        except Exception:
            partial_items = []
        final_status = "completed_with_errors" if partial_items else "failed"
        task_status = "postprocess_completed_with_errors" if partial_items else "postprocess_failed"
        db.update_scan_task_status(task_id, task_status, {"postprocess_run_id": run_id, "error": error})
        cleanup_deleted = (
            cleanup_auto_created_refresh_task(client=client, token=token, run_id=run_id, task_id=task_id)
            if options.get("auto_created_refresh_task")
            else None
        )
        cleanup_text = " Refresh task deleted." if cleanup_deleted else " Refresh task deletion is pending." if cleanup_deleted is False else ""
        host.schedule_scan_docker_group_cleanup(
            run_id=run_id,
            auth=auth,
            token=token,
            options=options,
            scan_finished_at=scan_finished_at or db.now_utc(),
        )
        db.finish_scan_postprocess_run(
            run_id,
            status=final_status,
            stage=final_status,
            message=(
                f"Scan post-processing completed with individual errors.{cleanup_text}"
                if partial_items
                else f"Scan post-processing failed before any result was saved.{cleanup_text}"
            ),
            error=error,
        )
    finally:
        cleanup_finished_task_prechecks(client=client, token=token, task_id=task_id)
        client.session.close()
        with SCAN_POSTPROCESS_FUTURES_LOCK:
            SCAN_POSTPROCESS_CANCEL_EVENTS.pop(run_id, None)
            removal_batcher = _SCAN_REMOVAL_BATCHERS.pop(run_id, None)
        if removal_batcher is not None:
            removal_batcher.shutdown()


def cleanup_finished_task_prechecks(*, client: MpVmClient, token: str, task_id: str) -> None:
    """The precheck tasks of a finished audit task are no longer needed in MP VM."""
    from .scanner_task_launch import cleanup_precheck_tasks

    try:
        cleanup_precheck_tasks(client=client, token=token, audit_task_id=task_id)
    except Exception:  # noqa: BLE001 - never let cleanup change the outcome of the run
        SCAN_LOG.exception("[scan-postprocess] precheck cleanup failed task_id=%s", task_id)


def raise_if_scan_postprocess_cancelled(run_id: str) -> None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        cancel_event = SCAN_POSTPROCESS_CANCEL_EVENTS.get(run_id)
    if cancel_event and cancel_event.is_set():
        raise ScanPostprocessCancelled("Scan post-processing was cancelled.")


def scan_postprocess_cancel_event(run_id: str) -> threading.Event | None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        return SCAN_POSTPROCESS_CANCEL_EVENTS.get(run_id)


def scan_removal_batcher(run_id: str) -> _ScanRemovalBatcher | None:
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        return _SCAN_REMOVAL_BATCHERS.get(run_id)


class _ScanRemovalBatcher:
    """Groups card-saved assets into MP VM removal batches for one scan run.

    Asset workers call :meth:`enqueue` after the card is saved locally and
    return immediately; the item keeps its ``card_saved`` stage until the
    single per-run daemon thread reaches a terminal status for it. The
    thread fires a batch as soon as ``_SCAN_REMOVAL_BATCH_SIZE`` pending
    items have accumulated, so batches of 20 form *during* the scan
    instead of after it; ``mark_final()`` (called by the monitor only
    after every asset worker has finished) flushes the remainder, and the
    thread exits once stopped or once final with empty queues. One
    ``remove_assets`` call covers up to ``_SCAN_REMOVAL_BATCH_SIZE``
    assets and one ``wait_for_asset_removal`` stream covers the whole
    operation. Items that already carry a removal operation (restart
    recovery) are joined immediately: the batcher polls the existing
    operation and never starts a second removal for the same asset.

    Lock discipline: the condition lock guards only in-memory state
    (``_pending``, ``_joins``, flags). All HTTP calls and DB writes happen
    outside the lock.
    """

    def __init__(self, *, run_id: str, auth: Any, token: str) -> None:
        self.run_id = run_id
        self.auth = auth
        self.token = token
        self._cond = threading.Condition()
        self._pending: list[tuple[int, str]] = []
        self._joins: list[tuple[int, str, str]] = []
        self._final = False
        self._stopped = False
        self._client: MpVmClient | None = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"scan-removal-batcher-{run_id}",
            daemon=True,
        )
        self._thread.start()

    # -- worker / monitor API ---------------------------------------------

    def enqueue(
        self,
        item_id: int,
        asset_id: str,
        *,
        existing_operation_id: str | None = None,
    ) -> None:
        """Queue the item for removal and return immediately (non-blocking).

        The item keeps its ``card_saved`` stage in the database until the
        batcher thread marks it ``deleting`` and later a terminal status.
        """
        item_id = int(item_id)
        thread_alive = False
        with self._cond:
            thread_alive = self._thread.is_alive()
            if thread_alive:
                if existing_operation_id:
                    self._joins.append((item_id, str(existing_operation_id), str(asset_id)))
                else:
                    self._pending.append((item_id, str(asset_id)))
                self._cond.notify_all()
        if not thread_alive:
            # Post-shutdown race: the batcher thread already exited (e.g. a
            # late enqueue after run cleanup). Record the failure directly so
            # the item cannot dangle without a terminal status.
            self._record_item(
                item_id,
                "removal_failed",
                "Removal batcher thread exited unexpectedly.",
                None,
                asset_id,
            )

    def mark_final(self) -> None:
        """Flush the remaining queue once no more workers will enqueue."""
        with self._cond:
            self._final = True
            self._cond.notify_all()

    def shutdown(self) -> None:
        """Ask the thread to exit once its queue is drained (run cleanup)."""
        with self._cond:
            self._stopped = True
            self._final = True
            self._cond.notify_all()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    # -- internals ----------------------------------------------------------

    def _client_for_removal(self) -> MpVmClient:
        if self._client is None:
            self._client = host.MpVmClient(self.auth)
        return self._client

    def _record_item(
        self,
        item_id: int,
        status: str,
        message: str,
        operation_id: str | None,
        asset_id: str | None = None,
    ) -> None:
        values: dict[str, Any] = {
            "status": status,
            "stage": status,
            "message": message,
            "error": None if status == "completed" else message,
            "finished_at": db.now_utc(),
        }
        if operation_id:
            values["removal_operation_id"] = operation_id
        row: dict[str, Any] | None = None
        try:
            row = db.update_scan_postprocess_item(item_id, **values)
        except psycopg.Error:
            scan_log(
                logging.ERROR,
                "removal_batch_item_update_failed",
                postprocess_run_id=self.run_id,
                item_id=item_id,
                status=status,
            )
        # Per-item terminal events moved here from the asset worker: the
        # worker no longer blocks on the removal, so only the batcher knows
        # when an item reached its terminal status.
        terminal_context: dict[str, Any] = {
            "postprocess_run_id": self.run_id,
            "item_id": item_id,
            "asset_id": asset_id,
            "removal_operation_id": operation_id,
            "message": message,
        }
        if row:
            terminal_context["job_id"] = row.get("mp_job_id")
            terminal_context["target"] = row.get("target")
        if status == "completed":
            scan_log(logging.INFO, "asset_processing_completed", **terminal_context)
        elif status == "removal_failed":
            scan_log(logging.ERROR, "mpvm_removal_failed", **terminal_context)

    def _mark_deleting(self, item_id: int, operation_id: str, batch_size: int) -> None:
        try:
            db.update_scan_postprocess_item(
                item_id,
                status="deleting",
                stage="deleting_in_mpvm",
                removal_operation_id=operation_id,
                message=f"MP VM asset removal started (batch of {batch_size}).",
            )
        except psycopg.Error:
            scan_log(
                logging.ERROR,
                "removal_batch_item_update_failed",
                postprocess_run_id=self.run_id,
                item_id=item_id,
                status="deleting",
            )

    def _run(self) -> None:
        try:
            while True:
                with self._cond:
                    # Fire as soon as a full batch of _SCAN_REMOVAL_BATCH_SIZE
                    # has accumulated (the user-facing "каждые 20 хостов"
                    # cadence); joins are always processed immediately. With
                    # fewer than 20 pending items the thread keeps waiting,
                    # so a partial wave never triggers a removal on its own.
                    while (
                        len(self._pending) < _SCAN_REMOVAL_BATCH_SIZE
                        and not self._joins
                        and not self._final
                        and not self._stopped
                    ):
                        self._cond.wait(timeout=1.0)
                    # mark_final()/shutdown() only happen after every asset
                    # worker has returned (or the run is being torn down), so
                    # any work still queued here is the complete remainder:
                    # flush it, then exit once both queues are empty.
                    if (self._stopped or self._final) and not self._pending and not self._joins:
                        break
                    batch = self._pending[:_SCAN_REMOVAL_BATCH_SIZE]
                    del self._pending[:_SCAN_REMOVAL_BATCH_SIZE]
                    joins = self._joins[:]
                    self._joins.clear()
                if batch:
                    self._process_batch(batch)
                for join_item_id, join_operation_id, join_asset_id in joins:
                    self._process_join(join_item_id, join_operation_id, join_asset_id)
        finally:
            if self._client is not None:
                self._client.session.close()

    def _process_batch(self, batch: list[tuple[int, str]]) -> None:
        item_ids = [item_id for item_id, _ in batch]
        asset_ids = [asset_id for _item_id, asset_id in batch]
        cancel_event = scan_postprocess_cancel_event(self.run_id)
        if cancel_event is not None and cancel_event.is_set():
            message = "MP VM asset removal cancelled by operator."
            scan_log(
                logging.INFO,
                "removal_batch_cancelled",
                postprocess_run_id=self.run_id,
                item_ids=item_ids,
                count=len(batch),
            )
            for item_id, asset_id in batch:
                self._record_item(item_id, "cancelled", message, None, asset_id)
            return
        scan_log(
            logging.INFO,
            "removal_batch_started",
            postprocess_run_id=self.run_id,
            item_ids=item_ids,
            asset_ids=asset_ids,
            count=len(batch),
        )
        try:
            operation_id = self._client_for_removal().remove_assets(self.token, asset_ids)
        except Exception as exc:  # noqa: BLE001 - no operation id: fail the batch, keep serving
            message = f"MP VM asset removal batch failed to start: {type(exc).__name__}: {exc}"
            scan_log(
                logging.ERROR,
                "removal_batch_failed",
                postprocess_run_id=self.run_id,
                item_ids=item_ids,
                count=len(batch),
                error=message,
            )
            for item_id, asset_id in batch:
                self._record_item(item_id, "removal_failed", message, None, asset_id)
            return
        for item_id, _asset_id in batch:
            self._mark_deleting(item_id, operation_id, len(batch))
            scan_log(
                logging.INFO,
                "mpvm_removal_started",
                postprocess_run_id=self.run_id,
                item_id=item_id,
                removal_operation_id=operation_id,
            )
        try:
            ok, message, _raw = self._client_for_removal().wait_for_asset_removal(
                self.token,
                operation_id,
                timeout_seconds=host.SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS,
                poll_seconds=host.SCAN_ASSET_REMOVAL_POLL_SECONDS,
                cancel_event=cancel_event,
            )
        except Exception as exc:  # noqa: BLE001
            ok, message = False, f"Removal operation polling failed: {type(exc).__name__}: {exc}"
        if cancel_event is not None and cancel_event.is_set():
            status = "cancelled"
            message = "MP VM asset removal cancelled by operator."
        elif ok:
            status = "completed"
        else:
            status = "removal_failed"
        if status == "completed":
            scan_log(
                logging.INFO,
                "removal_batch_completed",
                postprocess_run_id=self.run_id,
                op_id=operation_id,
                item_ids=item_ids,
                count=len(batch),
            )
        else:
            scan_log(
                logging.ERROR,
                "removal_batch_failed",
                postprocess_run_id=self.run_id,
                op_id=operation_id,
                item_ids=item_ids,
                count=len(batch),
                message=message,
            )
        for item_id, asset_id in batch:
            self._record_item(item_id, status, message, operation_id, asset_id)

    def _process_join(self, item_id: int, operation_id: str, asset_id: str) -> None:
        cancel_event = scan_postprocess_cancel_event(self.run_id)
        if cancel_event is not None and cancel_event.is_set():
            self._record_item(
                item_id, "cancelled", "MP VM asset removal cancelled by operator.", operation_id, asset_id
            )
            return
        try:
            ok, message, _raw = self._client_for_removal().wait_for_asset_removal(
                self.token,
                operation_id,
                timeout_seconds=host.SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS,
                poll_seconds=host.SCAN_ASSET_REMOVAL_POLL_SECONDS,
                cancel_event=cancel_event,
            )
        except Exception as exc:  # noqa: BLE001
            ok, message = False, f"Removal operation polling failed: {type(exc).__name__}: {exc}"
        if cancel_event is not None and cancel_event.is_set():
            self._record_item(
                item_id, "cancelled", "MP VM asset removal cancelled by operator.", operation_id, asset_id
            )
        elif ok:
            self._record_item(item_id, "completed", message, operation_id, asset_id)
        else:
            self._record_item(item_id, "removal_failed", message, operation_id, asset_id)


def cleanup_auto_created_refresh_task(
    *,
    client: MpVmClient,
    token: str,
    run_id: str,
    task_id: str,
) -> bool:
    try:
        response = client.delete_scanner_task(token, task_id, mode="delete_v3")
        db.delete_scan_task(task_id)
        update_refresh_task_cleanup_message(run_id, f"Refresh task {task_id} deleted from MP VM.")
        scan_log(
            logging.INFO,
            "asset_refresh_task_deleted",
            postprocess_run_id=run_id,
            task_id=task_id,
            already_deleted=bool(response.get("alreadyDeleted")) if isinstance(response, dict) else False,
        )
        return True
    except (MpVmApiError, requests.RequestException, psycopg.Error) as exc:
        try:
            update_refresh_task_cleanup_message(run_id, f"Refresh task {task_id} deletion is pending: {exc}")
        except psycopg.Error:
            SCAN_LOG.exception(
                "[scan-postprocess] failed to persist refresh task cleanup error postprocess_run_id=%s task_id=%s",
                run_id,
                task_id,
            )
        SCAN_LOG.exception(
            "[scan-postprocess] refresh task cleanup failed postprocess_run_id=%s task_id=%s",
            run_id,
            task_id,
        )
        return False


def update_refresh_task_cleanup_message(run_id: str, cleanup_message: str) -> None:
    run = db.get_scan_postprocess_run(run_id)
    if not run:
        return
    base_message = str(run.get("message") or "").split(" Refresh task cleanup:", 1)[0].strip()
    prefix = f"{base_message} " if base_message else ""
    db.update_scan_postprocess_run(run_id, message=f"{prefix}Refresh task cleanup: {cleanup_message}"[:4000])


def finalize_asset_card_refresh(run_id: str, options: dict[str, Any]) -> dict[str, Any] | None:
    source_asset_id = str(options.get("refresh_asset_id") or "").strip()
    if not source_asset_id:
        return None
    completed_ids = sorted(
        {
            str(item.get("asset_id"))
            for item in db.list_scan_postprocess_items(run_id)
            if item.get("status") == "completed" and item.get("asset_id") and db.asset_card_exists(str(item["asset_id"]))
        }
    )
    if source_asset_id in completed_ids:
        refreshed_asset_id = source_asset_id
    elif len(completed_ids) == 1:
        refreshed_asset_id = completed_ids[0]
    else:
        scan_log(
            logging.WARNING,
            "asset_refresh_replacement_skipped",
            postprocess_run_id=run_id,
            refresh_asset_id=source_asset_id,
            completed_asset_ids=completed_ids,
            reason="no_completed_card" if not completed_ids else "ambiguous_completed_cards",
        )
        return None
    if refreshed_asset_id != source_asset_id:
        db.delete_asset_card(source_asset_id)
    scan_log(
        logging.INFO,
        "asset_refresh_replaced",
        postprocess_run_id=run_id,
        previous_asset_id=source_asset_id,
        asset_id=refreshed_asset_id,
    )
    return {"previous_asset_id": source_asset_id, "asset_id": refreshed_asset_id}


def monitor_successful_scan_jobs(
    *,
    client: MpVmClient,
    auth: AuthConfig,
    token: str,
    task_id: str,
    started_from: str,
    timeout_seconds: float,
    poll_seconds: float,
    postprocess_run_id: str,
    require_clean_jobs: bool,
    docker_group_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    monitor_started = time.perf_counter()
    scan_deadline = time.monotonic() + timeout_seconds
    resolution_deadline: float | None = None
    latest_run: dict[str, Any] | None = None
    latest_jobs: list[dict[str, Any]] = []
    successful_jobs: list[dict[str, Any]] = []
    pending_targets: dict[str, str | None] = {}
    target_errors: dict[str, str] = {}
    existing_items = db.list_scan_postprocess_items(postprocess_run_id)
    seen_asset_ids = {str(item["asset_id"]) for item in existing_items if item.get("asset_id")}
    resolved_job_targets = {
        (str(item.get("mp_job_id") or ""), str(item.get("target") or ""))
        for item in existing_items
        if item.get("asset_id")
    }
    asset_futures: set[Future[Any]] = set()
    last_job_states: dict[str, str] = {}
    last_summary: tuple[int, int, int] | None = None
    last_persisted_progress: tuple[Any, ...] | None = None
    logged_mp_run_id: str | None = None
    logged_waiting_for_run = False
    scan_finished_at: str | None = None
    resolution_request_count = 0
    resolution_error_count = 0
    resolution_peak_active = 0
    resolution_active = 0
    resolution_lock = threading.Lock()
    resolution_queue_wait_ms = 0.0
    worker_state = threading.local()
    resolution_clients: list[MpVmClient] = []

    # Per-run removal batcher: one remove_assets call per up-to-20 card-saved
    # assets and one operation poll stream per batch. Registered before any
    # asset worker is submitted so every worker can enqueue into it.
    removal_batcher = _ScanRemovalBatcher(run_id=postprocess_run_id, auth=auth, token=token)
    with SCAN_POSTPROCESS_FUTURES_LOCK:
        _SCAN_REMOVAL_BATCHERS[postprocess_run_id] = removal_batcher

    def resolution_client() -> MpVmClient:
        nonlocal client
        worker_client = getattr(worker_state, "client", None)
        if worker_client is None:
            # Unit-test callers sometimes use a lightweight auth stub. Production
            # always supplies AuthConfig and receives one isolated Session per worker.
            worker_client = host.MpVmClient(auth) if isinstance(auth, AuthConfig) else client
            worker_state.client = worker_client
            if worker_client is not client:
                with resolution_lock:
                    resolution_clients.append(worker_client)
        return worker_client

    def resolve_target(target: str, job_id: str | None, run_started_at: str) -> tuple[str, str | None, list[dict[str, Any]], str]:
        nonlocal resolution_active, resolution_error_count, resolution_peak_active
        nonlocal resolution_queue_wait_ms, resolution_request_count
        queued_at = time.perf_counter()
        try:
            with host.BACKGROUND_REQUEST_SEMAPHORE:
                started = time.perf_counter()
                with resolution_lock:
                    resolution_queue_wait_ms += (started - queued_at) * 1000
                    resolution_request_count += 1
                    resolution_active += 1
                    resolution_peak_active = max(resolution_peak_active, resolution_active)
                try:
                    assets, error = resolve_scanned_target_once(
                        client=resolution_client(),
                        token=token,
                        target=target,
                        mp_job_id=job_id,
                        run_started_at=run_started_at,
                    )
                    return target, job_id, assets, error
                finally:
                    with resolution_lock:
                        resolution_active -= 1
        except (MpVmApiError, requests.RequestException, ValueError) as exc:
            with resolution_lock:
                resolution_error_count += 1
            return target, job_id, [], f"{type(exc).__name__}: {exc}"

    def drain_asset_batch() -> None:
        batch = tuple(asset_futures)
        for future in batch:
            future.result()
        asset_futures.difference_update(batch)

    def submit_asset(
        executor: ThreadPoolExecutor,
        item: dict[str, Any],
    ) -> None:
        # Scanner-task assets are built in discrete waves. Do not queue the next
        # wave until every card in the current group has reached a terminal
        # state; this keeps task processing predictable and bounds DB/MP VM load.
        if len(asset_futures) >= host.SCAN_ASSET_PROCESS_WORKERS:
            drain_asset_batch()
        asset_futures.add(
            executor.submit(
                process_scanned_asset_item_with_progress,
                item=item,
                auth=auth,
                token=token,
                postprocess_run_id=postprocess_run_id,
            )
        )

    with ThreadPoolExecutor(
        max_workers=host.SCAN_ASSET_PROCESS_WORKERS,
        thread_name_prefix="scan-asset-process",
    ) as asset_executor, ThreadPoolExecutor(
        max_workers=host.SCAN_TARGET_RESOLUTION_WORKERS,
        thread_name_prefix="scan-target-resolution",
    ) as resolution_executor:
        for item in existing_items:
            if item.get("asset_id") and item.get("status") not in {
                "completed", "resolution_failed", "build_failed", "removal_failed",
            }:
                submit_asset(asset_executor, item)
                scan_log(
                    logging.INFO,
                    "item_resumed",
                    postprocess_run_id=postprocess_run_id,
                    item_id=item.get("id"),
                    job_id=item.get("mp_job_id"),
                    target=item.get("target"),
                    asset_id=item.get("asset_id"),
                    status=item.get("status"),
                )

        while True:
            raise_if_scan_postprocess_cancelled(postprocess_run_id)
            with host.BACKGROUND_REQUEST_SEMAPHORE:
                runs = client.get_task_runs(token, task_id, time_from=started_from)
            if not runs and not logged_waiting_for_run:
                logged_waiting_for_run = True
                scan_log(
                    logging.INFO,
                    "waiting_for_mp_run",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    started_from=started_from,
                )
            if runs:
                latest_run = runs[0]
                mp_run_id = str(latest_run.get("id") or "")
                if mp_run_id:
                    if logged_mp_run_id != mp_run_id:
                        logged_mp_run_id = mp_run_id
                        scan_log(
                            logging.INFO,
                            "mp_run_found",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            run_status=latest_run.get("status"),
                            run_error_status=latest_run.get("errorStatus"),
                            run_started_at=latest_run.get("startedAt"),
                        )
                    with host.BACKGROUND_REQUEST_SEMAPHORE:
                        latest_jobs, successful_jobs = client.split_successful_run_jobs(
                            token,
                            mp_run_id,
                            require_clean_jobs=require_clean_jobs,
                        )
                    successful_ids = {str(job.get("id") or "") for job in successful_jobs}
                    for job in latest_jobs:
                        job_id = str(job.get("id") or "")
                        profile = as_dict(job.get("profile"))
                        profile_name = profile.get("name") if isinstance(profile, dict) else None
                        state = json.dumps(
                            {
                                "status": job.get("status"),
                                "errorStatus": job.get("errorStatus"),
                                "runMode": job.get("runMode"),
                                "profile": profile_name,
                                "targets": job.get("targets"),
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                            default=str,
                        )
                        if last_job_states.get(job_id) == state:
                            continue
                        last_job_states[job_id] = state
                        run_mode = re.sub(r"[^a-z0-9]+", "", str(job.get("runMode") or "").casefold())
                        if "connectioncheck" in run_mode:
                            decision = "ignored_connection_check"
                        elif is_host_discovery_profile(job.get("profile")):
                            decision = "ignored_host_discovery_profile"
                        elif job_id in successful_ids:
                            decision = "ready_for_asset_processing"
                        elif job.get("errorStatus") is None:
                            decision = "waiting_error_status"
                        elif not has_success_status(job.get("errorStatus")):
                            decision = "ignored_non_success_error_status"
                        else:
                            decision = "ignored_require_clean_jobs"
                        scan_log(
                            logging.INFO,
                            "job_state_changed",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            job_id=job_id,
                            decision=decision,
                            status=job.get("status"),
                            error_status=job.get("errorStatus"),
                            run_mode=job.get("runMode"),
                            profile_name=profile_name,
                            targets=job.get("targets"),
                        )
                    summary_key = (len(latest_jobs), len(successful_jobs), len(seen_asset_ids))
                    if summary_key != last_summary:
                        last_summary = summary_key
                        scan_log(
                            logging.INFO,
                            "jobs_summary",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            total_job_count=len(latest_jobs),
                            successful_job_count=len(successful_jobs),
                            resolved_asset_count=len(seen_asset_ids),
                        )
                    for target, target_job_id in successful_scan_target_jobs(successful_jobs).items():
                        if (str(target_job_id or ""), target) not in resolved_job_targets:
                            pending_targets[target] = target_job_id

                    run_started_at = str(latest_run.get("startedAt") or started_from)
                    resolution_results: list[tuple[str, str | None, list[dict[str, Any]], str]] = []
                    target_items = list(pending_targets.items())
                    for offset in range(0, len(target_items), host.SCAN_TARGET_RESOLUTION_WORKERS):
                        window = target_items[offset:offset + host.SCAN_TARGET_RESOLUTION_WORKERS]
                        window_futures = [
                            resolution_executor.submit(resolve_target, target, job_id, run_started_at)
                            for target, job_id in window
                        ]
                        resolution_results.extend(future.result() for future in window_futures)

                    for target, resolved_job_id, assets, error in resolution_results:
                        if not assets:
                            target_errors[target] = error
                            scan_log(
                                logging.WARNING,
                                "asset_not_resolved_yet",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=resolved_job_id,
                                target=target,
                                error=error,
                            )
                            continue
                        target_scheduled = False
                        for asset in assets:
                            asset_id = str(asset["asset_id"])
                            if asset_id in seen_asset_ids:
                                target_scheduled = True
                                continue
                            try:
                                item = db.upsert_scan_postprocess_item(
                                    postprocess_run_id,
                                    item_key=f"asset:{asset_id}",
                                    mp_job_id=asset.get("mp_job_id"),
                                    target=asset.get("target"),
                                    asset_id=asset_id,
                                    display_name=asset.get("display_name"),
                                    status="queued",
                                    stage="queued",
                                )
                            except Exception as exc:
                                error = f"{type(exc).__name__}: {exc}"
                                target_errors[target] = error
                                SCAN_LOG.exception(
                                    "[scan-postprocess] asset queue persistence failed "
                                    "postprocess_run_id=%s task_id=%s mp_run_id=%s job_id=%s target=%s asset_id=%s "
                                    "error_type=%s error=%s",
                                    postprocess_run_id,
                                    task_id,
                                    mp_run_id,
                                    resolved_job_id,
                                    target,
                                    asset_id,
                                    type(exc).__name__,
                                    str(exc),
                                )
                                continue
                            seen_asset_ids.add(asset_id)
                            target_scheduled = True
                            scan_log(
                                logging.INFO,
                                "asset_queued",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=resolved_job_id,
                                target=target,
                                asset_id=asset_id,
                                item_id=item.get("id"),
                            )
                            submit_asset(asset_executor, item)
                        if not target_scheduled:
                            scan_log(
                                logging.WARNING,
                                "asset_queue_retry_pending",
                                postprocess_run_id=postprocess_run_id,
                                task_id=task_id,
                                mp_run_id=mp_run_id,
                                job_id=resolved_job_id,
                                target=target,
                                resolved_asset_ids=[str(asset.get("asset_id")) for asset in assets],
                                error=target_errors.get(target),
                            )
                            continue
                        resolved_job_targets.add((str(resolved_job_id or ""), target))
                        pending_targets.pop(target, None)
                        target_errors.pop(target, None)

                    terminal = is_finished(latest_run)
                    if terminal and scan_finished_at is None:
                        scan_finished_at = str(latest_run.get("finishedAt") or db.now_utc())
                        if docker_dynamic_group_from_options(docker_group_options):
                            host.remember_docker_scan_finished_at(postprocess_run_id, scan_finished_at, confirmed=True)
                        scan_log(
                            logging.INFO,
                            "mp_run_finished",
                            postprocess_run_id=postprocess_run_id,
                            task_id=task_id,
                            mp_run_id=mp_run_id,
                            scan_finished_at=scan_finished_at,
                        )
                    if terminal and resolution_deadline is None:
                        resolution_deadline = time.monotonic() + host.SCAN_ASSET_RESOLUTION_TIMEOUT_SECONDS
                    progress = (
                        mp_run_id, run_started_at, bool(seen_asset_ids), len(latest_jobs),
                        len(successful_jobs), len(successful_scan_target_jobs(successful_jobs)), len(seen_asset_ids),
                    )
                    if progress != last_persisted_progress:
                        last_persisted_progress = progress
                        db.update_scan_postprocess_run(
                            postprocess_run_id,
                            mp_run_id=mp_run_id,
                            run_started_at=run_started_at,
                            status="processing" if seen_asset_ids else "monitoring",
                            stage="building_cards" if seen_asset_ids else "watching_jobs",
                            total_job_count=len(latest_jobs),
                            successful_job_count=len(successful_jobs),
                            target_count=len(successful_scan_target_jobs(successful_jobs)),
                            asset_count=len(seen_asset_ids),
                            message=(
                                f"Processing {len(seen_asset_ids)} asset(s); watching errorStatus for {len(latest_jobs)} job(s)."
                            ),
                        )

            now = time.monotonic()
            scan_timed_out = now >= scan_deadline
            resolution_finished = resolution_deadline is not None and (not pending_targets or now >= resolution_deadline)
            if resolution_finished or (scan_timed_out and latest_run is None):
                scan_log(
                    logging.INFO,
                    "monitoring_loop_finished",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    scan_timed_out=scan_timed_out,
                    pending_target_count=len(pending_targets),
                    scheduled_asset_count=len(seen_asset_ids),
                )
                break
            if scan_timed_out and latest_run is not None and resolution_deadline is None:
                client.stop_scanner_task_best_effort(token, task_id)
                scan_log(
                    logging.WARNING,
                    "scan_timeout_stop_requested",
                    postprocess_run_id=postprocess_run_id,
                    task_id=task_id,
                    timeout_seconds=timeout_seconds,
                )
                resolution_deadline = now + host.SCAN_ASSET_RESOLUTION_TIMEOUT_SECONDS
            sleep_seconds = min(poll_seconds, host.SCAN_ASSET_RESOLUTION_POLL_SECONDS)
            cancel_event = scan_postprocess_cancel_event(postprocess_run_id)
            if cancel_event:
                if cancel_event.wait(sleep_seconds):
                    raise ScanPostprocessCancelled("Scan post-processing was cancelled.")
            else:
                time.sleep(sleep_seconds)

        for target, pending_job_id in pending_targets.items():
            item = db.upsert_scan_postprocess_item(
                postprocess_run_id,
                item_key=f"target:{target}",
                mp_job_id=pending_job_id,
                target=target,
                asset_id=None,
                display_name=None,
                status="resolution_failed",
                stage="resolution_failed",
            )
            db.update_scan_postprocess_item(
                int(item["id"]),
                status="resolution_failed",
                stage="resolution_failed",
                error=target_errors.get(target, "Asset resolution timed out."),
                finished_at=db.now_utc(),
            )
            scan_log(
                logging.ERROR,
                "asset_resolution_failed",
                postprocess_run_id=postprocess_run_id,
                task_id=task_id,
                job_id=pending_job_id,
                target=target,
                error=target_errors.get(target, "Asset resolution timed out."),
            )
        drain_asset_batch()
        # Every asset worker has returned, so every removal has already been
        # enqueued (enqueueing is non-blocking): flush the batcher's
        # remainder and wait for it to drain.
        removal_batcher.mark_final()
        removal_batcher.join(timeout=host.SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS)
        if removal_batcher.is_alive():
            scan_log(
                logging.WARNING,
                "removal_batcher_join_timeout",
                postprocess_run_id=postprocess_run_id,
                timeout_seconds=host.SCAN_ASSET_REMOVAL_TIMEOUT_SECONDS,
            )
        with SCAN_POSTPROCESS_FUTURES_LOCK:
            if _SCAN_REMOVAL_BATCHERS.get(postprocess_run_id) is removal_batcher:
                _SCAN_REMOVAL_BATCHERS.pop(postprocess_run_id, None)

    resolution_http = {"requests": 0, "retries": 0, "errors": 0, "rate_limited": 0}
    for resolution_worker_client in resolution_clients:
        snapshot = resolution_worker_client.session.telemetry()
        for key in resolution_http:
            resolution_http[key] += int(snapshot.get(key) or 0)
        resolution_worker_client.session.close()

    if latest_run is None:
        raise RuntimeError(f"Scanner run was not found before timeout ({timeout_seconds / 60:.1f} minutes).")
    if scan_finished_at is None:
        scan_finished_at = db.now_utc()
        if docker_dynamic_group_from_options(docker_group_options):
            host.remember_docker_scan_finished_at(postprocess_run_id, scan_finished_at, confirmed=False)
    return {
        "total_job_count": len(latest_jobs),
        "successful_job_count": len(successful_jobs),
        "asset_count": len(seen_asset_ids),
        "scan_finished_at": scan_finished_at,
        "stats": {
            "elapsed_ms": round((time.perf_counter() - monitor_started) * 1000, 2),
            "asset_process_workers": host.SCAN_ASSET_PROCESS_WORKERS,
            "target_resolution_workers": host.SCAN_TARGET_RESOLUTION_WORKERS,
            "target_resolution_peak_active": resolution_peak_active,
            "target_resolution_requests": resolution_request_count,
            "target_resolution_errors": resolution_error_count,
            "background_queue_wait_ms": round(resolution_queue_wait_ms, 2),
            "http": resolution_http,
        },
    }


def resolve_scanned_target_once(
    *,
    client: MpVmClient,
    token: str,
    target: str,
    mp_job_id: str | None,
    run_started_at: str,
) -> tuple[list[dict[str, Any]], str]:
    records = host.query_scanned_asset_records(client, token, target)
    require_freshness = "/" in target
    assets = [
        normalize_scanned_asset_record(record, target=target, mp_job_id=mp_job_id)
        for record in records
        if not require_freshness or scanned_asset_record_is_current(record, run_started_at)
    ]
    assets = [asset for asset in assets if asset.get("asset_id")]
    scan_log(
        logging.INFO,
        "asset_resolution_result",
        job_id=mp_job_id,
        target=target,
        pdql_record_count=len(records),
        resolved_asset_count=len(assets),
        require_freshness=require_freshness,
        resolved_asset_ids=[asset.get("asset_id") for asset in assets],
    )
    if assets:
        return assets, ""
    if not records:
        return [], f"PDQL returned no assets for successful job target {target}."
    if require_freshness:
        return [], f"PDQL returned {len(records)} asset(s) for {target}, but none has CreationTime/UpdateTime from this run."
    return [], f"PDQL returned {len(records)} record(s) for {target}, but none contains asset_id."


def refresh_docker_containers_for_scanned_asset(
    *,
    client: MpVmClient,
    token: str,
    asset_id: str,
    item_id: int,
    parent_operation_id: str,
    iterations: int = _DEFAULT_DOCKER_GROUP_ITERATIONS,
    settle_seconds: float = _DEFAULT_DOCKER_GROUP_SETTLE_SECONDS,
    timeout_seconds: float = _DEFAULT_DOCKER_GROUP_TIMEOUT_SECONDS,
    poll_seconds: float = _DEFAULT_DOCKER_GROUP_POLL_SECONDS,
) -> dict[str, Any]:
    if iterations <= 0:
        return {"status": "disabled", "attempts": 0, "docker_ready": False}

    cancel_event = scan_postprocess_cancel_event(parent_operation_id)
    last_error: Exception | None = None
    successful_query = False
    for attempt in range(1, iterations + 1):
        raise_if_scan_postprocess_cancelled(parent_operation_id)
        if attempt > 1 and settle_seconds > 0:
            if cancel_event:
                if cancel_event.wait(settle_seconds):
                    raise ScanPostprocessCancelled("Scan post-processing was cancelled.")
            else:
                time.sleep(settle_seconds)
        raise_if_scan_postprocess_cancelled(parent_operation_id)
        docker_source: dict[str, Any] | None = None
        db.update_scan_postprocess_item(
            item_id,
            status="preparing",
            stage="probing_docker_containers",
            message=f"Docker container data probe {attempt} of {iterations}.",
            error=None,
        )
        scan_log(
            logging.INFO,
            "docker_container_probe_started",
                postprocess_run_id=parent_operation_id,
                item_id=item_id,
                asset_id=asset_id,
                attempt=attempt,
            iterations=iterations,
        )
        try:
            docker_source, warning = host.build_docker_vulnerability_source(
                token=token,
                asset_id=asset_id,
                asset_type="Host",
                pdql_template=DOCKER_VULNERABILITY_PDQL,
                max_items=1,
                sources=[],
                remote_call=lambda operation, _label: operation(client),
            )
            if warning:
                raise RuntimeError(warning)
            successful_query = True
        except ScanPostprocessCancelled:
            raise
        except Exception as exc:
            last_error = exc
            scan_log(
                logging.WARNING,
                "docker_container_probe_failed",
                postprocess_run_id=parent_operation_id,
                item_id=item_id,
                asset_id=asset_id,
                attempt=attempt,
                error=str(exc),
            )
            continue

        docker_ready = bool(
            docker_source
            and (
                docker_source.get("status") == "containers"
                or int(docker_source.get("vulnerabilities_count") or 0) > 0
            )
        )
        if docker_ready:
            return {"status": "ready", "attempts": attempt, "docker_ready": True}

    if not successful_query:
        raise RuntimeError(
            f"Docker container refresh failed after {iterations} iteration(s): {last_error or 'PDQL unavailable'}"
        )
    return {"status": "completed", "attempts": iterations, "docker_ready": False}


def process_scanned_asset_item(*, item: dict[str, Any], auth: AuthConfig, token: str) -> None:
    item_id = int(item["id"])
    asset_id = str(item["asset_id"])
    run_id = str(item.get("postprocess_run_id") or "")
    removal_operation_id = item.get("removal_operation_id")
    card_saved = bool(removal_operation_id)
    client = host.MpVmClient(auth)
    context = {
        "postprocess_run_id": run_id,
        "item_id": item_id,
        "job_id": item.get("mp_job_id"),
        "target": item.get("target"),
        "asset_id": asset_id,
    }
    scan_log(
        logging.INFO,
        "asset_processing_started",
        **context,
        resumed_removal_operation_id=removal_operation_id,
    )
    try:
        raise_if_scan_postprocess_cancelled(run_id)
        # Restart recovery: the card was already committed locally before the
        # previous process died (the removal batch had not started yet), so
        # skip the docker probe and rebuild and go straight to removal.
        card_already_saved = (
            not removal_operation_id
            and str(item.get("stage") or "") == "card_saved"
            and db.asset_card_exists(asset_id)
        )
        if card_already_saved:
            card_saved = True
            scan_log(logging.INFO, "asset_card_save_confirmed", **context)
        elif not removal_operation_id:
            refresh_docker_containers_for_scanned_asset(
                client=client,
                token=token,
                asset_id=asset_id,
                item_id=item_id,
                parent_operation_id=run_id,
            )
            scan_log(logging.INFO, "asset_card_build_starting", **context)
            build_job_id = build_scanned_asset_card(
                item_id=item_id,
                asset_id=asset_id,
                auth=auth,
                token=token,
                parent_operation_id=run_id,
            )
            item = db.update_scan_postprocess_item(
                item_id,
                status="card_saved",
                stage="card_saved",
                build_job_id=build_job_id,
                message="Asset card saved locally.",
                error=None,
            ) or item
            card_saved = True
            raise_if_scan_postprocess_cancelled(run_id)
            scan_log(logging.INFO, "asset_card_saved", **context, build_job_id=build_job_id)
        else:
            scan_log(
                logging.INFO,
                "mpvm_removal_resumed",
                **context,
                removal_operation_id=removal_operation_id,
            )
        batcher = scan_removal_batcher(run_id)
        if batcher is None:
            raise RuntimeError(f"No removal batcher registered for run {run_id}.")
        # Removal is batched per run: one remove_assets call per up to
        # _SCAN_REMOVAL_BATCH_SIZE card-saved assets, one operation poll
        # stream per batch. Enqueueing is non-blocking — the worker returns
        # now and the item keeps its card_saved stage until the batcher
        # thread marks it deleting and then a terminal status (the per-item
        # asset_processing_completed / mpvm_removal_failed events are
        # emitted by the batcher).
        batcher.enqueue(
            item_id,
            asset_id,
            existing_operation_id=str(removal_operation_id) if removal_operation_id else None,
        )
        scan_log(
            logging.INFO,
            "asset_removal_enqueued",
            **context,
            existing_operation_id=str(removal_operation_id) if removal_operation_id else None,
        )
    except ScanPostprocessCancelled:
        db.update_scan_postprocess_item(
            item_id,
            status="cancelled",
            stage="cancelled",
            message="Processing cancelled by operator.",
            finished_at=db.now_utc(),
        )
        raise
    except Exception as exc:
        status = "removal_failed" if card_saved else "build_failed"
        db.update_scan_postprocess_item(
            item_id,
            status=status,
            stage=status,
            error=str(exc)[:4000],
            finished_at=db.now_utc(),
        )
        SCAN_LOG.exception(
            "[scan-postprocess] asset processing failed status=%s context=%s",
            status,
            json.dumps(context, ensure_ascii=False, default=str),
        )
    finally:
        client.session.close()


def process_scanned_asset_item_with_progress(
    *,
    item: dict[str, Any],
    auth: AuthConfig,
    token: str,
    postprocess_run_id: str,
) -> None:
    process_scanned_asset_item(item=item, auth=auth, token=token)
    db.refresh_scan_postprocess_counts(postprocess_run_id)


def build_scanned_asset_card(
    *,
    item_id: int,
    asset_id: str,
    auth: AuthConfig,
    token: str,
    parent_operation_id: str,
) -> str:
    request = {
        "asset_id": asset_id,
        "timeline_timestamp": None,
        "limit_per_collection": 5000,
        "max_items_per_collection": 5000,
        "max_depth": ASSET_CARD_MAX_DEPTH,
        "parent_operation_id": parent_operation_id,
    }
    while True:
        raise_if_scan_postprocess_cancelled(parent_operation_id)
        # Count-based gate (not "no active job at all"): builds are allowed to
        # run concurrently up to ASSET_CARD_BUILD_JOB_LIMIT.
        active_count = db.count_active_asset_card_build_jobs()
        if active_count >= db.ASSET_CARD_BUILD_JOB_LIMIT:
            scan_log(
                logging.INFO,
                "asset_card_waiting_for_slot",
                item_id=item_id,
                asset_id=asset_id,
                active_build_job_count=active_count,
            )
            time.sleep(2)
            continue
        build_job_id = str(uuid.uuid4())
        build_trace_id = new_trace_id()
        try:
            job = db.create_asset_card_build_job(
                build_job_id,
                trace_id=build_trace_id,
                asset_id=asset_id,
                operation="refresh" if db.asset_card_exists(asset_id) else "create",
                request=request,
            )
            if job is None:
                scan_log(
                    logging.INFO,
                    "asset_card_slot_busy_retry",
                    item_id=item_id,
                    asset_id=asset_id,
                )
                time.sleep(2)
                continue
            scan_log(
                logging.INFO,
                "asset_card_build_job_created",
                item_id=item_id,
                asset_id=asset_id,
                build_job_id=build_job_id,
            )
            break
        except psycopg.errors.UniqueViolation:
            scan_log(
                logging.INFO,
                "asset_card_slot_race_retry",
                item_id=item_id,
                asset_id=asset_id,
            )
            time.sleep(2)
    db.update_scan_postprocess_item(
        item_id,
        status="building",
        stage="building_card",
        build_job_id=build_job_id,
        started_at=db.now_utc(),
    )
    cancel_event = host.register_asset_card_build_job(build_job_id)
    host.run_asset_card_build_job(
        job_id=build_job_id,
        auth=auth,
        token=token,
        request=request,
        cancel_event=cancel_event,
        trace_id=build_trace_id,
    )
    job = db.get_asset_card_build_job(build_job_id)
    if not job or job.get("status") != "completed":
        scan_log(
            logging.ERROR,
            "asset_card_build_job_failed",
            item_id=item_id,
            asset_id=asset_id,
            build_job_id=build_job_id,
            build_status=(job or {}).get("status"),
            message=(job or {}).get("message"),
        )
        raise RuntimeError((job or {}).get("message") or "Asset card build did not complete.")
    canonical_asset_id = str(job.get("asset_id") or asset_id)
    if not db.asset_card_exists(canonical_asset_id):
        scan_log(
            logging.ERROR,
            "asset_card_missing_after_build",
            item_id=item_id,
            asset_id=asset_id,
            build_job_id=build_job_id,
        )
        raise RuntimeError("Asset card build completed without a saved local card.")
    scan_log(
        logging.INFO,
        "asset_card_build_job_completed",
        item_id=item_id,
        asset_id=canonical_asset_id,
        original_asset_id=asset_id if canonical_asset_id != asset_id else None,
        build_job_id=build_job_id,
    )
    return build_job_id
