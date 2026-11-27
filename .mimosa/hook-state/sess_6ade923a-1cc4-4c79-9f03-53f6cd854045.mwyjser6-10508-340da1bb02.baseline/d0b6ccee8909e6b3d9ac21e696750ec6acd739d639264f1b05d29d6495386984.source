from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from .. import db
from ..mpvm.common import parse_mpvm_datetime
from ..mpvm.docker_vulnerabilities import docker_dynamic_group_from_options, docker_scan_group_name
from ..mpvm_client import AuthConfig, is_finished
from .main_host import host
from .scan_postprocess import SCAN_LOG, scan_log

if TYPE_CHECKING:
    from ..mpvm_client import MpVmClient

DOCKER_GROUP_CLEANUP_FUTURES: dict[str, Future[Any]] = {}


DOCKER_GROUP_CLEANUP_FUTURES_LOCK = threading.Lock()


def prepare_docker_dynamic_group_for_scan(
    *,
    client: MpVmClient,
    token: str,
    run_id: str,
    task_id: str,
    persist_lifecycle: bool = False,
) -> dict[str, Any] | None:
    """Create one run-scoped Docker group and make it ready before the remote scan starts."""
    if host.DOCKER_DYNAMIC_GROUP_ITERATIONS <= 0:
        return None

    group_name = docker_scan_group_name(run_id)
    if persist_lifecycle:
        db.update_scan_postprocess_docker_group(
            run_id,
            name=group_name,
            state="creating",
            cleanup_error=None,
        )
    try:
        hierarchy = client.get_asset_group_hierarchy(token)
        existing = client.find_asset_group(hierarchy, name=group_name)
    except Exception as exc:
        if persist_lifecycle:
            db.update_scan_postprocess_docker_group(
                run_id,
                state="create_failed",
                cleanup_after=db.now_utc(),
                cleanup_error=str(exc)[:4000],
            )
        raise
    if existing and existing.get("id"):
        group_id = str(existing["id"])
        reused_at = db.now_utc()
        if persist_lifecycle:
            db.update_scan_postprocess_docker_group(
                run_id,
                id=group_id,
                name=group_name,
                state="ready",
                created_at=reused_at,
                reused=True,
            )
        scan_log(
            logging.INFO,
            "docker_dynamic_group_reused",
            postprocess_run_id=run_id,
            task_id=task_id,
            group_id=group_id,
            group_name=group_name,
        )
        return {
            "id": group_id,
            "name": group_name,
            "created_at": reused_at,
            "reused": True,
        }

    try:
        operation_id = client.create_dynamic_asset_group(
            token,
            name=group_name,
            predicate=host.DOCKER_DYNAMIC_GROUP_PREDICATE,
            parent_id=host.DOCKER_DYNAMIC_GROUP_PARENT_ID,
            description=(
                f"Managed Docker container discovery group for scanner task {task_id}; "
                f"scan run {run_id}."
            ),
        )
        if persist_lifecycle:
            db.update_scan_postprocess_docker_group(
                run_id,
                creation_operation_id=operation_id,
            )
        group_id = client.wait_for_asset_group_creation(
            token,
            operation_id,
            timeout_seconds=host.DOCKER_DYNAMIC_GROUP_TIMEOUT_SECONDS,
            poll_seconds=host.DOCKER_DYNAMIC_GROUP_POLL_SECONDS,
        )
    except Exception as exc:
        if persist_lifecycle:
            db.update_scan_postprocess_docker_group(
                run_id,
                state="create_failed",
                cleanup_after=db.now_utc(),
                cleanup_error=str(exc)[:4000],
            )
        raise
    if host.DOCKER_DYNAMIC_GROUP_SETTLE_SECONDS > 0:
        time.sleep(host.DOCKER_DYNAMIC_GROUP_SETTLE_SECONDS)
    created_at = db.now_utc()
    if persist_lifecycle:
        db.update_scan_postprocess_docker_group(
            run_id,
            id=group_id,
            name=group_name,
            state="ready",
            created_at=created_at,
            creation_operation_id=operation_id,
            reused=False,
            cleanup_error=None,
        )
    scan_log(
        logging.INFO,
        "docker_dynamic_group_ready_before_scan",
        postprocess_run_id=run_id,
        task_id=task_id,
        group_id=group_id,
        group_name=group_name,
        creation_operation_id=operation_id,
    )
    return {
        "id": group_id,
        "name": group_name,
        "created_at": created_at,
        "creation_operation_id": operation_id,
        "reused": False,
    }


def remove_docker_dynamic_group(
    *,
    client: MpVmClient,
    token: str,
    group: dict[str, Any],
) -> dict[str, Any]:
    group_id = str(group.get("id") or "").strip()
    group_name = str(group.get("name") or "").strip()
    hierarchy = client.get_asset_group_hierarchy(token)
    existing = client.find_asset_group(hierarchy, group_id=group_id) if group_id else None
    if existing is None and group_name:
        existing = client.find_asset_group(hierarchy, name=group_name)
    if existing is None:
        return {"removed": True, "already_absent": True, "group_id": group_id or None}

    actual_group_id = str(existing.get("id") or group_id)
    if not actual_group_id:
        raise RuntimeError(f"Docker dynamic group {group_name or '<unnamed>'} has no id.")
    removal_operation_id = client.remove_asset_groups(token, [actual_group_id])
    client.wait_for_asset_group_absent(
        token,
        actual_group_id,
        timeout_seconds=host.DOCKER_DYNAMIC_GROUP_TIMEOUT_SECONDS,
        poll_seconds=host.DOCKER_DYNAMIC_GROUP_POLL_SECONDS,
    )
    return {
        "removed": True,
        "already_absent": False,
        "group_id": actual_group_id,
        "removal_operation_id": removal_operation_id,
    }


def remember_docker_scan_finished_at(run_id: str, finished_at: str, *, confirmed: bool) -> None:
    run = db.get_scan_postprocess_run(run_id)
    if not run or not docker_dynamic_group_from_options(run.get("options")):
        return
    db.update_scan_postprocess_docker_group(
        run_id,
        scan_finished_at=finished_at,
        scan_terminal_confirmed=confirmed,
    )


def docker_group_cleanup_after(scan_finished_at: str | None) -> str:
    finished = parse_mpvm_datetime(scan_finished_at) or datetime.now(UTC)
    return (finished + timedelta(seconds=host.DOCKER_DYNAMIC_GROUP_RETENTION_SECONDS)).isoformat(timespec="seconds")


def confirm_docker_scan_terminal_for_cleanup(
    *,
    client: MpVmClient,
    token: str,
    run: dict[str, Any],
    group: dict[str, Any],
) -> dict[str, Any] | None:
    """Return cleanup-ready metadata, or ``None`` while the remote scan may still be active."""
    start_was_requested = bool(group.get("scanner_start_requested_at") or group.get("scanner_started_at"))
    if not start_was_requested or group.get("scan_terminal_confirmed") is True:
        return group

    task_id = str(run.get("mp_task_id") or "").strip()
    started_from = str(run.get("started_from") or "").strip()
    if not task_id or not started_from:
        raise RuntimeError("Cannot confirm scanner termination: task id or start timestamp is missing.")

    runs = client.get_task_runs(token, task_id, time_from=started_from)
    if not runs:
        cleanup_at = parse_mpvm_datetime(group.get("cleanup_after"))
        start_failed = str(group.get("state") or "").strip().lower() == "start_failed"
        if start_failed and cleanup_at is not None and cleanup_at <= datetime.now(UTC):
            scan_log(
                logging.WARNING,
                "docker_dynamic_group_cleanup_after_unobserved_start_failure",
                postprocess_run_id=run.get("run_id"),
                task_id=task_id,
                cleanup_after=group.get("cleanup_after"),
            )
            return {**group, "scanner_run_not_observed": True}
        return None
    latest_run = runs[0]
    expected_run_id = str(run.get("mp_run_id") or "").strip()
    actual_run_id = str(latest_run.get("id") or "").strip()
    if expected_run_id and actual_run_id and actual_run_id != expected_run_id:
        return None
    if not is_finished(latest_run):
        return None

    terminal_at = str(latest_run.get("finishedAt") or db.now_utc())
    cleanup_after = docker_group_cleanup_after(terminal_at)
    db.update_scan_postprocess_docker_group(
        str(run["run_id"]),
        scan_finished_at=terminal_at,
        scan_terminal_confirmed=True,
        cleanup_after=cleanup_after,
        cleanup_error=None,
    )
    return {
        **group,
        "scan_finished_at": terminal_at,
        "scan_terminal_confirmed": True,
        "cleanup_after": cleanup_after,
    }


def finish_provisional_scan_start_failure(
    *,
    run_id: str,
    auth: AuthConfig,
    token: str,
    error: Exception,
) -> None:
    run = db.get_scan_postprocess_run(run_id)
    if not run or run.get("status") not in db.SCAN_POSTPROCESS_ACTIVE_STATUSES:
        return
    options = run.get("options") if isinstance(run.get("options"), dict) else {}
    failed_at = db.now_utc()
    host.schedule_scan_docker_group_cleanup(
        run_id=run_id,
        auth=auth,
        token=token,
        options=options,
        scan_finished_at=failed_at,
    )
    db.finish_scan_postprocess_run(
        run_id,
        status="failed",
        stage="scanner_start_failed",
        message="Scanner task start could not be confirmed; managed Docker group cleanup was requested.",
        error=str(error)[:4000],
    )


def schedule_scan_docker_group_cleanup(
    *,
    run_id: str,
    auth: AuthConfig,
    token: str,
    options: dict[str, Any] | None = None,
    scan_finished_at: str | None = None,
) -> bool:
    supplied_group = docker_dynamic_group_from_options(options)
    if supplied_group is None:
        return False

    run = db.get_scan_postprocess_run(run_id)
    if not run:
        return False
    group = docker_dynamic_group_from_options(run.get("options")) or supplied_group
    if group.get("removed_at"):
        return False

    terminal_at = str(group.get("scan_finished_at") or scan_finished_at or db.now_utc())
    cleanup_after = str(group.get("cleanup_after") or docker_group_cleanup_after(terminal_at))
    updated = db.update_scan_postprocess_docker_group(
        run_id,
        scan_finished_at=str(group.get("scan_finished_at") or terminal_at),
        cleanup_after=cleanup_after,
        cleanup_error=None,
    )
    if not updated:
        return False

    with DOCKER_GROUP_CLEANUP_FUTURES_LOCK:
        current = DOCKER_GROUP_CLEANUP_FUTURES.get(run_id)
        if current and not current.done():
            return True
        cancel_event = host.CONTAINER.operation_runner.cancellations.register("docker-group-cleanup", run_id)
        future = host.CONTAINER.operation_runner.submit(
            "docker-group-cleanup",
            run_scan_docker_group_cleanup,
            run_id=run_id,
            auth=auth,
            token=token,
            cancel_event=cancel_event,
        )
        DOCKER_GROUP_CLEANUP_FUTURES[run_id] = future

    def forget(_future: Future[Any]) -> None:
        with DOCKER_GROUP_CLEANUP_FUTURES_LOCK:
            if DOCKER_GROUP_CLEANUP_FUTURES.get(run_id) is _future:
                DOCKER_GROUP_CLEANUP_FUTURES.pop(run_id, None)
        host.CONTAINER.operation_runner.cancellations.remove("docker-group-cleanup", run_id)

    future.add_done_callback(forget)
    scan_log(
        logging.INFO,
        "docker_dynamic_group_cleanup_scheduled",
        postprocess_run_id=run_id,
        group_id=group.get("id"),
        group_name=group.get("name"),
        scan_finished_at=terminal_at,
        cleanup_after=cleanup_after,
        retention_seconds=host.DOCKER_DYNAMIC_GROUP_RETENTION_SECONDS,
    )
    return True


def run_scan_docker_group_cleanup(
    *,
    run_id: str,
    auth: AuthConfig,
    token: str,
    cancel_event: threading.Event,
) -> None:
    client = host.MpVmClient(auth)
    retry_seconds = max(30.0, float(host.DOCKER_DYNAMIC_GROUP_POLL_SECONDS))
    try:
        while not cancel_event.is_set():
            try:
                run = db.get_scan_postprocess_run(run_id)
                if not run:
                    return
                group = docker_dynamic_group_from_options(run.get("options"))
                if not group or group.get("removed_at"):
                    return
                if run.get("status") in db.SCAN_POSTPROCESS_ACTIVE_STATUSES:
                    if cancel_event.wait(min(5.0, retry_seconds)):
                        return
                    continue

                needs_terminal_check = bool(
                    (group.get("scanner_start_requested_at") or group.get("scanner_started_at"))
                    and group.get("scan_terminal_confirmed") is not True
                )
                confirmation_token = client.ensure_access_token() if needs_terminal_check else token
                confirmed_group = confirm_docker_scan_terminal_for_cleanup(
                    client=client,
                    token=confirmation_token,
                    run=run,
                    group=group,
                )
                if confirmed_group is None:
                    scan_log(
                        logging.INFO,
                        "docker_dynamic_group_cleanup_waiting_for_scan_terminal",
                        postprocess_run_id=run_id,
                        task_id=run.get("mp_task_id"),
                        mp_run_id=run.get("mp_run_id"),
                    )
                    if cancel_event.wait(retry_seconds):
                        return
                    continue
                group = confirmed_group
                cleanup_at = parse_mpvm_datetime(group.get("cleanup_after"))
                if cleanup_at is None:
                    raise RuntimeError("Docker dynamic group cleanup deadline is missing or invalid.")
                remaining = (cleanup_at - datetime.now(UTC)).total_seconds()
                if remaining > 0 and cancel_event.wait(remaining):
                    return

                cleanup_token = client.ensure_access_token()
                cleanup = remove_docker_dynamic_group(client=client, token=cleanup_token, group=group)
                removed_at = db.now_utc()
                db.update_scan_postprocess_docker_group(
                    run_id,
                    removed_at=removed_at,
                    removal_operation_id=cleanup.get("removal_operation_id"),
                    cleanup_error=None,
                )
                scan_log(
                    logging.INFO,
                    "docker_dynamic_group_removed_after_scan",
                    postprocess_run_id=run_id,
                    group_name=group.get("name"),
                    removed_at=removed_at,
                    **cleanup,
                )
                return
            except Exception as exc:
                try:
                    db.update_scan_postprocess_docker_group(
                        run_id,
                        cleanup_error=str(exc)[:4000],
                        cleanup_last_attempt_at=db.now_utc(),
                    )
                except Exception:
                    SCAN_LOG.exception(
                        "[scan-postprocess] failed to persist Docker group cleanup error "
                        "postprocess_run_id=%s",
                        run_id,
                    )
                SCAN_LOG.exception(
                    "[scan-postprocess] Docker group cleanup failed; retrying "
                    "postprocess_run_id=%s retry_seconds=%s",
                    run_id,
                    retry_seconds,
                )
                if cancel_event.wait(retry_seconds):
                    return
    finally:
        client.session.close()
