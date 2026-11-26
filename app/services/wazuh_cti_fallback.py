"""Fallback per-CVE refresh when the bulk Wazuh download is unavailable."""

import logging
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack
from random import uniform
from threading import Event
from time import monotonic

import requests
from fastapi import HTTPException

from ..core import get_settings
from ..diagnostics import log_event
from ..repositories import passport_refresh
from ..repositories.passports.wazuh_cti import record_refresh_failures, refresh_candidates
from .wazuh_cti import TransientWazuhError, refresh_passport

WAZUH_REFRESH_WORKERS = 64
PROGRESS_INTERVAL = 2
MAX_REFRESH_ATTEMPTS = 3


def _refresh_with_retries(
    passport_id: str, session: requests.Session, cancel_event: Event, rate_limited: Event,
) -> tuple[str, int, int, str] | None:
    for attempt in range(1, MAX_REFRESH_ATTEMPTS + 1):
        try:
            refresh_passport(passport_id, session=session)
        except HTTPException as exc:
            if exc.status_code == 429:
                rate_limited.set()
            failure = (passport_id, exc.status_code, attempt, str(exc.detail)[:1000])
            if not isinstance(exc, TransientWazuhError) or attempt == MAX_REFRESH_ATTEMPTS or rate_limited.is_set():
                return failure
            if cancel_event.wait(2 ** (attempt - 1) + uniform(0, 0.5)) or rate_limited.is_set():
                return failure
        else:
            return None
    raise AssertionError("Unreachable retry state")


def refresh_local_passports(operation_id: str, cancel_event: Event) -> None:
    counts = {"total": 0, "updated": 0, "failed": 0, "skipped_fresh": 0}
    progress = 0
    rate_limited = Event()

    def report() -> None:
        nonlocal progress
        processed = counts["updated"] + counts["failed"]
        eligible = counts["total"] - counts["skipped_fresh"]
        progress = processed * 100 // eligible if eligible else 0
        passport_refresh.update(
            operation_id, status="running", stage="wazuh-cti-fallback", percent=progress,
            message=(f"Wazuh CTI per-CVE: обработано {processed} из {eligible}. "
                     f"Свежих пропущено: {counts['skipped_fresh']}."),
            result={"wazuh_cti": counts, "mode": "per-cve"},
        )

    try:
        if not cancel_event.is_set():
            settings = get_settings()
            passport_ids, counts["skipped_fresh"] = refresh_candidates(min(8760, settings.passport_detail_ttl_hours))
            counts["total"] = len(passport_ids) + counts["skipped_fresh"]
            workers = min(WAZUH_REFRESH_WORKERS, len(passport_ids))
            if workers and not cancel_event.is_set():
                report()
                last_report = monotonic()
                remaining = iter(passport_ids)
                with ExitStack() as stack:
                    sessions = [stack.enter_context(requests.Session()) for _ in range(workers)]
                    executor = stack.enter_context(ThreadPoolExecutor(max_workers=workers, thread_name_prefix="wazuh-cti"))
                    pending = {}

                    def submit_next(session: requests.Session) -> None:
                        if cancel_event.is_set() or rate_limited.is_set():
                            return
                        passport_id = next(remaining, None)
                        if passport_id is not None:
                            future = executor.submit(_refresh_with_retries, passport_id, session, cancel_event, rate_limited)
                            pending[future] = session

                    for session in sessions:
                        submit_next(session)
                    while pending:
                        completed, _ = wait(pending, timeout=PROGRESS_INTERVAL, return_when=FIRST_COMPLETED)
                        available = []
                        failures = []
                        for future in completed:
                            available.append(pending.pop(future))
                            failure = future.result()
                            if failure is not None:
                                failures.append(failure)
                            else:
                                counts["updated"] += 1
                        if failures:
                            record_refresh_failures(operation_id, failures)
                            counts["failed"] += len(failures)
                        for session in available:
                            submit_next(session)
                        now = monotonic()
                        if now - last_report >= PROGRESS_INTERVAL and not cancel_event.is_set():
                            report()
                            last_report = now
                progress = (counts["updated"] + counts["failed"]) * 100 // len(passport_ids)
        if cancel_event.is_set():
            status = "cancelled"
            message = "Обновление Wazuh CTI остановлено."
        elif rate_limited.is_set():
            status = "completed_with_errors"
            message = (f"Wazuh CTI ограничил частоту запросов. Обновлено: {counts['updated']}, "
                       f"ошибок: {counts['failed']}, свежих пропущено: {counts['skipped_fresh']}.")
        else:
            status = "completed_with_errors" if counts["failed"] else "completed"
            message = (f"Wazuh CTI per-CVE: обновлено {counts['updated']} из {counts['total']}, "
                       f"ошибок {counts['failed']}, свежих пропущено: {counts['skipped_fresh']}.")
            progress = 100
    except Exception as exc:
        log_event("passport-sync", "wazuh-cti.refresh.failed", level=logging.ERROR,
                  operation_id=operation_id, error_type=type(exc).__name__)
        status = "failed"
        message = "Не удалось завершить обновление паспортов Wazuh CTI."
    passport_refresh.update(
        operation_id, status=status, stage=status, percent=progress, message=message,
        result={"wazuh_cti": counts, "mode": "per-cve"},
    )
