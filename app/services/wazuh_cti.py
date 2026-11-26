"""Load and cache the public Wazuh CTI record for a local CVE passport."""

import logging
import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack
from random import uniform
from threading import Event
from time import monotonic
from typing import Any

import requests
from fastapi import HTTPException

from ..core import get_settings
from ..diagnostics import log_event
from ..repositories import passport_refresh
from ..repositories.passports.wazuh_cti import record_refresh_failures, refresh_candidates, save_detail
from .wazuh_asset_match import extract_rules

PASSPORT_ID = re.compile(r"wazuh-cti:(CVE-[0-9]{4}-[0-9]{4,})")
WAZUH_REFRESH_WORKERS = 64
PROGRESS_INTERVAL = 2
MAX_REFRESH_ATTEMPTS = 3


class TransientWazuhError(HTTPException):
    """An HTTP or transport failure eligible for another attempt."""


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
            operation_id, status="running", stage="wazuh-cti", percent=progress,
            message=(f"Wazuh CTI: обработано {processed} из {eligible}. "
                     f"Свежих пропущено: {counts['skipped_fresh']}."),
            result={"wazuh_cti": counts},
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
            message = (f"Wazuh CTI: обновлено {counts['updated']} из {counts['total']}, "
                       f"ошибок {counts['failed']}, свежих пропущено: {counts['skipped_fresh']}.")
            progress = 100
    except Exception as exc:
        log_event("passport-sync", "wazuh-cti.refresh.failed", level=logging.ERROR,
                  operation_id=operation_id, error_type=type(exc).__name__)
        status = "failed"
        message = "Не удалось завершить обновление паспортов Wazuh CTI."
    passport_refresh.update(
        operation_id, status=status, stage=status, percent=progress, message=message,
        result={"wazuh_cti": counts},
    )


def refresh_passport(passport_id: str, *, session: requests.Session | None = None) -> dict[str, Any]:
    match = PASSPORT_ID.fullmatch(passport_id)
    if not match:
        raise HTTPException(status_code=404, detail="Паспорт Wazuh CTI не найден.")
    cve = match[1]
    url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve}"
    try:
        get = session.get if session is not None else requests.get
        response = get(f"{url}/json5", timeout=(3, 10), allow_redirects=False)
        response.raise_for_status()
        record = response.json()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 404:
            raise HTTPException(status_code=404, detail=f"{cve} отсутствует в Wazuh CTI.") from exc
        if status == 429:
            raise HTTPException(status_code=429, detail="Wazuh CTI ограничил частоту запросов.") from exc
        if status in (408, 500, 502, 503, 504):
            raise TransientWazuhError(status_code=502, detail=f"Wazuh CTI вернул HTTP {status}.") from exc
        raise HTTPException(status_code=502, detail="Wazuh CTI временно недоступен.") from exc
    except (requests.Timeout, requests.ConnectionError, requests.exceptions.ChunkedEncodingError) as exc:
        raise TransientWazuhError(status_code=502, detail="Сбой соединения с Wazuh CTI.") from exc
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Не удалось загрузить запись Wazuh CTI.") from exc

    metadata = record.get("cveMetadata") if isinstance(record, dict) else None
    containers = record.get("containers") if isinstance(record, dict) else None
    if not isinstance(metadata, dict) or metadata.get("cveId") != cve or not isinstance(containers, dict):
        raise HTTPException(status_code=502, detail="Wazuh CTI вернул некорректную запись CVE.")
    adp = containers.get("adp")
    providers = [containers.get("cna"), *(adp if isinstance(adp, list) else [])]
    descriptions = []
    scores = []
    references: dict[str, None] = {}
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        for reference in provider.get("references") or []:
            link = reference.get("url") if isinstance(reference, dict) else None
            if isinstance(link, str) and link.lower().startswith(("https://", "http://")):
                references[link] = None
        for item in provider.get("descriptions") or []:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                descriptions.append(item)
        for metric in provider.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                score = metric.get(key)
                if isinstance(score, dict) and type(score.get("baseScore")) in (float, int):
                    scores.append(score)
    cvss = max(scores, key=lambda score: score["baseScore"], default={})
    description = next(
        (item["value"] for item in descriptions if item.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else None,
    )
    saved = save_detail(passport_id, {
        "source": "wazuh-cti",
        "url": url,
        "cves": [cve],
        "description": description,
        "severity": cvss.get("baseSeverity"),
        "score": cvss.get("baseScore"),
        "publishedAt": metadata.get("datePublished"),
        "references": list(references),
        "rules_indexed": True,
    }, extract_rules(providers))
    if saved is None:
        raise HTTPException(status_code=404, detail="Паспорт Wazuh CTI не найден.")
    return saved
