"""Apply the official bulk CTI snapshot to existing local DEB passports."""

import json
import logging
import re
from collections.abc import Callable
from hashlib import sha256
from tempfile import TemporaryFile
from threading import Event
from time import monotonic
from typing import BinaryIO
from urllib.parse import urlsplit
from zipfile import ZipFile

import requests
from fastapi import HTTPException
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from ..diagnostics import log_event
from ..repositories import passport_refresh
from ..repositories.asset_cards.wazuh_match import inventory_package_names
from ..repositories.passports.wazuh_cti import (
    record_refresh_failures,
    save_snapshot_batch,
    snapshot_applied,
    snapshot_targets,
)
from .wazuh_asset_match import PLATFORMS, platform_for
from .wazuh_cti import summarize_record

CATALOG_URL = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0"
CVE_LINE = re.compile(rb'^\s*\{\s*"name"\s*:\s*"(CVE-[0-9]{4}-[0-9]{4,})"')
BATCH_SIZE = 500


class SnapshotCancelled(Exception):
    pass


def collect_snapshot(
    stream: BinaryIO,
    targets: dict[str, bool],
    inventory: set[tuple[str, str, str]],
    cancel: Event,
    tick: Callable[[], None],
):
    records = {}
    failures = {}
    observed = set()
    found_schema = False
    for index, line in enumerate(stream):
        if index % 1024 == 0:
            if cancel.is_set():
                raise SnapshotCancelled
            tick()
        match = CVE_LINE.match(line)
        if not match:
            continue
        cve = match[1].decode("ascii")
        if found_schema and cve not in targets:
            continue
        passport_id = f"wazuh-cti:{cve}"
        try:
            payload = json.loads(line)["payload"]
            parsed = summarize_record(cve, payload, require_rules=not targets.get(cve))
        except (HTTPException, KeyError, TypeError, ValueError):
            if cve in targets:
                observed.add(cve)
                failures[cve] = (passport_id, 502, 1, "Некорректная запись CVE в снимке Wazuh CTI.")
            continue
        found_schema = True
        if cve not in targets:
            continue
        observed.add(cve)
        failures.pop(cve, None)
        if parsed is None:
            records.pop(cve, None)
            continue
        detail, rules = parsed
        detail["rules_hash"] = sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()
        records[cve] = (passport_id, detail, rules)

    if not found_schema:
        raise ValueError("Снимок не содержит читаемых записей CVE.")
    ordered = sorted(
        (row for cve, row in records.items() if cve not in failures),
        key=lambda row: (
            not any((vendor, release, package) in inventory for vendor, release, package, _, _ in row[2]),
            -(row[1]["score"] or 0),
            row[0],
        ),
    )
    return ordered, len(observed), list(failures.values())


def snapshot_metadata(session: requests.Session) -> tuple[int, str]:
    with session.get(CATALOG_URL, timeout=(5, 20)) as response:
        response.raise_for_status()
        data = response.json()["data"]
    offset, url = data["last_snapshot_offset"], data["last_snapshot_link"]
    location = urlsplit(url)
    if (type(offset) is not int or offset < 0 or location.scheme != "https"
            or location.netloc != "cti.wazuh.com" or not location.path.startswith("/store/contexts/vd_1.0.0/")):
        raise ValueError("Некорректный адрес или номер снимка Wazuh CTI.")
    return offset, url


def refresh_local_passports(operation_id: str, cancel: Event) -> None:
    counts = {"total": 0, "updated": 0, "failed": 0, "unchanged": 0, "outside_scope": 0, "not_in_snapshot": 0}
    checkpoint = {}
    progress = 0
    last_report = 0.0

    def report(percent: int, stage: str, message: str, *, force: bool = False) -> None:
        nonlocal progress, last_report
        if cancel.is_set():
            raise SnapshotCancelled
        now = monotonic()
        if force or now - last_report >= 2:
            progress = percent
            last_report = now
            passport_refresh.update(
                operation_id, status="running", stage=stage, percent=progress, message=message,
                result={"wazuh_cti": counts},
            )

    def apply_snapshot() -> str:
        targets = snapshot_targets()
        counts["total"] = len(targets)
        if not targets:
            return "Локальных паспортов Wazuh CTI нет."
        report(1, "snapshot", "Проверка версии снимка Wazuh CTI.", force=True)
        scope = sha256(json.dumps([list(targets), sorted(PLATFORMS.items())]).encode()).hexdigest()
        with requests.Session() as session:
            session.mount("https://", HTTPAdapter(max_retries=Retry(
                total=2, allowed_methods={"GET"}, status_forcelist=(408, 500, 502, 503, 504),
                backoff_factor=0.5, respect_retry_after_header=False,
            )))
            offset, url = snapshot_metadata(session)
            checkpoint.update(offset=offset, scope=scope)
            if snapshot_applied(offset, scope):
                return f"Снимок Wazuh CTI {offset} уже применён к этому набору паспортов."
            report(3, "snapshot", "Загрузка снимка Wazuh CTI.", force=True)
            with TemporaryFile() as downloaded:
                with session.get(url, timeout=(5, 60), stream=True, allow_redirects=False) as response:
                    if response.status_code != 200:
                        response.raise_for_status()
                        raise ValueError("Ожидался ZIP-снимок Wazuh CTI.")
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if cancel.is_set():
                            raise SnapshotCancelled
                        downloaded.write(chunk)
                        size = downloaded.tell()
                        report(20, "snapshot", f"Скачано {size // (1024 * 1024)} МиБ снимка Wazuh CTI.")
                report(40, "filter", "Отбор CVE для Ubuntu и Debian.", force=True)
                inventory = {
                    (*platform, row["package"])
                    for row in inventory_package_names() if row["package"]
                    if (platform := platform_for(row["os_name"], row["os_version"]))
                }
                with ZipFile(downloaded) as archive:
                    members = [name for name in archive.namelist() if name.endswith(".json")]
                    if len(members) != 1:
                        raise ValueError("Снимок должен содержать один JSON-файл.")
                    with archive.open(members[0]) as stream:
                        entries, seen, failures = collect_snapshot(
                            stream, targets, inventory, cancel,
                            lambda: report(40, "filter", "Чтение и отбор CVE из снимка Wazuh CTI."),
                        )
        counts["not_in_snapshot"] = len(targets) - seen
        counts["outside_scope"] = seen - len(entries) - len(failures)
        for start in range(0, len(failures), BATCH_SIZE):
            if cancel.is_set():
                raise SnapshotCancelled
            batch = failures[start : start + BATCH_SIZE]
            record_refresh_failures(operation_id, batch)
            counts["failed"] += len(batch)
        report(60, "save", f"Отобрано {len(entries)} паспортов для записи правил.", force=True)
        for start in range(0, len(entries), BATCH_SIZE):
            if cancel.is_set():
                raise SnapshotCancelled
            batch_entries = entries[start : start + BATCH_SIZE]
            changed = save_snapshot_batch(batch_entries)
            counts["updated"] += changed
            counts["unchanged"] += len(batch_entries) - changed
            processed = start + len(batch_entries)
            report(60 + 39 * processed // len(entries), "save", f"Проверено для записи {processed} из {len(entries)} паспортов.")
        return (f"Wazuh CTI: обновлено {counts['updated']}, без изменений {counts['unchanged']}, "
                f"вне охвата {counts['outside_scope']}, нет в снимке {counts['not_in_snapshot']}, ошибок {counts['failed']}.")

    try:
        if cancel.is_set():
            raise SnapshotCancelled
        message = apply_snapshot()
        if cancel.is_set():
            raise SnapshotCancelled
        status = "completed_with_errors" if counts["failed"] else "completed"
        progress = 100
    except SnapshotCancelled:
        status = "cancelled"
        message = "Обновление Wazuh CTI остановлено."
    except Exception as exc:
        log_event("passport-sync", "wazuh-cti.snapshot.failed", level=logging.ERROR,
                  operation_id=operation_id, error_type=type(exc).__name__)
        status = "failed"
        message = "Не удалось применить bulk-снимок Wazuh CTI."
    passport_refresh.update(
        operation_id, status=status, stage=status, percent=progress, message=message,
        result={"wazuh_cti": counts, "snapshot": checkpoint},
    )
