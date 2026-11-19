from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from ..core import get_settings
from ..mpvm.common import parse_mpvm_datetime
from ..mpvm_client import MpVmClient, status_strings
from ..repositories.assets import delete_stale_local_asset
from .main_host import host


def unavailable_scan_ips(jobs: list[dict[str, Any]], unreachable_errors: set[str]) -> set[str]:
    unavailable: set[str] = set()
    other: set[str] = set()
    for job in jobs:
        targets = job.get("targets")
        if isinstance(targets, str):
            targets = [targets]
        if not isinstance(targets, list):
            continue
        for target in targets:
            try:
                address = str(ip_address(str(target)))
            except ValueError:
                continue
            results = job.get("connectionCheckResults")
            confirmed = (
                len(targets) == 1
                and bool(job.get("id"))
                and status_strings(job.get("status")) in ({"finished"}, {"completed"})
                and "connectioncheck" in status_strings(job.get("runMode"))
                and isinstance(results, list)
                and bool(results)
                and all(
                    isinstance(result, dict)
                    and status_strings(result.get("status")) in ({"fail"}, {"failed"})
                    and isinstance(errors := result.get("errors"), list)
                    and bool(errors)
                    and all(isinstance(error, str) and error.strip() in unreachable_errors for error in errors)
                    for result in results
                )
            )
            (unavailable if confirmed else other).add(address)
    return unavailable - other


def cleanup_stale_scan_assets(
    client: MpVmClient, token: str, run_id: str, scan: dict[str, Any], check_cancelled: Callable[[], None],
    *, connection_check: dict[str, Any] | None = None,
) -> int:
    settings = get_settings()
    reasons = {error.strip() for error in settings.scan_unreachable_errors.split(",") if error.strip()}
    if not reasons:
        return 0

    finished = parse_mpvm_datetime(scan.get("confirmed_finished_at"))
    now = datetime.now(UTC)
    if not finished or finished > now or now - finished > timedelta(days=1):
        return 0
    jobs = list(scan["jobs"])
    if connection_check:
        task_id = connection_check.get("task_id")
        started = parse_mpvm_datetime(connection_check.get("started_from"))
        if isinstance(task_id, str) and task_id and started:
            check_cancelled()
            with host.BACKGROUND_REQUEST_SEMAPHORE:
                runs = client.get_task_runs(token, task_id, time_from=started.isoformat())
                if len(runs) == 1:
                    precheck_run = runs[0]
                    precheck_finished = parse_mpvm_datetime(precheck_run.get("finishedAt"))
                    if (
                        precheck_run.get("id")
                        and status_strings(precheck_run.get("status")) in ({"finished"}, {"completed"})
                        and precheck_finished
                        and started <= precheck_finished <= finished
                    ):
                        jobs.extend(client.get_all_run_jobs(token, str(precheck_run["id"])))
    cutoff = finished - timedelta(days=1)
    removed = 0
    for address in sorted(unavailable_scan_ips(jobs, reasons)):
        check_cancelled()
        removed += delete_stale_local_asset(address, cutoff, run_id=run_id)
    return removed
