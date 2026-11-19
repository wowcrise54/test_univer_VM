from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from .. import db
from ..core import get_settings
from ..mpvm.common import parse_mpvm_datetime
from ..mpvm.scan_results import fetch_asset_grid_records
from ..mpvm_client import (
    MpVmApiError,
    MpVmClient,
    build_asset_resolution_pdql,
    parse_asset_removal_operation,
    status_strings,
)
from ..repositories.asset_cards.cards import stale_scan_card_version
from ..repositories.assets import list_scan_asset_removals, reserve_scan_asset_removal, update_scan_asset_removal
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


def stale_asset_id(row: dict[str, Any], address: str, cutoff: datetime) -> str | None:
    # A record shared by multiple IPs may still represent a reachable host.
    if row.get("IpAddress") != address or row.get("AllAddresses") != [address]:
        return None
    asset_id = row.get("AssetId")
    if not isinstance(asset_id, str) or not asset_id.strip():
        return None
    for key in ("CreationTime", "UpdateTime", "AuditTime", "PentestTime"):
        if key not in row:
            return None
        value = row[key]
        if value is None and key in {"AuditTime", "PentestTime"}:
            continue
        parsed = parse_mpvm_datetime(value)
        if parsed is None or parsed >= cutoff:
            return None
    return asset_id


def cleanup_stale_scan_assets(
    client: MpVmClient, token: str, run_id: str, scan: dict[str, Any], check_cancelled: Callable[[], None],
    *, connection_check: dict[str, Any] | None = None,
) -> int:
    settings = get_settings()
    reasons = {error.strip() for error in settings.scan_unreachable_errors.split(",") if error.strip()}
    if not reasons:
        return 0

    def finish(removal_id: int, operation_id: str, asset_id: str, version: str, address: str) -> None:
        check_cancelled()
        with host.BACKGROUND_REQUEST_SEMAPHORE:
            ok, _message, response = client.wait_for_asset_removal(
                token, operation_id, settings.scan_asset_removal_timeout_seconds,
                settings.scan_asset_removal_poll_seconds, cancel_event=host.scan_postprocess_cancel_event(run_id),
            )
        if not ok:
            check_cancelled()
            if response and parse_asset_removal_operation(response)[0]:
                update_scan_asset_removal(removal_id, operation_id, "failed", response)
            raise MpVmApiError(f"MP VM did not confirm stale asset removal for {address}.")
        db.delete_asset_card(asset_id, expected_last_seen=version)
        update_scan_asset_removal(removal_id, operation_id, "completed", response)

    resumed: set[str] = set()
    for operation in list_scan_asset_removals(run_id):
        finish(
            operation["id"], operation["operation_id"], operation["asset_id"],
            operation["card_version"], operation["address"],
        )
        resumed.add(operation["address"])
    finished = parse_mpvm_datetime(scan.get("confirmed_finished_at"))
    now = datetime.now(UTC)
    if not finished or finished > now or now - finished > timedelta(days=1):
        return len(resumed)
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
    removed = len(resumed)
    for address in sorted(unavailable_scan_ips(jobs, reasons) - resumed):
        check_cancelled()
        key = f"Stale scan asset: {run_id}/{address}"
        predicate = build_asset_resolution_pdql(address).split(" | ", 1)[0]
        query = (
            f"{predicate} | select(Host.@Id as AssetId, Host.IpAddress as IpAddress, "
            "Host.@IpAddresses as AllAddresses, Host.@CreationTime as CreationTime, "
            "Host.@UpdateTime as UpdateTime, Host.@AuditTime as AuditTime, Host.@PentestTime as PentestTime)"
        )
        with host.BACKGROUND_REQUEST_SEMAPHORE:
            pdql_token = client.create_pdql_token(token, query)
            rows, stats = fetch_asset_grid_records(
                client=client, token=token, pdql_token=pdql_token, limit=2, batch_size=2,
            )
        if len(rows) != 1 or stats["reportedTotal"] not in (None, 1):
            continue
        asset_id = stale_asset_id(rows[0], address, cutoff)
        if not asset_id or not (version := stale_scan_card_version(asset_id, address, cutoff)):
            continue
        check_cancelled()
        removal_id = reserve_scan_asset_removal(key, asset_id, version)
        if removal_id is None:
            continue
        with host.BACKGROUND_REQUEST_SEMAPHORE:
            if stale_scan_card_version(asset_id, address, cutoff) != version:
                update_scan_asset_removal(removal_id, None, "skipped")
                continue
            check_cancelled()
            operation_id = client.remove_assets(token, [asset_id])
        update_scan_asset_removal(removal_id, operation_id, "processing")
        finish(removal_id, operation_id, asset_id, version, address)
        removed += 1
    return removed
