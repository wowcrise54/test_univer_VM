from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from typing import Any

from ..mpvm_client import MpVmApiError, MpVmClient, build_asset_resolution_pdql
from .asset_metadata import asset_value_to_text, normalize_asset_candidate_record
from .common import first_present, parse_mpvm_datetime


def successful_scan_target_jobs(jobs: list[dict[str, Any]]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for job in jobs:
        job_id = str(job.get("id") or "") or None
        raw_targets = job.get("targets")
        targets = raw_targets if isinstance(raw_targets, list) else [raw_targets] if isinstance(raw_targets, str) else []
        for target in targets:
            value = str(target or "").strip()
            if value and value not in result:
                result[value] = job_id
    return result


def query_scanned_asset_records(client: MpVmClient, token: str, target: str) -> list[dict[str, Any]]:
    pdql_token = client.create_pdql_token(token, build_asset_resolution_pdql(target))
    records, _summary = fetch_asset_grid_records(
        client=client,
        token=token,
        pdql_token=pdql_token,
        limit=50000,
        batch_size=5000,
    )
    return records


def normalize_scanned_asset_record(record: dict[str, Any], *, target: str, mp_job_id: str | None) -> dict[str, Any]:
    candidate = normalize_asset_candidate_record(record)
    raw_display_name = candidate.get("display_name") or first_present(
        record.get("Fqdn"),
        record.get("Hostname"),
        target,
    )
    return {
        "asset_id": candidate.get("asset_id"),
        "display_name": asset_value_to_text(raw_display_name),
        "target": target,
        "mp_job_id": mp_job_id,
    }


def scanned_asset_record_matches(record: dict[str, Any], target: str) -> bool:
    ip_values = [
        record.get("IpAddress"),
        record.get("Host.IpAddress"),
        record.get("IP"),
    ]
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return any(_ip_in_network(value, network) for value in ip_values)
        address = ipaddress.ip_address(target)
        return any(_ip_equals(value, address) for value in ip_values)
    except ValueError:
        names = [record.get("Fqdn"), record.get("Host.Fqdn"), record.get("Hostname"), record.get("Host.Hostname")]
        return any(str(value or "").rstrip(".").casefold() == target.rstrip(".").casefold() for value in names)


def scanned_asset_record_is_current(record: dict[str, Any], run_started_at: str) -> bool:
    threshold = parse_mpvm_datetime(run_started_at)
    if threshold is None:
        return False
    values = [
        record.get("UpdateTime"),
        record.get("CreationTime"),
        record.get("Host.@UpdateTime"),
        record.get("Host.@CreationTime"),
    ]
    return any((parsed := parse_mpvm_datetime(value)) is not None and parsed >= threshold for value in values)


def _ip_equals(value: Any, address: ipaddress._BaseAddress) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()) == address
    except ValueError:
        return False


def _ip_in_network(value: Any, network: ipaddress._BaseNetwork) -> bool:
    try:
        return ipaddress.ip_address(str(value).strip()) in network
    except ValueError:
        return False


def fetch_asset_grid_records(
    *,
    client: MpVmClient,
    token: str,
    pdql_token: str,
    limit: int | None,
    batch_size: int,
    progress_callback: Callable[[int, int | None], None] | None = None,
    retry_callback: Callable[[int, int | None, int, int], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    batches: list[dict[str, Any]] = []
    first_response: dict[str, Any] | None = None
    expected_total: int | None = None
    offset = 0

    while limit is None or offset < limit:
        current_limit = batch_size if limit is None else min(batch_size, limit - offset)
        for attempt in range(4):
            try:
                raw_response = client.fetch_asset_grid_data(
                    token,
                    pdql_token,
                    limit=current_limit,
                    offset=offset,
                )
                break
            except MpVmApiError as exc:
                if exc.status_code != 404 or "non-JSON response" not in str(exc):
                    raise
                if attempt == 3:
                    raise MpVmApiError(
                        f"MP VM вернул 404 при чтении assets_grid/data: offset={offset}, "
                        f"limit={current_limit}, получено до ошибки {len(records)} записей. "
                        "Страница недоступна после 3 повторов; проверьте журнал MP VM "
                        "или прокси для этого offset. Неполная выгрузка не сохранена.",
                        status_code=404,
                    ) from exc
                if retry_callback:
                    retry_callback(len(records), expected_total, offset, attempt + 1)
                time.sleep(2**attempt)
        if first_response is None:
            first_response = raw_response
        batch_records = extract_asset_grid_records(raw_response)
        batch_total = extract_asset_grid_total(raw_response)
        if batch_total is not None:
            expected_total = batch_total
        records.extend(batch_records)
        if progress_callback:
            progress_callback(len(records), expected_total)
        batches.append(
            {
                "offset": offset,
                "limit": current_limit,
                "records": len(batch_records),
                "reported_total": batch_total,
            }
        )
        if len(batch_records) < current_limit:
            break
        offset += current_limit
        if expected_total is not None and len(records) >= expected_total:
            break

    summary: dict[str, Any] = {
        "pdqlToken": pdql_token,
        "requestedLimit": limit,
        "batchSize": batch_size,
        "recordCount": len(records),
        "reportedTotal": expected_total,
        "batches": batches,
    }
    if not records and first_response is not None:
        summary["firstResponse"] = first_response
    return records, summary


def extract_asset_grid_records(raw_response: Any) -> list[dict[str, Any]]:
    if isinstance(raw_response, list):
        return [item if isinstance(item, dict) else {"value": item} for item in raw_response]
    if not isinstance(raw_response, dict):
        return []

    for key in ("records", "items", "rows", "values"):
        value = raw_response.get(key)
        if isinstance(value, list):
            return [item if isinstance(item, dict) else {"value": item} for item in value]

    data = raw_response.get("data")
    if isinstance(data, list):
        return [item if isinstance(item, dict) else {"value": item} for item in data]
    if isinstance(data, dict):
        return extract_asset_grid_records(data)

    return []


def extract_asset_grid_total(raw_response: Any) -> int | None:
    if not isinstance(raw_response, dict):
        return None
    for key in ("totalCount", "total", "count"):
        value = raw_response.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    data = raw_response.get("data")
    if isinstance(data, dict):
        return extract_asset_grid_total(data)
    return None
