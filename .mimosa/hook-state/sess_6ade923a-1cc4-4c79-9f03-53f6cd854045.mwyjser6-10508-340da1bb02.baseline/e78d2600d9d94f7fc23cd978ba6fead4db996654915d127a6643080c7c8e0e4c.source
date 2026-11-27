from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from ..mpvm_client import MpVmApiError, MpVmClient
from .common import first_present

SCANNER_TASK_TEMPLATE_FIELDS = {
    "name",
    "description",
    "scope",
    "profile",
    "agents",
    "overrides",
    "include",
    "exclude",
    "hostDiscovery",
    "triggerParameters",
    "deniedScanSettings",
    "isFqdnPriority",
    "groups",
}


def extract_remote_scanner_task_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("items", "data", "rows", "records", "values", "content"):
        nested = value.get(key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
        if isinstance(nested, dict):
            rows = extract_remote_scanner_task_rows(nested)
            if rows:
                return rows
    return []


def normalize_remote_scanner_task_template(item: dict[str, Any]) -> dict[str, Any] | None:
    if item.get("isDeleted") is True or item.get("deleted") is True:
        return None
    raw_payload = item
    for key in ("payload", "configuration", "config", "scannerTask", "task"):
        nested = item.get(key)
        if isinstance(nested, dict):
            raw_payload = nested
            break
    payload = {key: copy.deepcopy(raw_payload[key]) for key in SCANNER_TASK_TEMPLATE_FIELDS if key in raw_payload}
    payload.setdefault("name", str(raw_payload.get("displayName") or item.get("name") or item.get("displayName") or "Scanner task"))
    payload.setdefault("description", str(raw_payload.get("description") or item.get("description") or ""))
    if not payload.get("scope"):
        payload["scope"] = raw_payload.get("scopeId") or item.get("scopeId")
    if not payload.get("profile"):
        payload["profile"] = raw_payload.get("profileId") or item.get("profileId")
    for key in ("scope", "profile"):
        if isinstance(payload.get(key), dict):
            payload[key] = payload[key].get("id") or payload[key].get("uuid")
    if not payload.get("scope") or not payload.get("profile"):
        return None
    task_id = first_present(
        item.get("id"),
        item.get("taskId"),
        item.get("task_id"),
        item.get("uuid"),
        raw_payload.get("id"),
        raw_payload.get("taskId"),
    )
    if not task_id:
        return None
    name = str(payload.get("name") or "")
    if name.casefold().startswith("asset card refresh "):
        return None
    return {"mp_task_id": str(task_id), "name": name or str(task_id), "payload": payload, "source": "remote"}


def remote_scanner_task_templates(
    client: MpVmClient,
    token: str,
    *,
    main_filter: str | None = None,
    max_tasks: int = 200,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page_size = 50
    for offset in range(0, max_tasks, page_size):
        response = client.list_remote_scanner_tasks(
            token,
            offset=offset,
            limit=min(page_size, max_tasks - offset),
            main_filter=main_filter,
        )
        page = extract_remote_scanner_task_rows(response)
        for item in page:
            template = normalize_remote_scanner_task_template(item)
            if template:
                rows.append(template)
        if len(page) < page_size:
            break
    return rows


def build_precheck_task_name(prefix: str, audit_task_name: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix} {audit_task_name} {stamp}"


def remote_scanner_task_exists(client: MpVmClient, token: str, task_id: str) -> bool:
    page_size = 50
    max_pages = 101
    for page_number in range(max_pages):
        response = client.list_remote_scanner_tasks(
            token,
            offset=page_number * page_size,
            limit=page_size,
        )
        if not is_remote_scanner_task_list_response(response):
            raise MpVmApiError("Unexpected remote scanner task list response while checking task existence.")
        rows = extract_remote_scanner_task_rows(response)
        for row in rows:
            if remote_scanner_task_row_is_deleted(row):
                continue
            if remote_scanner_task_row_id(row) == task_id:
                return True
        if len(rows) < page_size:
            return False
    raise MpVmApiError("Could not confirm scanner task absence after reading 5000 remote tasks.")


def is_remote_scanner_task_list_response(value: Any) -> bool:
    if isinstance(value, list):
        return True
    if not isinstance(value, dict):
        return False
    for key in ("items", "data", "rows", "records", "values", "content"):
        nested = value.get(key)
        if isinstance(nested, list):
            return True
        if isinstance(nested, dict) and is_remote_scanner_task_list_response(nested):
            return True
    return False


def remote_scanner_task_row_id(row: dict[str, Any]) -> str | None:
    sources = [row]
    for key in ("payload", "configuration", "config", "scannerTask", "task"):
        nested = row.get(key)
        if isinstance(nested, dict):
            sources.append(nested)
    for source in sources:
        for key in ("id", "taskId", "task_id", "uuid"):
            value = source.get(key)
            if value is not None:
                return str(value)
    return None


def remote_scanner_task_row_is_deleted(row: dict[str, Any]) -> bool:
    if row.get("isDeleted") is True or row.get("deleted") is True:
        return True
    return any(
        isinstance(row.get(key), dict)
        and (row[key].get("isDeleted") is True or row[key].get("deleted") is True)
        for key in ("payload", "configuration", "config", "scannerTask", "task")
    )
