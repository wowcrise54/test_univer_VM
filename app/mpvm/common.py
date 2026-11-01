from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException

from ..mpvm_client import MpVmApiError


def as_dict(value: Any) -> dict[str, Any]:
    """Return value when it is a dict, otherwise an empty dict (typed for mypy)."""
    return value if isinstance(value, dict) else {}


def parse_mpvm_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        try:
            return datetime.fromtimestamp(number, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def simplify_named_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        result.append(
            {
                "id": item.get("id") or item.get("uuid") or item.get("value"),
                "name": item.get("name") or item.get("displayName") or item.get("title") or item.get("id"),
                "raw": item,
            }
        )
    return result


def extract_collection_items(response: Any) -> list[Any]:
    if isinstance(response, dict):
        items = response.get("items")
        if isinstance(items, list):
            return items
        data = response.get("data")
        if isinstance(data, list):
            return data
    if isinstance(response, list):
        return response
    return []


def extract_collection_count(response: Any) -> int | None:
    if not isinstance(response, dict):
        return None
    for key in ("count", "total", "totalCount", "totalItems"):
        try:
            if response.get(key) is not None:
                return int(response[key])
        except (TypeError, ValueError):
            return None
    return None


def number_or_none(value: Any) -> int | float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def number_or_zero(value: Any) -> int | float:
    return number_or_none(value) or 0


def normalize_asset_metadata_key(value: Any) -> str:
    return str(value or "").replace("_", "").replace("-", "").lower()


def json_dumps_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def normalize_boolean(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def first_present(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, MpVmApiError) and exc.status_code == 429:
        headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
        return HTTPException(
            status_code=429,
            detail={
                "code": "MPVM_RATE_LIMITED",
                "message": str(exc),
                "operator_message": "MP VM ограничил частоту запросов. Повторите позже.",
                "component": "mpvm",
                "retryable": True,
            },
            headers=headers,
        )
    return HTTPException(status_code=502, detail=str(exc))
