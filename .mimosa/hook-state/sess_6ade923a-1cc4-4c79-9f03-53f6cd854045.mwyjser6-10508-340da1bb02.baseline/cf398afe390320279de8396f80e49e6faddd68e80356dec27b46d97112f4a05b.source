"""Value codecs: CSV parsing, timestamps and scalar type conversion for stored data."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")

def make_csv_reader(csv_text: str) -> csv.DictReader:
    if not csv_text.strip():
        return csv.DictReader(io.StringIO(""))
    try:
        dialect = csv.Sniffer().sniff(csv_text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return csv.DictReader(io.StringIO(csv_text), dialect=dialect)

def normalize_row(row: dict[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in row.items():
        clean_key = (key or "").strip("\ufeff")
        normalized[clean_key] = clean_value(value) or ""
    return normalized

def first_value(row: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = clean_value(row.get(key))
        if value:
            return value
    return None

def clean_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None

def text_parameter(value: Any) -> str | None:
    """Return a psycopg-safe text value while preserving structured context."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list | tuple):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)

def safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def safe_decimal(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def decimal_to_number(value: Any) -> int | float | None:
    number = safe_decimal(value)
    if number is None:
        return None
    return int(number) if number.is_integer() else number

def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None

def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)

def json_loads(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, dict | list):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback
