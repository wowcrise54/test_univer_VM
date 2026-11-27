"""Repository for the asset card search index: leaf rows, index replacement, and searchable field listing."""

from __future__ import annotations

import re
from typing import Any

import psycopg

from ...persistence import connection, schema
from ...persistence.codecs import clean_value, first_non_empty
from ...persistence.sql import copy_rows, rows_to_dicts
from .cache import asset_card_search_index_coverage
from .inventory import asset_path_leaf

ASSET_SEARCH_HIDDEN_KEYS = {
    "raw", "rawcard", "rawrecord", "rawdetail", "rawvalue", "objectid", "type",
}


def is_hidden_asset_search_key(key: Any) -> bool:
    normalized = re.sub(r"[_-]", "", str(key or "")).lower()
    return normalized in ASSET_SEARCH_HIDDEN_KEYS or normalized.startswith("raw")


def asset_search_leaf_rows(
    value: Any,
    *,
    entity_path: str,
    field_path: str,
    field_name: str,
    depth: int = 0,
) -> list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]]:
    if depth > 8 or value is None:
        return []
    if isinstance(value, dict):
        if "hasItems" in value and isinstance(value.get("hasItems"), bool):
            value = value["hasItems"]
        else:
            rows: list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]] = []
            nested = value.get("data")
            if not isinstance(nested, dict):
                nested = value
            for key, child in nested.items():
                if is_hidden_asset_search_key(key):
                    continue
                child_path = f"{field_path}.{key}" if field_path else str(key)
                rows.extend(asset_search_leaf_rows(
                    child,
                    entity_path=entity_path,
                    field_path=child_path,
                    field_name=str(key),
                    depth=depth + 1,
                ))
            return rows
    if isinstance(value, list):
        rows = []
        for item in value:
            rows.extend(asset_search_leaf_rows(
                item,
                entity_path=entity_path,
                field_path=field_path,
                field_name=field_name,
                depth=depth + 1,
            ))
        return rows
    if isinstance(value, bool):
        return [(entity_path, field_path, field_name, "boolean", "true" if value else "false", "true" if value else "false", None, value)]
    if isinstance(value, int | float) and not isinstance(value, bool):
        return [(entity_path, field_path, field_name, "number", str(value), str(value), value, None)]
    text = clean_value(value)
    if text is None:
        return []
    return [(entity_path, field_path, field_name, "text", text, text.lower(), None, None)]


def build_asset_card_search_rows(card: dict[str, Any]) -> list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]]:
    root = card.get("root")
    if not isinstance(root, dict):
        root = {}
    root_data = root.get("data")
    if not isinstance(root_data, dict):
        root_data = {}
    rows: list[tuple[str, str, str, str, str | None, str | None, Any, bool | None]] = []
    summary = {
        "assetId": clean_value(card.get("asset_id")),
        "displayName": first_non_empty(card.get("display_name"), root.get("displayName")),
        "assetType": first_non_empty(card.get("asset_type"), root.get("type")),
        "fqdn": first_non_empty(card.get("fqdn"), root_data.get("fqdn")),
        "hostname": first_non_empty(card.get("hostname"), root_data.get("hostname")),
        "ipAddress": first_non_empty(card.get("ip_address"), root_data.get("ipAddress")),
        "osName": first_non_empty(card.get("os_name"), root_data.get("osName")),
        "osVersion": first_non_empty(card.get("os_version"), root_data.get("osVersion")),
        "vulnerabilityLevel": first_non_empty(card.get("vulnerability_level"), root.get("vulnerabilityLevel")),
    }
    rows.extend(asset_search_leaf_rows(summary, entity_path="asset", field_path="asset", field_name="asset"))
    rows.extend(asset_search_leaf_rows(root_data, entity_path="asset", field_path="asset", field_name="asset"))
    for node in card.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        path = clean_value(node.get("path"))
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        if path:
            rows.extend(asset_search_leaf_rows(data, entity_path=path, field_path=path, field_name=asset_path_leaf(path)))
    for collection in card.get("collections") or []:
        if not isinstance(collection, dict):
            continue
        collection_path = clean_value(collection.get("path"))
        if not collection_path:
            continue
        for index, item in enumerate(collection.get("items") or []):
            item_doc = item if isinstance(item, dict) else {"value": item}
            entity_path = clean_value(item_doc.get("path")) or f"{collection_path}[{index}]"
            if isinstance(item_doc.get("data"), dict):
                value = item_doc["data"]
                field_path = collection_path
            elif "value" in item_doc:
                value = item_doc.get("value")
                field_path = collection_path
            else:
                value = {key: val for key, val in item_doc.items() if key not in {"path", "node"}}
                field_path = collection_path
            rows.extend(asset_search_leaf_rows(
                value,
                entity_path=entity_path,
                field_path=field_path,
                field_name=clean_value(collection.get("name")) or asset_path_leaf(collection_path),
            ))
    deduped = list(dict.fromkeys(rows))
    return deduped


def replace_asset_card_search_index(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    card: dict[str, Any],
    updated_at: str,
) -> int:
    conn.execute("DELETE FROM asset_card_search_fields WHERE asset_id = %s", (asset_id,))
    rows = build_asset_card_search_rows(card)
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_search_fields",
            (
                "asset_id", "entity_path", "field_path", "field_name", "value_type",
                "value_text", "value_text_normalized", "value_number", "value_boolean", "updated_at",
            ),
            [(asset_id, *row, updated_at) for row in rows],
        )
    # Per-asset digest of the field catalog: listing fields would otherwise
    # aggregate the whole (tens of millions of rows) search table per request.
    conn.execute("DELETE FROM asset_card_search_field_catalog WHERE asset_id = %s", (asset_id,))
    catalog: dict[tuple[str, str], list[str | None]] = {}
    for _entity, field_path, field_name, value_type, value_text, *_rest in rows:
        entry = catalog.setdefault((field_path, value_type), [field_name, value_text])
        if field_name < str(entry[0] or ""):
            entry[0] = field_name
        if value_text is not None and (entry[1] is None or value_text < entry[1]):
            entry[1] = value_text
    if catalog:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO asset_card_search_field_catalog
                    (asset_id, field_path, value_type, field_name, sample_value)
                VALUES (%s, %s, %s, %s, %s)
                """,
                [(asset_id, path, vtype, name, sample) for (path, vtype), (name, sample) in catalog.items()],
            )
    return len(rows)


def list_asset_card_search_fields(q: str | None = None, limit: int = 100) -> dict[str, Any]:
    schema.init_db()
    limit = max(1, min(500, int(limit)))
    params: list[Any] = []
    where = ""
    if q:
        needle = f"%{q.strip().lower()}%"
        where = "WHERE LOWER(field_path) LIKE %s OR LOWER(field_name) LIKE %s"
        params.extend([needle, needle])
    with connection.connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                field_path,
                MIN(field_name) AS field_name,
                value_type,
                COUNT(*) AS asset_count,
                MIN(sample_value) AS sample_value
            FROM asset_card_search_field_catalog
            {where}
            GROUP BY field_path, value_type
            ORDER BY field_path, value_type
            LIMIT %s
            """,
            [*params, limit],
        ).fetchall()
    return {"rows": rows_to_dicts(rows), **asset_card_search_index_coverage()}
