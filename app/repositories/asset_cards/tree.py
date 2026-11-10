"""Repository for the asset card configuration tree: paths, labels, collection columns, and configuration details."""

from __future__ import annotations

import re
from typing import Any

import psycopg

from ...persistence import connection, schema
from ...persistence.codecs import clean_value, first_non_empty, json_loads, safe_int
from .cache import _hydrate_legacy_asset_card_cache
from .queries import _page_bounds


def asset_tree_parent_path(path: str | None) -> str | None:
    if not path or path == "asset":
        return None
    match = re.match(r"^(.*)\[\d+\]$", path)
    if match:
        return match.group(1)
    dot_index = path.rfind(".")
    return "asset" if dot_index <= 0 else path[:dot_index]


def asset_tree_depth(path: str | None) -> int:
    depth = 0
    current = asset_tree_parent_path(path)
    while current:
        depth += 1
        current = asset_tree_parent_path(current)
    return depth


def asset_path_key(path: str | None) -> str:
    text = str(path or "")
    match = re.match(r"^(.*)\[\d+\]$", text)
    normalized = match.group(1) if match else text
    return normalized.split(".")[-1] if normalized else ""


def labelize_asset_key(key: Any) -> str:
    labels = {
        "ipAddress": "IP address",
        "fqdn": "FQDN",
        "hostname": "Hostname",
        "hostType": "Host type",
        "macAddress": "MAC address",
        "osName": "OS name",
        "osVersion": "OS version",
        "isVirtual": "Virtual",
        "displayName": "Name",
        "vulnerabilityLevel": "Vulnerability level",
    }
    text = str(key or "")
    return labels.get(text) or re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ").strip().capitalize()


def asset_path_label(path: str | None) -> str:
    text = str(path or "")
    match = re.search(r"\[(\d+)\]$", text)
    if match:
        return f"Item {int(match.group(1)) + 1}"
    return labelize_asset_key(asset_path_key(text))


def asset_collection_meta(row: dict[str, Any]) -> str:
    fetched = row.get("fetched_count")
    total = row.get("reported_count")
    if fetched is None and total is None:
        return ""
    if total is not None and fetched != total:
        return f"{fetched or 0} / {total}"
    return str(first_non_empty(fetched, total, ""))


def _direct_child_filter_sql(parent_path: str) -> tuple[str, list[Any]]:
    if parent_path == "asset":
        prefix = "asset."
        rest_start = len(prefix) + 1
        return (
            """
            (
                (path LIKE %s AND POSITION('.' IN SUBSTRING(path FROM %s)) = 0 AND POSITION('[' IN SUBSTRING(path FROM %s)) = 0)
                OR (path NOT LIKE '%%.%%' AND path NOT LIKE '%%[%%' AND path <> 'asset')
            )
            """,
            [f"{prefix}%", rest_start, rest_start],
        )
    prefix = f"{parent_path}."
    rest_start = len(prefix) + 1
    return (
        """
        (
            (path LIKE %s AND POSITION('.' IN SUBSTRING(path FROM %s)) = 0 AND POSITION('[' IN SUBSTRING(path FROM %s)) = 0)
            OR path ~ %s
        )
        """,
        [f"{prefix}%", rest_start, rest_start, rf"^{re.escape(parent_path)}\[\d+\]$"],
    )


def _asset_tree_paths_with_children(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    paths: list[str],
) -> set[str]:
    if not paths:
        return set()
    rows = conn.execute(
        """
        SELECT DISTINCT candidate.path
        FROM UNNEST(%s::text[]) AS candidate(path)
        JOIN (
            SELECT path FROM asset_card_nodes WHERE asset_id = %s
            UNION ALL
            SELECT path FROM asset_card_collections WHERE asset_id = %s
        ) AS child
          ON child.path LIKE candidate.path || '.%%'
          OR child.path LIKE candidate.path || '[%%'
        WHERE child.path <> candidate.path
        """,
        (paths, asset_id, asset_id),
    ).fetchall()
    return {str(row["path"]) for row in rows}


def _asset_tree_row(raw: dict[str, Any], *, has_children: bool = False) -> dict[str, Any]:
    path = clean_value(raw.get("path")) or "asset"
    kind = clean_value(raw.get("kind")) or "node"
    parent_path = asset_tree_parent_path(path)
    if path != "asset" and parent_path is None:
        parent_path = "asset"
    label = first_non_empty(raw.get("title"), raw.get("display_name"), raw.get("name"), asset_path_label(path))
    subtitle = first_non_empty(raw.get("object_type"), raw.get("value_type"), raw.get("subtitle"), asset_path_key(path))
    meta = asset_collection_meta(raw) if kind == "collection" else ""
    return {
        "path": path,
        "parent_path": parent_path,
        "label": label,
        "subtitle": subtitle,
        "kind": kind,
        "meta": meta,
        "has_children": has_children,
        "depth": asset_tree_depth(path),
        "source": {
            "path": path,
            "type": first_non_empty(raw.get("object_type"), raw.get("value_type"), raw.get("kind")),
            "title": raw.get("title"),
            "name": raw.get("name"),
            "display_name": raw.get("display_name"),
        },
    }


def list_asset_card_configuration_tree(
    asset_id: str,
    *,
    parent_path: str | None = None,
    limit: int = 200,
) -> dict[str, Any] | None:
    schema.init_db()
    limit, _offset = _page_bounds(limit, 0, default=200, maximum=500)
    parent = clean_value(parent_path) or "asset"
    with connection.connect() as conn:
        card = conn.execute(
            "SELECT * FROM asset_cards WHERE asset_id = %s",
            (asset_id,),
        ).fetchone()
        if not card:
            return None
        _hydrate_legacy_asset_card_cache(conn, asset_id, dict(card))
        filter_sql, filter_params = _direct_child_filter_sql(parent)
        total_row = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM (
                SELECT path FROM asset_card_nodes WHERE asset_id = %s AND {filter_sql}
                UNION
                SELECT path FROM asset_card_collections WHERE asset_id = %s AND {filter_sql}
            ) AS children
            """,
            [asset_id, *filter_params, asset_id, *filter_params],
        ).fetchone()
        assert total_row is not None
        total = int(total_row["count"] or 0)
        rows = conn.execute(
            f"""
            SELECT *
            FROM (
                SELECT
                    path,
                    title,
                    display_name,
                    NULL::text AS name,
                    object_type,
                    NULL::text AS value_type,
                    NULL::integer AS reported_count,
                    NULL::integer AS fetched_count,
                    'node' AS kind
                FROM asset_card_nodes
                WHERE asset_id = %s AND {filter_sql}
                UNION ALL
                SELECT
                    path,
                    title,
                    NULL::text AS display_name,
                    name,
                    NULL::text AS object_type,
                    value_type,
                    reported_count,
                    fetched_count,
                    'collection' AS kind
                FROM asset_card_collections
                WHERE asset_id = %s AND {filter_sql}
            ) AS entries
            ORDER BY path, kind
            LIMIT %s
            """,
            [asset_id, *filter_params, asset_id, *filter_params, limit],
        ).fetchall()
        raw_rows = [dict(row) for row in rows]
        child_paths = _asset_tree_paths_with_children(
            conn,
            asset_id,
            [clean_value(row.get("path")) or "asset" for row in raw_rows],
        )
        entries: list[dict[str, Any]] = []
        if not clean_value(parent_path):
            root = json_loads(card.get("root_json"), {})
            root_label = first_non_empty(
                root.get("displayName") if isinstance(root, dict) else None,
                card.get("display_name"),
                card.get("hostname"),
                asset_id,
                "Asset",
            )
            entries.append({
                "path": "asset",
                "parent_path": None,
                "label": root_label,
                "subtitle": first_non_empty(root.get("type") if isinstance(root, dict) else None, card.get("asset_type"), "asset"),
                "kind": "root",
                "meta": "",
                "has_children": total > 0,
                "depth": 0,
                "source": {"path": "asset", "type": first_non_empty(card.get("asset_type"), "asset"), "title": root_label},
            })
        seen = {entry["path"] for entry in entries}
        for row in raw_rows:
            path = clean_value(row.get("path")) or "asset"
            entry = _asset_tree_row(row, has_children=path in child_paths)
            if entry["path"] in seen:
                continue
            entries.append(entry)
            seen.add(entry["path"])
        effective_total = total + (1 if not clean_value(parent_path) else 0)
        return {
            "asset_id": asset_id,
            "parent_path": None if not clean_value(parent_path) else parent,
            "rows": entries,
            "total": effective_total,
            "limit": limit,
            "offset": 0,
            "has_more": total > limit,
        }


def is_hidden_asset_detail_key(key: Any) -> bool:
    normalized = re.sub(r"[_-]", "", str(key or "")).lower()
    return normalized in {"type", "objectid"} or normalized.startswith("raw")


def is_verbose_asset_detail_value(value: Any) -> bool:
    return isinstance(value, dict | list)


def asset_collection_columns(items: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not items:
        return [{"key": "value", "title": "Value"}]
    if all(isinstance(item, dict) and "value" in item for item in items):
        return [{"key": "value", "title": "Value"}]
    preferred = ["ipAddress", "address", "hostname", "fqdn", "macAddress", "name", "displayName", "version", "status"]
    seen: set[str] = set()
    for item in items:
        data = item.get("data")
        if not isinstance(data, dict):
            data = {}
        for key, value in data.items():
            if not is_hidden_asset_detail_key(key) and not is_verbose_asset_detail_value(value):
                seen.add(str(key))
    ordered = sorted(seen, key=lambda item: (preferred.index(item) if item in preferred else 999, item.lower()))
    columns: list[dict[str, str]] = []
    if any(first_non_empty(item.get("display_name"), item.get("displayName")) for item in items):
        columns.append({"key": "display_name", "title": "Name"})
    if any(first_non_empty(item.get("object_id"), item.get("objectId")) for item in items):
        columns.append({"key": "object_id", "title": "Object ID"})
    if any(item.get("type") for item in items):
        columns.append({"key": "type", "title": "Type"})
    for key in ordered:
        if key not in {column["key"] for column in columns}:
            columns.append({"key": key, "title": labelize_asset_key(key)})
    if not columns:
        columns.append({"key": "display_name", "title": "Name"})
    return columns[:14]


def _asset_collection_detail_row(raw: dict[str, Any], index: int, columns: list[dict[str, str]]) -> dict[str, Any]:
    item = json_loads(raw.get("item_json"), {})
    if not isinstance(item, dict):
        item = {"value": item}
    data = item.get("data") if isinstance(item.get("data"), dict) else json_loads(raw.get("data_json"), {})
    if not isinstance(data, dict):
        data = {}
    row = {
        "key": first_non_empty(item.get("path"), raw.get("item_path"), raw.get("object_id"), index),
        "display_name": first_non_empty(item.get("display_name"), item.get("displayName"), raw.get("display_name")),
        "object_id": first_non_empty(item.get("object_id"), item.get("objectId"), raw.get("object_id")),
        "type": first_non_empty(item.get("type"), raw.get("object_type")),
        "value": item.get("value"),
    }
    for column in columns:
        key = column["key"]
        row[key] = first_non_empty(row.get(key), item.get(key), data.get(key))
    return row


def get_asset_card_configuration_detail(
    asset_id: str,
    *,
    path: str,
    kind: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any] | None:
    schema.init_db()
    limit, offset = _page_bounds(limit, offset, default=200, maximum=500)
    target_path = clean_value(path) or "asset"
    target_kind = clean_value(kind) or "node"
    with connection.connect() as conn:
        card_row = conn.execute(
            "SELECT * FROM asset_cards WHERE asset_id = %s",
            (asset_id,),
        ).fetchone()
        if not card_row:
            return None
            assert card_row is not None
        _hydrate_legacy_asset_card_cache(conn, asset_id, dict(card_row))
        if target_kind == "root":
            root = json_loads(card_row.get("root_json"), {})
            data = root.get("data") if isinstance(root, dict) else None
            if not isinstance(data, dict):
                data = {}
            base_values = [
                ("asset_id", "asset_id", card_row.get("asset_id")),
                ("display_name", "Name", first_non_empty(root.get("displayName") if isinstance(root, dict) else None, card_row.get("display_name"))),
                ("asset_type", "Type", first_non_empty(root.get("type") if isinstance(root, dict) else None, card_row.get("asset_type"))),
                ("hostname", "Hostname", first_non_empty(card_row.get("hostname"), data.get("hostname"))),
                ("fqdn", "FQDN", first_non_empty(card_row.get("fqdn"), data.get("fqdn"))),
                ("ip_address", "IP address", first_non_empty(card_row.get("ip_address"), data.get("ipAddress"))),
                ("os_name", "OS name", first_non_empty(card_row.get("os_name"), data.get("osName"))),
                ("os_version", "OS version", first_non_empty(card_row.get("os_version"), data.get("osVersion"))),
                ("vulnerability_level", "Vulnerability level", first_non_empty(card_row.get("vulnerability_level"), root.get("vulnerabilityLevel") if isinstance(root, dict) else None)),
            ]
            rows = [
                {"key": key, "path": f"asset.{key}", "title": title, "name": key, "value": value, "depth": 0}
                for key, title, value in base_values
                if value is not None and value != ""
            ]
            for key, value in data.items():
                if is_hidden_asset_detail_key(key) or is_verbose_asset_detail_value(value):
                    continue
                path_key = f"data.{key}"
                if any(row["name"] == key for row in rows):
                    continue
                rows.append({
                    "key": path_key,
                    "path": f"asset.{path_key}",
                    "title": labelize_asset_key(key),
                    "name": key,
                    "value": value,
                    "depth": 0,
                })
            total = len(rows)
            page_rows = rows[offset:offset + limit]
            return {
                "asset_id": asset_id,
                "path": target_path,
                "kind": target_kind,
                "columns": [
                    {"key": "path", "title": "Path"},
                    {"key": "title", "title": "Name"},
                    {"key": "value", "title": "Value"},
                ],
                "rows": page_rows,
                "layout": "properties",
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(page_rows) < total,
            }
        if target_kind == "collection":
            total_row = conn.execute(
                "SELECT COUNT(*) AS count FROM asset_card_collection_items WHERE asset_id = %s AND collection_path = %s",
                (asset_id, target_path),
            ).fetchone()
            assert total_row is not None
            total = int(total_row["count"] or 0)
            rows = conn.execute(
                """
                SELECT *
                FROM asset_card_collection_items
                WHERE asset_id = %s AND collection_path = %s
                ORDER BY item_index, id
                LIMIT %s OFFSET %s
                """,
                (asset_id, target_path, limit, offset),
            ).fetchall()
            raw_items = [dict(row) for row in rows]
            item_docs = [json_loads(row.get("item_json"), {}) for row in raw_items]
            item_docs = [item if isinstance(item, dict) else {"value": item} for item in item_docs]
            columns = asset_collection_columns(item_docs)
            detail_rows = [
                _asset_collection_detail_row(row, offset + index, columns)
                for index, row in enumerate(raw_items)
            ]
            return {
                "asset_id": asset_id,
                "path": target_path,
                "kind": target_kind,
                "columns": columns,
                "rows": detail_rows,
                "layout": "table",
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(detail_rows) < total,
            }

        prefix = f"{target_path}.%"
        item_prefix = f"{target_path}[%"
        where_sql = "asset_id = %s AND (path = %s OR path LIKE %s OR path LIKE %s)"
        params = (asset_id, target_path, prefix, item_prefix)
        total_row = conn.execute(
            f"SELECT COUNT(*) AS count FROM asset_card_table_rows WHERE {where_sql}",
            params,
        ).fetchone()
        assert total_row is not None
        total = int(total_row["count"] or 0)
        rows = conn.execute(
            f"""
            SELECT row_json, path, title, name, value_text, value_type, row_order
            FROM asset_card_table_rows
            WHERE {where_sql}
            ORDER BY row_order, path
            LIMIT %s OFFSET %s
            """,
            (*params, limit, offset),
        ).fetchall()
    detail_rows = []
    for index, raw in enumerate(rows):
        row = dict(raw)
        doc = json_loads(row.get("row_json"), {})
        if not isinstance(doc, dict):
            doc = {}
        detail_rows.append({
            "key": first_non_empty(doc.get("key"), f"{row.get('path')}-{row.get('row_order')}-{offset + index}"),
            "path": first_non_empty(doc.get("path"), row.get("path")),
            "title": first_non_empty(doc.get("title"), row.get("title"), row.get("name"), asset_path_label(row.get("path"))),
            "name": first_non_empty(doc.get("name"), row.get("name")),
            "type": first_non_empty(doc.get("type"), row.get("value_type")),
            "value": first_non_empty(doc.get("value"), row.get("value_text")),
            "depth": safe_int(doc.get("depth")) or 0,
        })
    return {
        "asset_id": asset_id,
        "path": target_path,
        "kind": target_kind,
        "columns": [
            {"key": "path", "title": "Path"},
            {"key": "title", "title": "Name"},
            {"key": "value", "title": "Value"},
        ],
        "rows": detail_rows,
        "layout": "properties",
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(detail_rows) < total,
    }
