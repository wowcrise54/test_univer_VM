"""Repository for asset card rows: upserts, quality, history, reads, deletion, and decoding."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ...diagnostics import log_event
from ...persistence import codecs, connection, locks, schema
from ...persistence.codecs import clean_value, first_non_empty, json_loads
from ...persistence.sql import validated_sort_sql
from .inventory import replace_asset_card_software_inventory
from .queries import canonical_asset_card_id
from .search_index import replace_asset_card_search_index
from .vulnerabilities import ASSET_CARD_BASE_COLUMNS, load_asset_card_structure, load_asset_card_vulnerabilities


def asset_card_exists(asset_id: str) -> bool:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute("SELECT 1 FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
    return row is not None


def upsert_asset_card(card: dict[str, Any]) -> dict[str, Any] | None:
    schema.init_db()
    write_started = datetime.now(UTC)
    root = card.get("root")
    if not isinstance(root, dict):
        root = {}
    data = root.get("data")
    if not isinstance(data, dict):
        data = {}
    remote_asset_id = clean_value(first_non_empty(card.get("asset_id"), root.get("objectId")))
    if not remote_asset_id:
        return None

    fqdn = clean_value(data.get("fqdn"))
    hostname = clean_value(data.get("hostname"))
    ip_address = clean_value(data.get("ipAddress"))

    current = codecs.now_utc()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        asset_id = canonical_asset_card_id(
            conn,
            remote_asset_id=remote_asset_id,
            fqdn=fqdn,
            hostname=hostname,
            ip_address=ip_address,
        )
        row = conn.execute(
            """
            INSERT INTO asset_cards (
                asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp, asset_token,
                root_json, metadata_json, nodes_json, collections_json, table_rows_json,
                vulnerabilities_json, stats_json, raw_card_json, first_seen, last_seen
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(asset_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                asset_type = EXCLUDED.asset_type,
                fqdn = EXCLUDED.fqdn,
                hostname = EXCLUDED.hostname,
                ip_address = EXCLUDED.ip_address,
                os_name = EXCLUDED.os_name,
                os_version = EXCLUDED.os_version,
                vulnerability_level = EXCLUDED.vulnerability_level,
                token_timestamp = EXCLUDED.token_timestamp,
                asset_token = EXCLUDED.asset_token,
                root_json = EXCLUDED.root_json,
                metadata_json = EXCLUDED.metadata_json,
                nodes_json = EXCLUDED.nodes_json,
                collections_json = EXCLUDED.collections_json,
                table_rows_json = EXCLUDED.table_rows_json,
                vulnerabilities_json = EXCLUDED.vulnerabilities_json,
                stats_json = EXCLUDED.stats_json,
                raw_card_json = EXCLUDED.raw_card_json,
                last_seen = EXCLUDED.last_seen
            RETURNING
                id, asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp,
                stats_json, first_seen, last_seen
            """,
            (
                asset_id,
                clean_value(first_non_empty(card.get("display_name"), root.get("displayName"))),
                clean_value(first_non_empty(card.get("asset_type"), root.get("type"))),
                fqdn,
                hostname,
                ip_address,
                clean_value(data.get("osName")),
                clean_value(data.get("osVersion")),
                clean_value(first_non_empty(card.get("vulnerability_level"), root.get("vulnerabilityLevel"))),
                card.get("timeline_timestamp"),
                clean_value(card.get("timeline_token")),
                json.dumps(root, ensure_ascii=False),
                json.dumps(card.get("metadata") or {}, ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("nodes") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("collections") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("table_rows") or []), ensure_ascii=False),
                json.dumps(strip_asset_card_raw(card.get("vulnerabilities") or {}), ensure_ascii=False),
                json.dumps(card.get("stats") or {}, ensure_ascii=False),
                "{}",
                current,
                current,
            ),
        ).fetchone()
        from .cache import replace_asset_card_cache

        replace_asset_card_cache(conn, asset_id, card, current)
        replace_asset_card_search_index(conn, asset_id, card, current)
        replace_asset_card_software_inventory(conn, asset_id, card, current)
        save_duration_ms = round((datetime.now(UTC) - write_started).total_seconds() * 1000, 2)
        stats = card.setdefault("stats", {})
        if isinstance(stats, dict):
            stats["save_duration_ms"] = save_duration_ms
            conn.execute(
                "UPDATE asset_cards SET stats_json = %s WHERE asset_id = %s",
                (json.dumps(stats, ensure_ascii=False), asset_id),
            )
    result = decode_asset_card_summary(dict(row)) if row else None
    if result:
        record_asset_card_history(result, card)
    log_event(
        "database",
        "db.write.completed",
        asset_id=asset_id,
        operation="upsert_asset_card",
        duration_ms=save_duration_ms,
        node_count=len(card.get("nodes") or []),
        collection_count=len(card.get("collections") or []),
        table_row_count=len(card.get("table_rows") or []),
    )
    return result


def asset_card_quality(card: dict[str, Any]) -> dict[str, Any]:
    stats = card.get("stats")
    if not isinstance(stats, dict):
        stats = {}
    warnings = stats.get("warnings")
    if not isinstance(warnings, list):
        warnings = []
    http = stats.get("http")
    if not isinstance(http, dict):
        http = {}
    errors = int(http.get("errors") or 0)
    score = max(0, 100 - min(70, len(warnings) * 5) - min(30, errors * 10))
    return {"score": score, "status": "good" if score >= 90 else "warning" if score >= 60 else "poor", "warning_count": len(warnings), "http_error_count": errors}


def record_asset_card_history(summary: dict[str, Any], card: dict[str, Any]) -> None:
    asset_id = str(summary.get("asset_id") or "")
    if not asset_id:
        return
    compact = {k: summary.get(k) for k in ("display_name", "asset_type", "fqdn", "hostname", "ip_address", "os_name", "os_version", "vulnerability_level")}
    compact.update({k: len(card.get(k) or []) for k in ("nodes", "collections", "table_rows")})
    quality = asset_card_quality(card)
    with connection.connect() as conn:
        previous = conn.execute("SELECT summary_json FROM asset_card_history WHERE asset_id=%s ORDER BY captured_at DESC LIMIT 1", (asset_id,)).fetchone()
        before = json_loads(previous["summary_json"], {}) if previous else {}
        changes = [{"field": k, "before": before.get(k), "after": v} for k, v in compact.items() if k in before and before.get(k) != v]
        conn.execute("INSERT INTO asset_card_history (asset_id,captured_at,quality_json,changes_json,summary_json) VALUES (%s,%s,%s,%s,%s)", (asset_id, codecs.now_utc(), json.dumps(quality), json.dumps(changes, ensure_ascii=False), json.dumps(compact, ensure_ascii=False)))
    log_event("database", "asset_card.history_recorded", asset_id=asset_id, quality=quality, change_count=len(changes))


def get_asset_card_history(asset_id: str, limit: int = 20) -> list[dict[str, Any]]:
    with connection.connect() as conn:
        rows = conn.execute("SELECT captured_at,quality_json,changes_json,summary_json FROM asset_card_history WHERE asset_id=%s ORDER BY captured_at DESC LIMIT %s", (asset_id, max(1, min(limit, 100)))).fetchall()
    return [{"captured_at": r["captured_at"], "quality": json_loads(r["quality_json"], {}), "changes": json_loads(r["changes_json"], []), "summary": json_loads(r["summary_json"], {})} for r in rows]


def delete_asset_card(asset_id: str) -> bool:
    schema.init_db()
    with connection.connect() as conn:
        locks._lock_vulnerability_passport_writes(conn)
        row = conn.execute(
            "DELETE FROM asset_cards WHERE asset_id = %s RETURNING asset_id",
            (asset_id,),
        ).fetchone()
    return row is not None


def is_asset_card_cache_empty(cache: dict[str, Any] | None) -> bool:
    if not isinstance(cache, dict):
        return True
    return not any(cache.get(key) for key in ("nodes", "collections", "table_rows"))


def list_asset_cards(
    *,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str | None = None,
) -> dict[str, Any]:
    schema.init_db()
    filters: list[str] = []
    params: list[Any] = []
    if q:
        like = f"%{q}%"
        filters.append(
            """
            (
                asset_id ILIKE %s OR display_name ILIKE %s OR asset_type ILIKE %s OR
                fqdn ILIKE %s OR hostname ILIKE %s OR ip_address ILIKE %s OR
                os_name ILIKE %s OR os_version ILIKE %s
            )
            """
        )
        params.extend([like, like, like, like, like, like, like, like])
    where = "WHERE " + " AND ".join(filters) if filters else ""
    limit = max(1, min(limit, 50000))
    offset = max(0, offset)
    sort_expression, direction = validated_sort_sql(
        sort_by,
        sort_dir,
        {"display_name": "LOWER(display_name)", "ip_address": "LOWER(ip_address)", "fqdn": "LOWER(fqdn)", "os_name": "LOWER(os_name)", "asset_type": "LOWER(asset_type)", "vulnerability_level": "LOWER(vulnerability_level)", "last_seen": "last_seen"},
        default="last_seen",
    )
    if sort_by is None:
        direction = "DESC"

    with connection.connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM asset_cards {where}", params).fetchone()
        assert total_row is not None
        rows = conn.execute(
            f"""
            SELECT
                id, asset_id, display_name, asset_type, fqdn, hostname, ip_address,
                os_name, os_version, vulnerability_level, token_timestamp,
                stats_json, first_seen, last_seen
            FROM asset_cards
            {where}
            ORDER BY {sort_expression} {direction} NULLS LAST, asset_id ASC
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
    return {
        "total": int(total_row["count"] or 0),
        "rows": [decode_asset_card_summary(dict(row)) for row in rows],
        "limit": limit,
        "offset": offset,
    }


def get_asset_card(asset_id: str) -> dict[str, Any] | None:
    schema.init_db()
    from .cache import load_asset_card_cache, replace_asset_card_cache

    with connection.connect() as conn:
        row = conn.execute("SELECT * FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
        cache = load_asset_card_cache(conn, asset_id) if row else None
        if row and is_asset_card_cache_empty(cache):
            legacy_card = decode_asset_card(dict(row))
            replace_asset_card_cache(conn, asset_id, legacy_card, codecs.now_utc())
            cache = load_asset_card_cache(conn, asset_id)
    card = decode_asset_card(dict(row), cache=cache) if row else None
    if card:
        card["loaded_sections"] = ["summary", "configuration", "vulnerabilities"]
    return card


def get_asset_card_section(asset_id: str, section: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            f"SELECT {ASSET_CARD_BASE_COLUMNS} FROM asset_cards WHERE asset_id = %s",
            (asset_id,),
        ).fetchone()
        if not row:
            return None
        cache: dict[str, Any] = {}
        loaded_sections = ["summary"]
        if section == "configuration":
            cache.update(load_asset_card_structure(conn, asset_id))
            cache["vulnerabilities"] = {}
            loaded_sections.append("configuration")
        elif section == "vulnerabilities":
            cache["vulnerabilities"] = load_asset_card_vulnerabilities(conn, asset_id)
            loaded_sections.append("vulnerabilities")
    card = decode_asset_card(dict(row), cache=cache)
    if section == "summary":
        for key in ("metadata", "nodes", "collections", "table_rows", "vulnerabilities"):
            card.pop(key, None)
    elif section == "configuration":
        card.pop("vulnerabilities", None)
    elif section == "vulnerabilities":
        for key in ("metadata", "nodes", "collections", "table_rows"):
            card.pop(key, None)
    card["loaded_sections"] = loaded_sections
    return card


def get_asset_card_summary(asset_id: str) -> dict[str, Any] | None:
    return get_asset_card_section(asset_id, "summary")


def decode_asset_card(row: dict[str, Any], cache: dict[str, Any] | None = None) -> dict[str, Any]:
    root = json_loads(row.get("root_json"), {})
    metadata = json_loads(row.get("metadata_json"), {})
    cached_nodes = cache.get("nodes") if isinstance(cache, dict) else None
    cached_collections = cache.get("collections") if isinstance(cache, dict) else None
    cached_table_rows = cache.get("table_rows") if isinstance(cache, dict) else None
    cached_vulnerabilities = cache.get("vulnerabilities") if isinstance(cache, dict) else None
    nodes = cached_nodes if cached_nodes else json_loads(row.get("nodes_json"), [])
    collections = cached_collections if cached_collections else json_loads(row.get("collections_json"), [])
    table_rows = cached_table_rows if cached_table_rows else json_loads(row.get("table_rows_json"), [])
    vulnerabilities = cached_vulnerabilities if isinstance(cached_vulnerabilities, dict) else json_loads(row.get("vulnerabilities_json"), {})
    stats = json_loads(row.get("stats_json"), {})
    return {
        "id": row.get("id"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "asset_type": row.get("asset_type"),
        "fqdn": row.get("fqdn"),
        "hostname": row.get("hostname"),
        "ip_address": row.get("ip_address"),
        "os_name": row.get("os_name"),
        "os_version": row.get("os_version"),
        "vulnerability_level": row.get("vulnerability_level"),
        "token_timestamp": row.get("token_timestamp"),
        "root": root if isinstance(root, dict) else {},
        "metadata": metadata if isinstance(metadata, dict) else {},
        "nodes": strip_asset_card_raw(nodes) if isinstance(nodes, list) else [],
        "collections": strip_asset_card_raw(collections) if isinstance(collections, list) else [],
        "table_rows": strip_asset_card_raw(table_rows) if isinstance(table_rows, list) else [],
        "vulnerabilities": strip_asset_card_raw(vulnerabilities) if isinstance(vulnerabilities, dict) else {},
        "stats": stats if isinstance(stats, dict) else {},
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def strip_asset_card_raw(value: Any) -> Any:
    raw_keys = {"raw", "raw_card", "raw_record", "raw_detail", "raw_value"}
    if isinstance(value, list):
        return [strip_asset_card_raw(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_asset_card_raw(item)
            for key, item in value.items()
            if key not in raw_keys
        }
    return value


def decode_asset_card_summary(row: dict[str, Any]) -> dict[str, Any]:
    stats = json_loads(row.get("stats_json"), {})
    return {
        "id": row.get("id"),
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "asset_type": row.get("asset_type"),
        "fqdn": row.get("fqdn"),
        "hostname": row.get("hostname"),
        "ip_address": row.get("ip_address"),
        "os_name": row.get("os_name"),
        "os_version": row.get("os_version"),
        "vulnerability_level": row.get("vulnerability_level"),
        "token_timestamp": row.get("token_timestamp"),
        "stats": stats if isinstance(stats, dict) else {},
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }
