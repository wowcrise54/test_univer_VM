"""Repository for asset card JSON cache: replacement, hydration of legacy caches, coverage metrics, and backfill batches."""

from __future__ import annotations

import json
from typing import Any

import psycopg

from ...diagnostics import log_event
from ...persistence import codecs, connection, locks, schema
from ...persistence.codecs import clean_value, json_loads, safe_decimal, safe_int
from ...persistence.sql import copy_rows
from .passport_links import reconcile_asset_card_vulnerability_passport_links


def replace_asset_card_cache(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    card: dict[str, Any],
    updated_at: str,
) -> None:
    from .cards import strip_asset_card_raw
    from .vulnerabilities import deduplicate_asset_card_vulnerability_findings, iter_asset_card_vulnerability_groups

    locks._lock_vulnerability_passport_writes(conn)
    conn.execute("DELETE FROM asset_card_table_rows WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_collection_items WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_collections WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_nodes WHERE asset_id = %s", (asset_id,))
    conn.execute("DELETE FROM asset_card_vulnerability_groups WHERE asset_id = %s", (asset_id,))

    nodes = [item for item in card.get("nodes") or [] if isinstance(item, dict)]
    collections = [item for item in card.get("collections") or [] if isinstance(item, dict)]
    table_rows = [item for item in card.get("table_rows") or [] if isinstance(item, dict)]

    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_nodes",
            (
                "asset_id", "path", "title", "display_name", "object_id", "object_type",
                "vulnerability_level", "data_json", "node_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(node.get("path")) or "",
                    clean_value(node.get("title")),
                    clean_value(node.get("display_name")),
                    clean_value(node.get("object_id")),
                    clean_value(node.get("type")),
                    clean_value(node.get("vulnerability_level")),
                    json.dumps(strip_asset_card_raw(node.get("data") or {}), ensure_ascii=False),
                    json.dumps(strip_asset_card_raw(node), ensure_ascii=False),
                    updated_at,
                )
                for node in nodes
                if clean_value(node.get("path"))
            ],
        )

        copy_rows(
            cur,
            "asset_card_collections",
            (
                "asset_id", "path", "name", "title", "value_type", "kind", "parent_type",
                "parent_object_id", "reported_count", "fetched_count", "truncated",
                "collection_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    clean_value(collection.get("path")) or "",
                    clean_value(collection.get("name")),
                    clean_value(collection.get("title")),
                    clean_value(collection.get("type")),
                    clean_value(collection.get("kind")),
                    clean_value(collection.get("parent_type")),
                    clean_value(collection.get("parent_object_id")),
                    safe_int(collection.get("count")),
                    safe_int(collection.get("fetched_count")),
                    bool(collection.get("truncated")),
                    json.dumps(strip_asset_card_raw({k: v for k, v in collection.items() if k != "items"}), ensure_ascii=False),
                    updated_at,
                )
                for collection in collections
                if clean_value(collection.get("path"))
            ],
        )

        item_rows: list[tuple[Any, ...]] = []
        for collection in collections:
            collection_path = clean_value(collection.get("path"))
            if not collection_path:
                continue
            items = collection.get("items")
            if not isinstance(items, list):
                items = []
            for index, item in enumerate(items):
                item_doc = item if isinstance(item, dict) else {"path": f"{collection_path}[{index}]", "value": item}
                data = item_doc.get("data") if isinstance(item_doc.get("data"), dict) else {}
                item_rows.append(
                    (
                        asset_id,
                        collection_path,
                        index,
                        clean_value(item_doc.get("path")) or f"{collection_path}[{index}]",
                        clean_value(item_doc.get("display_name")),
                        clean_value(item_doc.get("object_id")),
                        clean_value(item_doc.get("type")),
                        clean_value(item_doc.get("vulnerability_level")),
                        json.dumps(strip_asset_card_raw(data), ensure_ascii=False),
                        json.dumps(strip_asset_card_raw(item_doc), ensure_ascii=False),
                        updated_at,
                    )
                )
        copy_rows(
            cur,
            "asset_card_collection_items",
            (
                "asset_id", "collection_path", "item_index", "item_path", "display_name",
                "object_id", "object_type", "vulnerability_level", "data_json", "item_json",
                "updated_at",
            ),
            item_rows,
        )

        copy_rows(
            cur,
            "asset_card_table_rows",
            (
                "asset_id", "row_order", "path", "name", "title", "value_text", "value_type",
                "kind", "parent_type", "parent_object_id", "row_json", "updated_at",
            ),
            [
                (
                    asset_id,
                    index,
                    clean_value(row.get("path")) or "",
                    clean_value(row.get("name")),
                    clean_value(row.get("title")),
                    clean_value(row.get("value")),
                    clean_value(row.get("type")),
                    clean_value(row.get("kind")),
                    clean_value(row.get("parent_type")),
                    clean_value(row.get("parent_object_id")),
                    json.dumps(strip_asset_card_raw(row), ensure_ascii=False),
                    updated_at,
                )
                for index, row in enumerate(table_rows)
                if clean_value(row.get("path"))
            ],
        )

    vulnerability_groups = iter_asset_card_vulnerability_groups(card.get("vulnerabilities"))
    group_rows = [
        (
            asset_id,
            group["source"],
            group["collection_type"],
            group["collection_id"],
            clean_value(group.get("name")),
            clean_value(group.get("level")),
            safe_int(group.get("vulnerabilities_count")) or 0,
            safe_decimal(group.get("cvss_score")),
            safe_int(group.get("order")) or 0,
            bool(group.get("truncated")),
            json.dumps(strip_asset_card_raw({key: value for key, value in group.items() if key != "items"}), ensure_ascii=False),
            updated_at,
        )
        for group in vulnerability_groups
    ]
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_vulnerability_groups",
            (
                "asset_id", "source_type", "collection_type", "collection_id", "name", "severity",
                "vulnerability_count", "cvss_score", "group_order", "truncated", "group_json", "updated_at",
            ),
            group_rows,
        )

    stored_groups = conn.execute(
        """
        SELECT id, source_type, collection_type, collection_id
        FROM asset_card_vulnerability_groups
        WHERE asset_id = %s
        """,
        (asset_id,),
    ).fetchall()
    group_ids = {
        (row["source_type"], row["collection_type"], row["collection_id"]): int(row["id"])
        for row in stored_groups
    }
    finding_rows: list[tuple[Any, ...]] = []
    unique_findings, duplicate_finding_count = deduplicate_asset_card_vulnerability_findings(
        vulnerability_groups
    )
    for group, finding in unique_findings:
        group_id = group_ids.get((group["source"], group["collection_type"], group["collection_id"]))
        if group_id is None:
            continue
        finding_rows.append(
            (
                asset_id,
                group_id,
                clean_value(finding.get("vulnerability_instance_id")),
                clean_value(finding.get("vulnerability_id")),
                clean_value(finding.get("object_id")),
                clean_value(finding.get("cve_name")),
                clean_value(finding.get("name")),
                clean_value(finding.get("level")),
                safe_decimal(finding.get("cvss_score")),
                clean_value(finding.get("description_key")),
                json.dumps(strip_asset_card_raw(finding), ensure_ascii=False),
                updated_at,
            )
        )
    if duplicate_finding_count:
        log_event(
            "database",
            "asset_card.vulnerabilities.deduplicated",
            level=30,
            asset_id=asset_id,
            duplicate_count=duplicate_finding_count,
            retained_count=len(finding_rows),
        )
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_vulnerabilities",
            (
                "asset_id", "group_id", "vulnerability_instance_id", "vulnerability_id",
                "object_id", "cve_name", "name", "severity", "cvss_score", "description_key",
                "vulnerability_json", "updated_at",
            ),
            finding_rows,
        )

    reconcile_asset_card_vulnerability_passport_links(conn, None, updated_at, asset_id=asset_id)


def load_asset_card_cache(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
) -> dict[str, Any]:
    from .vulnerabilities import load_asset_card_structure, load_asset_card_vulnerabilities

    return {
        **load_asset_card_structure(conn, asset_id),
        "vulnerabilities": load_asset_card_vulnerabilities(conn, asset_id),
    }


def _hydrate_legacy_asset_card_cache(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    row: dict[str, Any],
) -> bool:
    """Populate normalized paging tables for cards saved before they existed."""
    from .cards import decode_asset_card
    from .vulnerabilities import iter_asset_card_vulnerability_groups

    legacy_structure = any(
        json_loads(row.get(column), [])
        for column in ("nodes_json", "collections_json", "table_rows_json")
    )
    legacy_vulnerabilities = json_loads(row.get("vulnerabilities_json"), {})
    legacy_groups = iter_asset_card_vulnerability_groups(legacy_vulnerabilities)
    if not legacy_structure and not legacy_groups:
        return False

    coverage = conn.execute(
        """
        SELECT
            EXISTS (
                SELECT 1 FROM asset_card_nodes WHERE asset_id = %s
                UNION ALL
                SELECT 1 FROM asset_card_collections WHERE asset_id = %s
                UNION ALL
                SELECT 1 FROM asset_card_table_rows WHERE asset_id = %s
            ) AS has_structure,
            EXISTS (
                SELECT 1 FROM asset_card_vulnerability_groups WHERE asset_id = %s
            ) AS has_vulnerabilities
        """,
        (asset_id, asset_id, asset_id, asset_id),
    ).fetchone()
    assert coverage is not None
    needs_structure = bool(legacy_structure) and not bool(coverage["has_structure"])
    needs_vulnerabilities = bool(legacy_groups) and not bool(coverage["has_vulnerabilities"])
    if not needs_structure and not needs_vulnerabilities:
        return False

    replace_asset_card_cache(conn, asset_id, decode_asset_card(row), codecs.now_utc())
    return True


def asset_card_search_index_coverage() -> dict[str, int]:
    """Index coverage of asset cards.

    ``indexed_cards`` is counted from the small ``asset_cards`` side with
    an indexed ``EXISTS`` lookup.  Because of the FK
    ``asset_card_search_fields.asset_id -> asset_cards.asset_id`` this is
    exactly equivalent to ``COUNT(DISTINCT asset_id)`` on the search
    fields table, but avoids a parallel full scan + sort of the
    15 GB / 21 M-row ``asset_card_search_fields`` table.  The old form
    took 2-3 minutes per call on production-sized data and blocked
    application startup (and made every asset-card API response slow).
    """
    schema.init_db()
    with connection.connect() as conn:
        row = conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM asset_cards) AS total_cards,
                (
                    SELECT COUNT(*)
                    FROM asset_cards card
                    WHERE EXISTS (
                        SELECT 1
                        FROM asset_card_search_fields field
                        WHERE field.asset_id = card.asset_id
                    )
                )
                    AS indexed_cards,
                (
                    SELECT COUNT(*)
                    FROM asset_cards
                    WHERE software_inventory_updated_at IS NOT NULL
                )
                    AS software_inventory_indexed_cards
            """
        ).fetchone()
    assert row is not None
    total_cards = int(row["total_cards"] or 0)
    return {
        "total_cards": total_cards,
        "indexed_cards": int(row["indexed_cards"] or 0),
        "software_inventory_total_cards": total_cards,
        "software_inventory_indexed_cards": int(
            row["software_inventory_indexed_cards"] or 0
        ),
    }


def asset_card_software_inventory_coverage() -> dict[str, int]:
    coverage = asset_card_search_index_coverage()
    return {
        "software_inventory_total_cards": coverage["software_inventory_total_cards"],
        "software_inventory_indexed_cards": coverage[
            "software_inventory_indexed_cards"
        ],
    }


def backfill_asset_card_search_index_batch(limit: int = 20) -> dict[str, int]:
    from .cards import get_asset_card
    from .inventory import replace_asset_card_software_inventory
    from .search_index import replace_asset_card_search_index

    schema.init_db()
    limit = max(1, min(100, int(limit)))
    with connection.connect() as conn:
        missing = conn.execute(
            """
            SELECT card.asset_id
            FROM asset_cards card
            WHERE NOT EXISTS (
                SELECT 1 FROM asset_card_search_fields field WHERE field.asset_id = card.asset_id
            )
            ORDER BY card.last_seen DESC, card.asset_id
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    processed = 0
    indexed_fields = 0
    for row in missing:
        asset_id = str(row["asset_id"])
        card = get_asset_card(asset_id)
        if not card:
            continue
        current = codecs.now_utc()
        with connection.connect() as conn:
            indexed_fields += replace_asset_card_search_index(conn, asset_id, card, current)
            replace_asset_card_software_inventory(conn, asset_id, card, current)
        processed += 1
    coverage = asset_card_search_index_coverage()
    return {**coverage, "processed": processed, "indexed_fields": indexed_fields}


def backfill_asset_card_software_inventory_batch(limit: int = 20) -> dict[str, int]:
    """Populate the materialized software rows for legacy asset cards."""
    from .cards import get_asset_card
    from .inventory import replace_asset_card_software_inventory

    schema.init_db()
    limit = max(1, min(100, int(limit)))
    with connection.connect() as conn:
        missing = conn.execute(
            """
            SELECT card.asset_id
            FROM asset_cards card
            WHERE card.software_inventory_updated_at IS NULL
            ORDER BY card.last_seen DESC, card.asset_id
            LIMIT %s
            """,
            (limit,),
        ).fetchall()
    processed = 0
    indexed_rows = 0
    for row in missing:
        asset_id = str(row["asset_id"])
        card = get_asset_card(asset_id)
        if not card:
            continue
        current = codecs.now_utc()
        with connection.connect() as conn:
            indexed_rows += replace_asset_card_software_inventory(
                conn,
                asset_id,
                card,
                current,
            )
        processed += 1
    return {
        **asset_card_software_inventory_coverage(),
        "processed": processed,
        "indexed_rows": indexed_rows,
    }
