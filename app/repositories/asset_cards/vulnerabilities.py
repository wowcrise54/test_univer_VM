"""Repository for asset card vulnerabilities and structure: finding loading, grouping, deduplication, and listing."""

from __future__ import annotations

from typing import Any

import psycopg

from ...persistence import connection, schema
from ...persistence.codecs import clean_value, decimal_to_number, json_loads
from .cache import _hydrate_legacy_asset_card_cache
from .queries import _page_bounds

ASSET_CARD_BASE_COLUMNS = """
    id, asset_id, display_name, asset_type, fqdn, hostname, ip_address,
    os_name, os_version, vulnerability_level, token_timestamp,
    root_json, metadata_json, stats_json, first_seen, last_seen
"""


def load_asset_card_structure(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
) -> dict[str, Any]:
    nodes = [
        json_loads(row.get("node_json"), {})
        for row in conn.execute(
            "SELECT node_json FROM asset_card_nodes WHERE asset_id = %s ORDER BY path",
            (asset_id,),
        ).fetchall()
    ]
    table_rows = [
        json_loads(row.get("row_json"), {})
        for row in conn.execute(
            "SELECT row_json FROM asset_card_table_rows WHERE asset_id = %s ORDER BY row_order, path",
            (asset_id,),
        ).fetchall()
    ]

    collection_docs: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        """
        SELECT path, collection_json
        FROM asset_card_collections
        WHERE asset_id = %s
        ORDER BY path
        """,
        (asset_id,),
    ).fetchall():
        path = clean_value(row.get("path")) or ""
        collection = json_loads(row.get("collection_json"), {})
        if isinstance(collection, dict):
            collection["items"] = []
            collection_docs[path] = collection

    for row in conn.execute(
        """
        SELECT collection_path, item_json
        FROM asset_card_collection_items
        WHERE asset_id = %s
        ORDER BY collection_path, item_index
        """,
        (asset_id,),
    ).fetchall():
        collection_path = clean_value(row.get("collection_path")) or ""
        collection = collection_docs.get(collection_path)
        item = json_loads(row.get("item_json"), {})
        if collection is not None and isinstance(item, dict):
            collection.setdefault("items", []).append(item)

    return {
        "nodes": [node for node in nodes if isinstance(node, dict)],
        "collections": list(collection_docs.values()),
        "table_rows": [row for row in table_rows if isinstance(row, dict)],
    }


def _asset_vulnerability_group(row: dict[str, Any]) -> dict[str, Any]:
    group = json_loads(row.get("group_json"), {})
    if not isinstance(group, dict):
        group = {}
    group.update({
        "source": row.get("source_type"),
        "collection_type": row.get("collection_type"),
        "collection_id": row.get("collection_id"),
        "group_key": f"{row.get('source_type')}:{row.get('collection_id')}",
        "name": row.get("name"),
        "level": row.get("severity"),
        "vulnerabilities_count": int(row.get("vulnerability_count") or 0),
        "cvss_score": decimal_to_number(row.get("cvss_score")),
        "order": int(row.get("group_order") or 0),
        "truncated": bool(row.get("truncated")),
    })
    group.pop("items", None)
    return group


def iter_asset_card_vulnerability_groups(vulnerabilities: Any) -> list[dict[str, Any]]:
    if not isinstance(vulnerabilities, dict):
        return []
    sources = vulnerabilities.get("sources")
    if not isinstance(sources, list):
        return []
    groups: list[dict[str, Any]] = []
    for source_doc in sources:
        if not isinstance(source_doc, dict):
            continue
        source_type = clean_value(source_doc.get("source"))
        collection_type = clean_value(source_doc.get("collection_type"))
        source_groups = source_doc.get("groups")
        if not source_type or not collection_type or not isinstance(source_groups, list):
            continue
        for group in source_groups:
            if not isinstance(group, dict):
                continue
            collection_id = clean_value(group.get("collection_id"))
            if not collection_id:
                continue
            groups.append({
                **group,
                "source": source_type,
                "collection_type": collection_type,
                "collection_id": collection_id,
            })
    return groups


def deduplicate_asset_card_vulnerability_findings(
    vulnerability_groups: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], int]:
    """Keep the first occurrence of each non-empty instance id for one asset."""

    findings: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen_instance_ids: set[str] = set()
    duplicate_count = 0
    for group in vulnerability_groups:
        for finding in group.get("items") or []:
            if not isinstance(finding, dict):
                continue
            instance_id = clean_value(finding.get("vulnerability_instance_id"))
            if instance_id:
                if instance_id in seen_instance_ids:
                    duplicate_count += 1
                    continue
                seen_instance_ids.add(instance_id)
            findings.append((group, finding))
    return findings, duplicate_count


def load_asset_card_vulnerabilities(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
) -> dict[str, Any]:
    from .cards import strip_asset_card_raw

    stored_row = conn.execute(
        "SELECT vulnerabilities_json FROM asset_cards WHERE asset_id = %s",
        (asset_id,),
    ).fetchone()
    stored = json_loads(stored_row.get("vulnerabilities_json") if stored_row else None, {})
    result = strip_asset_card_raw(stored) if isinstance(stored, dict) else {}
    sources = result.get("sources")
    if not isinstance(sources, list):
        sources = []
    source_by_kind = {
        clean_value(source.get("source")): source
        for source in sources
        if isinstance(source, dict) and clean_value(source.get("source"))
    }
    for source in sources:
        if isinstance(source, dict):
            source["groups"] = []

    group_rows = conn.execute(
        """
        SELECT *
        FROM asset_card_vulnerability_groups
        WHERE asset_id = %s
        ORDER BY source_type, group_order, name NULLS LAST, collection_id
        """,
        (asset_id,),
    ).fetchall()
    for group_row in group_rows:
        group = json_loads(group_row.get("group_json"), {})
        if not isinstance(group, dict):
            group = {}
        group.update({
            "source": group_row.get("source_type"),
            "collection_type": group_row.get("collection_type"),
            "collection_id": group_row.get("collection_id"),
            "name": group_row.get("name"),
            "level": group_row.get("severity"),
            "vulnerabilities_count": int(group_row.get("vulnerability_count") or 0),
            "cvss_score": decimal_to_number(group_row.get("cvss_score")),
            "order": int(group_row.get("group_order") or 0),
            "truncated": bool(group_row.get("truncated")),
            "items": [],
        })
        source_type = clean_value(group_row.get("source_type")) or "unknown"
        source = source_by_kind.get(source_type)
        if source is None:
            source = {
                "source": source_type,
                "collection_type": group_row.get("collection_type"),
                "title": (
                    "Уязвимости ОС" if source_type == "os"
                    else "Docker-контейнеры" if source_type == "docker"
                    else "Уязвимости программного обеспечения"
                ),
                "groups": [],
            }
            source_by_kind[source_type] = source
            sources.append(source)

        finding_rows = conn.execute(
            """
            SELECT
                vulnerability.*,
                COALESCE(
                    array_agg(link.passport_internal_id ORDER BY link.passport_internal_id)
                    FILTER (WHERE link.passport_internal_id IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS passport_ids,
                COALESCE(
                    jsonb_agg(
                        jsonb_build_object(
                            'internal_id', passports.internal_id,
                            'external_id', passports.external_id,
                            'name', passports.name,
                            'severity', passports.severity,
                            'has_detail', passports.raw_detail_json IS NOT NULL,
                            'match_method', link.match_method
                        )
                        ORDER BY COALESCE(passports.name, passports.external_id, passports.internal_id), passports.internal_id
                    ) FILTER (WHERE passports.internal_id IS NOT NULL),
                    '[]'::jsonb
                ) AS passports
            FROM asset_card_vulnerabilities AS vulnerability
            LEFT JOIN asset_card_vulnerability_passports AS link
                ON link.asset_vulnerability_id = vulnerability.id
            LEFT JOIN vulnerability_passports AS passports
                ON passports.internal_id = link.passport_internal_id
            WHERE vulnerability.group_id = %s
            GROUP BY vulnerability.id
            ORDER BY vulnerability.cve_name NULLS LAST, vulnerability.name NULLS LAST, vulnerability.id
            """,
            (group_row["id"],),
        ).fetchall()
        for finding_row in finding_rows:
            finding = json_loads(finding_row.get("vulnerability_json"), {})
            if not isinstance(finding, dict):
                finding = {}
            passports = json_loads(finding_row.get("passports"), [])
            finding.update({
                "level": finding_row.get("severity"),
                "name": finding_row.get("name"),
                "cve_name": finding_row.get("cve_name"),
                "description_key": finding_row.get("description_key"),
                "cvss_score": decimal_to_number(finding_row.get("cvss_score")),
                "object_id": finding_row.get("object_id"),
                "vulnerability_id": finding_row.get("vulnerability_id"),
                "vulnerability_instance_id": finding_row.get("vulnerability_instance_id"),
                "passport_ids": finding_row.get("passport_ids") or [],
                "passports": passports if isinstance(passports, list) else [],
            })
            group["items"].append(finding)
        source["groups"].append(group)

    result["sources"] = sources
    return result


def list_asset_card_vulnerability_groups(asset_id: str) -> dict[str, Any] | None:
    from .cards import strip_asset_card_raw

    schema.init_db()
    with connection.connect() as conn:
        stored_row = conn.execute(
            "SELECT * FROM asset_cards WHERE asset_id = %s",
            (asset_id,),
        ).fetchone()
        if not stored_row:
            return None
        _hydrate_legacy_asset_card_cache(conn, asset_id, dict(stored_row))
        stored = json_loads(stored_row.get("vulnerabilities_json"), {})
        result = strip_asset_card_raw(stored) if isinstance(stored, dict) else {}
        sources = result.get("sources")
        if not isinstance(sources, list):
            sources = []
        source_by_kind = {
            clean_value(source.get("source")): source
            for source in sources
            if isinstance(source, dict) and clean_value(source.get("source"))
        }
        for source in sources:
            if isinstance(source, dict):
                source["groups"] = []
        group_rows = conn.execute(
            """
            SELECT *
            FROM asset_card_vulnerability_groups
            WHERE asset_id = %s
            ORDER BY source_type, group_order, name NULLS LAST, collection_id
            """,
            (asset_id,),
        ).fetchall()
    for raw in group_rows:
        row = dict(raw)
        group = _asset_vulnerability_group(row)
        source_type = clean_value(row.get("source_type")) or "unknown"
        source = source_by_kind.get(source_type)
        if source is None:
            source = {
                "source": source_type,
                "collection_type": row.get("collection_type"),
                "title": (
                    "OS vulnerabilities" if source_type == "os"
                    else "Docker containers" if source_type == "docker"
                    else "Software vulnerabilities"
                ),
                "groups": [],
            }
            source_by_kind[source_type] = source
            sources.append(source)
        source.setdefault("groups", []).append(group)
    result["sources"] = sources
    result["loaded_sections"] = ["vulnerability_groups"]
    return {"asset_id": asset_id, "vulnerabilities": result}


def _decode_asset_vulnerability_finding(row: dict[str, Any]) -> dict[str, Any]:
    finding = json_loads(row.get("vulnerability_json"), {})
    if not isinstance(finding, dict):
        finding = {}
    passports = json_loads(row.get("passports"), [])
    finding.update({
        "level": row.get("severity"),
        "name": row.get("name"),
        "cve_name": row.get("cve_name"),
        "description_key": row.get("description_key"),
        "cvss_score": decimal_to_number(row.get("cvss_score")),
        "object_id": row.get("object_id"),
        "vulnerability_id": row.get("vulnerability_id"),
        "vulnerability_instance_id": row.get("vulnerability_instance_id"),
        "passport_ids": row.get("passport_ids") or [],
        "passports": passports if isinstance(passports, list) else [],
    })
    return finding


def list_asset_card_vulnerability_findings(
    asset_id: str,
    *,
    source: str,
    collection_id: str,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any] | None:
    schema.init_db()
    limit, offset = _page_bounds(limit, offset, default=100, maximum=500)
    source_type = clean_value(source)
    group_collection_id = clean_value(collection_id)
    if not source_type or not group_collection_id:
        raise ValueError("source and collection_id are required.")
    with connection.connect() as conn:
        card_row = conn.execute("SELECT * FROM asset_cards WHERE asset_id = %s", (asset_id,)).fetchone()
        if not card_row:
            return None
        _hydrate_legacy_asset_card_cache(conn, asset_id, dict(card_row))
        group_row = conn.execute(
            """
            SELECT *
            FROM asset_card_vulnerability_groups
            WHERE asset_id = %s AND source_type = %s AND collection_id = %s
            """,
            (asset_id, source_type, group_collection_id),
        ).fetchone()
        if not group_row:
            return {
                "asset_id": asset_id,
                "source": source_type,
                "collection_id": group_collection_id,
                "group": None,
                "rows": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "has_more": False,
            }
        group_id = int(group_row["id"])
        total_row = conn.execute(
            "SELECT COUNT(*) AS count FROM asset_card_vulnerabilities WHERE group_id = %s",
            (group_id,),
        ).fetchone()
        assert total_row is not None
        total = int(total_row["count"] or 0)
        rows = conn.execute(
            """
            SELECT
                vulnerability.*,
                COALESCE(
                    array_agg(link.passport_internal_id ORDER BY link.passport_internal_id)
                    FILTER (WHERE link.passport_internal_id IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS passport_ids,
                COALESCE(
                    jsonb_agg(
                        jsonb_build_object(
                            'internal_id', passports.internal_id,
                            'external_id', passports.external_id,
                            'name', passports.name,
                            'severity', passports.severity,
                            'has_detail', passports.raw_detail_json IS NOT NULL,
                            'match_method', link.match_method
                        )
                        ORDER BY COALESCE(passports.name, passports.external_id, passports.internal_id), passports.internal_id
                    ) FILTER (WHERE passports.internal_id IS NOT NULL),
                    '[]'::jsonb
                ) AS passports
            FROM asset_card_vulnerabilities AS vulnerability
            LEFT JOIN asset_card_vulnerability_passports AS link
                ON link.asset_vulnerability_id = vulnerability.id
            LEFT JOIN vulnerability_passports AS passports
                ON passports.internal_id = link.passport_internal_id
            WHERE vulnerability.group_id = %s
            GROUP BY vulnerability.id
            ORDER BY vulnerability.cve_name NULLS LAST, vulnerability.name NULLS LAST, vulnerability.id
            LIMIT %s OFFSET %s
            """,
            (group_id, limit, offset),
        ).fetchall()
    findings = [_decode_asset_vulnerability_finding(dict(row)) for row in rows]
    return {
        "asset_id": asset_id,
        "source": source_type,
        "collection_id": group_collection_id,
        "group": _asset_vulnerability_group(dict(group_row)),
        "rows": findings,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(findings) < total,
    }
