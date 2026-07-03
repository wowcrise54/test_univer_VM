from __future__ import annotations

from typing import Any

from .. import db


def _card_row(conn: Any, asset_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT
            asset_id, display_name, asset_type, fqdn, hostname, ip_address,
            os_name, os_version, vulnerability_level, token_timestamp,
            root_json, stats_json, first_seen, last_seen
        FROM asset_cards
        WHERE asset_id = %s
        """,
        (asset_id,),
    ).fetchone()
    return dict(row) if row else None


def get_overview(asset_id: str) -> dict[str, Any] | None:
    db.init_db()
    with db.connect() as conn:
        row = _card_row(conn, asset_id)
    if not row:
        return None
    root = db.json_loads(row.pop("root_json"), {})
    stats = db.json_loads(row.pop("stats_json"), {})
    version = str(row.get("last_seen") or "")
    return {
        "asset": row,
        "root": db.strip_asset_card_raw(root) if isinstance(root, dict) else {},
        "stats": stats if isinstance(stats, dict) else {},
        "sections": ["summary", "configuration", "vulnerabilities"],
        "version": version,
    }


def get_tree_children(
    asset_id: str,
    *,
    parent_path: str | None,
    limit: int,
    offset: int,
) -> dict[str, Any] | None:
    db.init_db()
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    with db.connect() as conn:
        card = _card_row(conn, asset_id)
        if not card:
            return None
        version = str(card.get("last_seen") or "")
        if parent_path is None:
            root = db.json_loads(card.get("root_json"), {})
            if not isinstance(root, dict):
                root = {}
            return {
                "rows": [{
                    "path": "asset",
                    "parent_path": None,
                    "depth": 0,
                    "kind": "root",
                    "label": root.get("displayName") or card.get("display_name") or asset_id,
                    "subtitle": root.get("type") or card.get("asset_type") or "asset",
                    "has_children": True,
                }],
                "total": 1,
                "limit": limit,
                "offset": 0,
                "next_cursor": None,
                "version": version,
            }

        total_row = conn.execute(
            """
            SELECT (
                (SELECT COUNT(*) FROM asset_card_nodes WHERE asset_id = %s AND parent_path = %s) +
                (SELECT COUNT(*) FROM asset_card_collections WHERE asset_id = %s AND parent_path = %s) +
                (SELECT COUNT(*) FROM asset_card_collection_items WHERE asset_id = %s AND collection_path = %s)
            ) AS count
            """,
            (asset_id, parent_path, asset_id, parent_path, asset_id, parent_path),
        ).fetchone()
        rows = conn.execute(
            """
            WITH entries AS (
                SELECT path, parent_path, depth, 'node'::TEXT AS kind,
                       COALESCE(title, display_name, path) AS label,
                       COALESCE(object_type, object_id, '') AS subtitle,
                       NULL::INTEGER AS item_count
                FROM asset_card_nodes
                WHERE asset_id = %s AND parent_path = %s
                UNION ALL
                SELECT path, parent_path, depth, 'collection'::TEXT AS kind,
                       COALESCE(title, name, path) AS label,
                       COALESCE(name, value_type, '') AS subtitle,
                       COALESCE(fetched_count, reported_count, 0) AS item_count
                FROM asset_card_collections
                WHERE asset_id = %s AND parent_path = %s
                UNION ALL
                SELECT item_path AS path, collection_path AS parent_path, 0 AS depth,
                       'item'::TEXT AS kind,
                       COALESCE(display_name, object_id, item_path) AS label,
                       COALESCE(object_type, object_id, '') AS subtitle,
                       NULL::INTEGER AS item_count
                FROM asset_card_collection_items
                WHERE asset_id = %s AND collection_path = %s
            )
            SELECT * FROM entries
            ORDER BY kind, label, path
            LIMIT %s OFFSET %s
            """,
            (asset_id, parent_path, asset_id, parent_path, asset_id, parent_path, limit, offset),
        ).fetchall()

        candidate_paths = [str(row["path"]) for row in rows if row.get("path")]
        child_parent_rows = conn.execute(
            """
            SELECT parent_path AS path FROM asset_card_nodes WHERE asset_id = %s AND parent_path = ANY(%s)
            UNION
            SELECT parent_path AS path FROM asset_card_collections WHERE asset_id = %s AND parent_path = ANY(%s)
            UNION
            SELECT collection_path AS path FROM asset_card_collection_items WHERE asset_id = %s AND collection_path = ANY(%s)
            """,
            (asset_id, candidate_paths, asset_id, candidate_paths, asset_id, candidate_paths),
        ).fetchall() if candidate_paths else []
        paths_with_children = {str(row["path"]) for row in child_parent_rows if row.get("path")}

        result: list[dict[str, Any]] = []
        for raw in rows:
            item = dict(raw)
            item["depth"] = db.asset_card_path_depth(item.get("path"))
            item["has_children"] = str(item.get("path")) in paths_with_children
            result.append(item)
        total = int(total_row.get("count") or 0)
    next_offset = offset + len(result)
    return {
        "rows": result,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_cursor": str(next_offset) if next_offset < total else None,
        "version": version,
    }


def get_configuration_detail(
    asset_id: str,
    *,
    path: str,
    kind: str,
    limit: int,
    offset: int,
) -> dict[str, Any] | None:
    db.init_db()
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    with db.connect() as conn:
        card = _card_row(conn, asset_id)
        if not card:
            return None
        version = str(card.get("last_seen") or "")
        if kind == "root":
            document = db.json_loads(card.get("root_json"), {})
            return {"entry": db.strip_asset_card_raw(document), "rows": [], "total": 1, "limit": limit, "offset": 0, "version": version}
        if kind == "node":
            row = conn.execute(
                "SELECT node_json FROM asset_card_nodes WHERE asset_id = %s AND path = %s",
                (asset_id, path),
            ).fetchone()
            document = db.json_loads(row.get("node_json") if row else None, {})
            return {"entry": db.strip_asset_card_raw(document), "rows": [], "total": 1 if row else 0, "limit": limit, "offset": 0, "version": version}
        if kind == "item":
            row = conn.execute(
                "SELECT item_json FROM asset_card_collection_items WHERE asset_id = %s AND item_path = %s",
                (asset_id, path),
            ).fetchone()
            document = db.json_loads(row.get("item_json") if row else None, {})
            return {"entry": db.strip_asset_card_raw(document), "rows": [], "total": 1 if row else 0, "limit": limit, "offset": 0, "version": version}
        if kind != "collection":
            return {"entry": {}, "rows": [], "total": 0, "limit": limit, "offset": offset, "version": version}

        collection_row = conn.execute(
            "SELECT collection_json FROM asset_card_collections WHERE asset_id = %s AND path = %s",
            (asset_id, path),
        ).fetchone()
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM asset_card_collection_items WHERE asset_id = %s AND collection_path = %s",
            (asset_id, path),
        ).fetchone()
        item_rows = conn.execute(
            """
            SELECT item_json FROM asset_card_collection_items
            WHERE asset_id = %s AND collection_path = %s
            ORDER BY item_index
            LIMIT %s OFFSET %s
            """,
            (asset_id, path, limit, offset),
        ).fetchall()
        entry = db.json_loads(collection_row.get("collection_json") if collection_row else None, {})
        items = [db.strip_asset_card_raw(db.json_loads(row.get("item_json"), {})) for row in item_rows]
        total = int(count_row.get("count") or 0)
    return {"entry": db.strip_asset_card_raw(entry), "rows": items, "total": total, "limit": limit, "offset": offset, "version": version}


def get_vulnerability_groups(asset_id: str) -> dict[str, Any] | None:
    db.init_db()
    with db.connect() as conn:
        card = _card_row(conn, asset_id)
        if not card:
            return None
        stored = conn.execute(
            "SELECT vulnerabilities_json FROM asset_cards WHERE asset_id = %s",
            (asset_id,),
        ).fetchone()
        snapshot = db.json_loads(stored.get("vulnerabilities_json") if stored else None, {})
        header = db.strip_asset_card_raw(snapshot.get("header") or {}) if isinstance(snapshot, dict) else {}
        rows = conn.execute(
            """
            SELECT source_type, collection_type, collection_id, name, severity,
                   vulnerability_count, cvss_score, group_order, truncated
            FROM asset_card_vulnerability_groups
            WHERE asset_id = %s
            ORDER BY source_type, group_order, name NULLS LAST, collection_id
            """,
            (asset_id,),
        ).fetchall()
        groups = []
        for raw in rows:
            group = dict(raw)
            group["cvss_score"] = db.decimal_to_number(group.get("cvss_score"))
            groups.append(group)
    return {"header": header, "groups": groups, "total": len(groups), "version": str(card.get("last_seen") or "")}


def get_vulnerability_findings(
    asset_id: str,
    *,
    source: str,
    collection_id: str,
    limit: int,
    offset: int,
) -> dict[str, Any] | None:
    db.init_db()
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    with db.connect() as conn:
        card = _card_row(conn, asset_id)
        if not card:
            return None
        group = conn.execute(
            """
            SELECT id FROM asset_card_vulnerability_groups
            WHERE asset_id = %s AND source_type = %s AND collection_id = %s
            """,
            (asset_id, source, collection_id),
        ).fetchone()
        if not group:
            return {"rows": [], "total": 0, "limit": limit, "offset": offset, "version": str(card.get("last_seen") or "")}
        count_row = conn.execute(
            "SELECT COUNT(*) AS count FROM asset_card_vulnerabilities WHERE group_id = %s",
            (group["id"],),
        ).fetchone()
        rows = conn.execute(
            """
            SELECT vulnerability.*,
                   COALESCE(array_agg(link.passport_internal_id ORDER BY link.passport_internal_id)
                       FILTER (WHERE link.passport_internal_id IS NOT NULL), ARRAY[]::TEXT[]) AS passport_ids,
                   COALESCE(jsonb_agg(jsonb_build_object(
                       'internal_id', passports.internal_id,
                       'external_id', passports.external_id,
                       'name', passports.name,
                       'severity', passports.severity,
                       'has_detail', passports.raw_detail_json IS NOT NULL,
                       'match_method', link.match_method
                   )) FILTER (WHERE passports.internal_id IS NOT NULL), '[]'::jsonb) AS passports
            FROM asset_card_vulnerabilities AS vulnerability
            LEFT JOIN asset_card_vulnerability_passports AS link ON link.asset_vulnerability_id = vulnerability.id
            LEFT JOIN vulnerability_passports AS passports ON passports.internal_id = link.passport_internal_id
            WHERE vulnerability.group_id = %s
            GROUP BY vulnerability.id
            ORDER BY vulnerability.cve_name NULLS LAST, vulnerability.name NULLS LAST, vulnerability.id
            LIMIT %s OFFSET %s
            """,
            (group["id"], limit, offset),
        ).fetchall()
        findings: list[dict[str, Any]] = []
        for raw in rows:
            finding = db.json_loads(raw.get("vulnerability_json"), {})
            if not isinstance(finding, dict):
                finding = {}
            finding.update({
                "level": raw.get("severity"),
                "name": raw.get("name"),
                "cve_name": raw.get("cve_name"),
                "description_key": raw.get("description_key"),
                "cvss_score": db.decimal_to_number(raw.get("cvss_score")),
                "object_id": raw.get("object_id"),
                "vulnerability_id": raw.get("vulnerability_id"),
                "vulnerability_instance_id": raw.get("vulnerability_instance_id"),
                "passport_ids": raw.get("passport_ids") or [],
                "passports": db.json_loads(raw.get("passports"), []),
            })
            findings.append(db.strip_asset_card_raw(finding))
        total = int(count_row.get("count") or 0)
    return {"rows": findings, "total": total, "limit": limit, "offset": offset, "version": str(card.get("last_seen") or "")}
