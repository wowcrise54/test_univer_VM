"""Asset card query execution: rule compilation, presets, sorting, and field-based queries with evidence matching."""

from __future__ import annotations

import ipaddress
from typing import Any

import psycopg

from ...persistence import connection, schema
from ...persistence.codecs import first_non_empty, safe_int
from ...persistence.sql import rows_to_dicts
from .cache import asset_card_search_index_coverage
from .inventory import SOFTWARE_ENTITY_PATTERN
from .presets import ASSET_CARD_QUERY_PRESETS, public_asset_card_query_preset

ASSET_QUERY_TEXT_OPERATORS = {"equals", "not_equals", "contains", "starts_with", "in"}


ASSET_QUERY_NUMBER_OPERATORS = {"equals", "not_equals", "gt", "gte", "lt", "lte"}


ASSET_QUERY_BOOLEAN_OPERATORS = {"is_true", "is_false"}


ASSET_QUERY_COMMON_OPERATORS = {"exists", "not_exists"}


ASSET_SOFTWARE_ROWS_CTE = rf"""
WITH software_rows AS (
    SELECT
        inventory.asset_id,
        COALESCE(card.display_name, card.hostname, card.fqdn, card.asset_id) AS host,
        inventory.soft_name,
        inventory.soft_name_normalized,
        inventory.soft_version,
        inventory.soft_version_normalized,
        inventory.vendor,
        inventory.architecture,
        inventory.install_path,
        card.last_seen AS update_time
    FROM asset_card_software_inventory AS inventory
    JOIN asset_cards AS card ON card.asset_id = inventory.asset_id
    WHERE (%s = FALSE OR inventory.is_windows = TRUE)
      AND inventory.entity_path ~* '{SOFTWARE_ENTITY_PATTERN}'
)
"""


def _page_bounds(limit: int, offset: int, *, default: int, maximum: int) -> tuple[int, int]:
    safe_limit = safe_int(limit)
    safe_offset = safe_int(offset)
    return (
        max(1, min(maximum, safe_limit if safe_limit is not None else default)),
        max(0, safe_offset if safe_offset is not None else 0),
    )


def collect_asset_query_rules(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    if node.get("field_path"):
        return [node]
    result: list[dict[str, Any]] = []
    for child in node.get("rules") or []:
        result.extend(collect_asset_query_rules(child))
    return result


def canonical_asset_card_id(
    conn: psycopg.Connection[dict[str, Any]],
    *, remote_asset_id: str, fqdn: str | None, hostname: str | None, ip_address: str | None,
) -> str:
    """Keep one local card when MP VM recreates the same host with a new object id."""
    row = conn.execute(
        """
        SELECT asset_id
        FROM asset_cards
        WHERE asset_id <> %s
          AND (
            (%s::text IS NOT NULL AND LOWER(NULLIF(TRIM(fqdn), '')) = LOWER(%s::text)) OR
            (%s::text IS NULL AND %s::text IS NOT NULL AND NULLIF(TRIM(ip_address), '') = %s::text) OR
            (%s::text IS NULL AND %s::text IS NULL AND %s::text IS NOT NULL
              AND LOWER(NULLIF(TRIM(hostname), '')) = LOWER(%s::text))
          )
        ORDER BY last_seen DESC, id DESC
        LIMIT 1
        """,
        (
            remote_asset_id,
            fqdn, fqdn,
            fqdn, ip_address, ip_address,
            fqdn, ip_address, hostname, hostname,
        ),
    ).fetchone()
    return str(row["asset_id"]) if row else remote_asset_id


def validate_asset_query_tree(node: Any, *, depth: int = 0, parent_scope: str | None = None) -> int:
    if not isinstance(node, dict):
        raise ValueError("Query node must be an object.")
    if depth > 3:
        raise ValueError("Query groups may not be nested deeper than 3 levels.")
    if node.get("field_path"):
        if not str(node.get("operator") or ""):
            raise ValueError("Every field rule requires an operator.")
        return 1
    combinator = str(node.get("combinator") or "and").lower()
    scope = str(node.get("match_scope") or "host").lower()
    if combinator not in {"and", "or"} or scope not in {"host", "same_entity"}:
        raise ValueError("Unsupported query group combinator or match_scope.")
    if parent_scope == "same_entity" and scope == "host":
        raise ValueError("A host-scoped group cannot be nested inside same_entity.")
    rules = node.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Every query group must contain at least one rule.")
    count = sum(validate_asset_query_tree(child, depth=depth + 1, parent_scope=scope) for child in rules)
    if count > 20:
        raise ValueError("A query may contain at most 20 field rules.")
    if scope == "same_entity" and any(
        str(rule.get("operator") or "") == "not_exists" for rule in collect_asset_query_rules(node)
    ):
        raise ValueError("not_exists is only supported for host-scoped groups.")
    return count


def compile_asset_query_rule(rule: dict[str, Any]) -> tuple[str, list[Any], str]:
    field_path = str(rule.get("field_path") or "").strip()
    operator = str(rule.get("operator") or "").lower()
    value = rule.get("value")
    if not field_path:
        raise ValueError("field_path is required.")
    if operator == "not_exists":
        return (
            "SELECT card.asset_id, NULL::text AS entity_path FROM asset_cards card "
            "WHERE NOT EXISTS (SELECT 1 FROM asset_card_search_fields field WHERE field.asset_id = card.asset_id AND field.field_path = %s)",
            [field_path],
            "host",
        )
    base = "SELECT asset_id, entity_path FROM asset_card_search_fields WHERE field_path = %s"
    params: list[Any] = [field_path]
    if operator == "exists":
        return base, params, "entity"
    if operator == "in_cidr":
        if field_path != "asset.ipAddress":
            raise ValueError("in_cidr is only supported for asset.ipAddress.")
        try:
            network = ipaddress.ip_network(str(value or "").strip(), strict=False)
        except ValueError as exc:
            raise ValueError("in_cidr requires a valid IPv4 or IPv6 network.") from exc
        return (
            f"{base} AND value_text_normalized::inet <<= %s::cidr",
            [*params, str(network)],
            "entity",
        )
    if operator in ASSET_QUERY_TEXT_OPERATORS:
        if operator == "in":
            values = value if isinstance(value, list) else [item.strip() for item in str(value or "").split(",") if item.strip()]
            if not values:
                raise ValueError("in requires at least one value.")
            normalized_values = [str(item).lower() for item in values]
            placeholders = ", ".join(["%s"] * len(values))
            digest_placeholders = ", ".join(["md5(%s)"] * len(values))
            return (
                f"{base} AND md5(value_text_normalized) IN ({digest_placeholders}) "
                f"AND value_text_normalized IN ({placeholders})",
                [*params, *normalized_values, *normalized_values],
                "entity",
            )
        normalized = str(value or "").lower()
        expression = {
            "equals": "value_text_normalized = %s",
            "not_equals": "value_text_normalized <> %s",
            "contains": "value_text_normalized LIKE %s",
            "starts_with": "value_text_normalized LIKE %s",
        }[operator]
        if operator == "contains":
            normalized = f"%{normalized}%"
        elif operator == "starts_with":
            normalized = f"{normalized}%"
        if operator == "equals":
            return (
                f"{base} AND md5(value_text_normalized) = md5(%s) AND value_text_normalized = %s",
                [*params, normalized, normalized],
                "entity",
            )
        return f"{base} AND {expression}", [*params, normalized], "entity"
    if operator in ASSET_QUERY_NUMBER_OPERATORS:
        try:
            numeric = float(value if value is not None else "")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{operator} requires a numeric value.") from exc
        expression = {"equals": "=", "not_equals": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[operator]
        return f"{base} AND value_number {expression} %s", [*params, numeric], "entity"
    if operator in ASSET_QUERY_BOOLEAN_OPERATORS:
        return f"{base} AND value_boolean = %s", [*params, operator == "is_true"], "entity"
    raise ValueError(f"Unsupported asset query operator: {operator}")


def compile_asset_query_node(node: dict[str, Any]) -> tuple[str, list[Any], str]:
    if node.get("field_path"):
        return compile_asset_query_rule(node)
    scope = str(node.get("match_scope") or "host").lower()
    combinator = str(node.get("combinator") or "and").lower()
    child_parts: list[str] = []
    params: list[Any] = []
    for child in node.get("rules") or []:
        child_sql, child_params, child_scope = compile_asset_query_node(child)
        if scope == "host":
            child_sql = f"SELECT DISTINCT asset_id, NULL::text AS entity_path FROM ({child_sql}) child"
        elif child_scope == "host":
            raise ValueError("Host-scoped rules cannot be correlated inside same_entity.")
        child_parts.append(f"SELECT asset_id, entity_path FROM ({child_sql}) grouped_child")
        params.extend(child_params)
    joiner = " INTERSECT " if combinator == "and" else " UNION "
    return joiner.join(child_parts), params, scope


ASSET_QUERY_SORT_COLUMNS = {
    "display_name": "LOWER(card.display_name)",
    "ip_address": "LOWER(card.ip_address)",
    "fqdn": "LOWER(card.fqdn)",
    "os_name": "LOWER(card.os_name)",
    "asset_type": "LOWER(card.asset_type)",
    "last_seen": "card.last_seen",
    "vulnerability_level": "LOWER(card.vulnerability_level)",
}


def asset_query_evidence_matches(field: dict[str, Any], rule: dict[str, Any]) -> bool:
    operator = str(rule.get("operator") or "").lower()
    if operator in {"exists", "not_exists"}:
        return operator == "exists"
    value = rule.get("value")
    if operator in ASSET_QUERY_BOOLEAN_OPERATORS:
        return bool(field.get("value_boolean")) is (operator == "is_true")
    if operator in ASSET_QUERY_NUMBER_OPERATORS:
        number_raw = field.get("value_number")
        try:
            left_value, right_value = float(number_raw if number_raw is not None else ""), float(value if value is not None else "")
        except (TypeError, ValueError):
            return False
        return {"equals": left_value == right_value, "not_equals": left_value != right_value, "gt": left_value > right_value, "gte": left_value >= right_value, "lt": left_value < right_value, "lte": left_value <= right_value}[operator]
    left = str(field.get("value_text_normalized") or field.get("value_text") or "").lower()
    if operator == "in":
        values = value if isinstance(value, list) else [item.strip() for item in str(value or "").split(",")]
        return left in {str(item).lower() for item in values}
    if operator == "in_cidr":
        try:
            return ipaddress.ip_address(left) in ipaddress.ip_network(str(value or "").strip(), strict=False)
        except ValueError:
            return False
    right = str(value or "").lower()
    return {"equals": left == right, "not_equals": left != right, "contains": right in left, "starts_with": left.startswith(right)}.get(operator, False)


def query_asset_card_preset(
    preset_id: str,
    *,
    software_name: str | None = None,
    software_version_like: str | None = None,
    vendor: str | None = None,
    os_name: str | None = None,
    os_version_like: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    schema.init_db()
    preset = ASSET_CARD_QUERY_PRESETS.get(str(preset_id))
    if preset is None:
        raise KeyError(preset_id)
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))

    if preset["kind"] == "os":
        filters = []
        params: list[Any] = []
        if os_name and os_name.strip():
            filters.append("STRPOS(LOWER(card.os_name), LOWER(%s)) > 0")
            params.append(os_name.strip())
        if os_version_like and os_version_like.strip():
            filters.append("LOWER(card.os_version) LIKE LOWER(%s)")
            params.append(os_version_like.strip())
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        statement = f"""
            SELECT
                card.os_name,
                card.os_version,
                COUNT(*)::int AS count,
                COUNT(*) OVER()::int AS __total
            FROM asset_cards AS card
            {where}
            GROUP BY card.os_name, card.os_version
            ORDER BY LOWER(card.os_name) ASC NULLS LAST,
                     LOWER(card.os_version) ASC NULLS LAST
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
    else:
        filters = []
        params = [bool(preset.get("windows_only"))]
        if preset.get("search") or software_name is not None or software_version_like is not None:
            clean_name = str(
                software_name
                if software_name is not None
                else preset.get("defaults", {}).get("software_name", "")
            ).strip()
            clean_version = str(
                software_version_like
                if software_version_like is not None
                else preset.get("defaults", {}).get("software_version_like", "")
            ).strip()
            if not clean_name and preset.get("search"):
                raise ValueError("software_name must not be blank.")
            if clean_name:
                filters.append("STRPOS(soft_name_normalized, LOWER(%s)) > 0")
                params.append(clean_name)
            if clean_version:
                filters.append("soft_version_normalized LIKE LOWER(%s)")
                params.append(clean_version)
        if vendor and vendor.strip():
            filters.append("STRPOS(LOWER(vendor), LOWER(%s)) > 0")
            params.append(vendor.strip())
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        grouping = preset["grouping"]
        if grouping == "name":
            grouped = f"""
                SELECT soft_name, COUNT(*)::int AS count
                FROM software_rows
                {where}
                GROUP BY soft_name
            """
            order = "LOWER(soft_name) ASC NULLS LAST"
        elif grouping == "name_version":
            grouped = f"""
                SELECT soft_name, soft_version, COUNT(*)::int AS count
                FROM software_rows
                {where}
                GROUP BY soft_name, soft_version
            """
            order = (
                "LOWER(soft_name) ASC NULLS LAST, "
                "LOWER(soft_version) ASC NULLS LAST"
            )
        elif grouping == "vendor":
            grouped = f"""
                SELECT vendor, COUNT(*)::int AS soft_number
                FROM software_rows
                {where}
                GROUP BY vendor
            """
            order = "soft_number DESC, LOWER(vendor) ASC NULLS LAST"
        else:
            raise ValueError(f"Unsupported preset grouping: {grouping}")
        statement = (
            ASSET_SOFTWARE_ROWS_CTE
            + f"""
                SELECT grouped.*, COUNT(*) OVER()::int AS __total
                FROM ({grouped}) AS grouped
                ORDER BY {order}
                LIMIT %s OFFSET %s
            """
        )
        params.extend([limit, offset])

    with connection.connect() as conn:
        raw_rows = conn.execute(statement, params).fetchall()
    rows = rows_to_dicts(raw_rows)
    total = int(rows[0].pop("__total", 0)) if rows else 0
    for row in rows[1:]:
        row.pop("__total", None)
    return {
        "preset": public_asset_card_query_preset(preset),
        "rows": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
        "execution": "local",
        "source": "asset_cards",
        **asset_card_search_index_coverage(),
    }


def query_asset_card_preset_assets(
    preset_id: str,
    *,
    software_name: str | None = None,
    software_version: str | None = None,
    vendor: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    schema.init_db()
    preset = ASSET_CARD_QUERY_PRESETS.get(str(preset_id))
    if preset is None:
        raise KeyError(preset_id)
    if preset["kind"] == "os":
        limit = max(1, min(500, int(limit)))
        offset = max(0, int(offset))
        with connection.connect() as conn:
            rows = rows_to_dicts(conn.execute("""
                SELECT card.asset_id,
                       COALESCE(card.display_name, card.hostname, card.fqdn, card.asset_id) AS display_name,
                       card.hostname, card.ip_address, card.fqdn,
                       card.os_name, card.os_version, card.last_seen,
                       COUNT(*) OVER()::int AS __total
                FROM asset_cards AS card
                WHERE card.os_name IS NOT DISTINCT FROM %s::text
                  AND card.os_version IS NOT DISTINCT FROM %s::text
                ORDER BY LOWER(COALESCE(card.display_name, card.hostname, card.fqdn, card.asset_id)),
                         card.asset_id
                LIMIT %s OFFSET %s
            """, [os_name, os_version, limit, offset]).fetchall())
        total = int(rows[0].get("__total", 0)) if rows else 0
        for row in rows:
            row.pop("__total", None)
        return {
            "preset": public_asset_card_query_preset(preset),
            "selection": {"os_name": os_name, "os_version": os_version},
            "rows": rows, "total": total, "limit": limit, "offset": offset,
            "execution": "local", "source": "asset_cards",
            **asset_card_search_index_coverage(),
        }
    if preset["kind"] != "software":
        raise ValueError("Asset details are only available for software presets.")
    clean_name = str(software_name or "").strip()
    clean_version = str(software_version or "").strip()
    clean_vendor = str(vendor or "").strip()
    if not clean_name and not clean_vendor:
        raise ValueError("software_name or vendor is required.")
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))

    filters = []
    params: list[Any] = [bool(preset.get("windows_only"))]
    if clean_name:
        filters.append("soft_name_normalized = LOWER(%s)")
        params.append(clean_name)
    if clean_version:
        filters.append("soft_version_normalized = LOWER(%s)")
        params.append(clean_version)
    if clean_vendor:
        filters.append("vendor = %s")
        params.append(clean_vendor)
    statement = (
        ASSET_SOFTWARE_ROWS_CTE
        + f""",
        selected_assets AS (
            SELECT
                asset_id,
                host,
                MAX(soft_name) AS soft_name,
                STRING_AGG(DISTINCT NULLIF(soft_version, ''), ', ') AS soft_version,
                STRING_AGG(DISTINCT NULLIF(vendor, ''), ', ') AS vendor,
                STRING_AGG(DISTINCT NULLIF(architecture, ''), ', ') AS architecture,
                STRING_AGG(DISTINCT NULLIF(install_path, ''), ', ') AS install_path,
                MAX(update_time) AS update_time
            FROM software_rows
            WHERE {" AND ".join(filters)}
            GROUP BY asset_id, host
        )
            SELECT
                selected_assets.asset_id,
                selected_assets.host AS display_name,
                card.ip_address,
                card.fqdn,
                card.hostname,
                card.os_name,
                card.os_version,
                selected_assets.update_time AS last_seen,
                selected_assets.soft_name,
                selected_assets.soft_version,
                selected_assets.vendor,
                selected_assets.architecture,
                selected_assets.install_path,
                COUNT(*) OVER()::int AS __total
            FROM selected_assets
            JOIN asset_cards AS card USING (asset_id)
            ORDER BY LOWER(selected_assets.host) ASC NULLS LAST,
                     selected_assets.asset_id ASC
            LIMIT %s OFFSET %s
        """
    )
    params.extend([limit, offset])
    with connection.connect() as conn:
        raw_rows = conn.execute(statement, params).fetchall()
    rows = rows_to_dicts(raw_rows)
    total = int(rows[0].pop("__total", 0)) if rows else 0
    for row in rows[1:]:
        row.pop("__total", None)
    return {
        "preset": public_asset_card_query_preset(preset),
        "selection": {
            "software_name": clean_name or None,
            "software_version": clean_version or None,
            "vendor": clean_vendor or None,
        },
        "rows": rows,
        "total": total,
        "limit": limit,
        "offset": offset,
        "execution": "local",
        "source": "asset_cards",
        **asset_card_search_index_coverage(),
    }


def query_asset_cards_by_fields(
    query: dict[str, Any],
    *,
    sort_by: str = "display_name",
    sort_dir: str = "asc",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    from .cards import decode_asset_card_summary

    validate_asset_query_tree(query)
    matched_sql, params, _scope = compile_asset_query_node(query)
    sort_expression = ASSET_QUERY_SORT_COLUMNS.get(sort_by)
    if not sort_expression:
        raise ValueError(f"Unsupported asset query sort column: {sort_by}")
    direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    limit = max(1, min(50000, int(limit)))
    offset = max(0, int(offset))
    matched_cte = f"WITH matched_pairs AS ({matched_sql}), matched AS (SELECT DISTINCT asset_id FROM matched_pairs)"
    with connection.connect() as conn:
        total_row = conn.execute(f"{matched_cte} SELECT COUNT(*) AS count FROM matched", params).fetchone()
        assert total_row is not None
        total = total_row["count"]
        cards = conn.execute(
            f"""
            {matched_cte}
            SELECT card.id, card.asset_id, card.display_name, card.asset_type, card.fqdn,
                   card.hostname, card.ip_address, card.os_name, card.os_version,
                   card.vulnerability_level, card.token_timestamp, card.stats_json,
                   card.first_seen, card.last_seen
            FROM matched JOIN asset_cards card ON card.asset_id = matched.asset_id
            ORDER BY {sort_expression} {direction} NULLS LAST, card.asset_id ASC
            LIMIT %s OFFSET %s
            """,
            [*params, limit, offset],
        ).fetchall()
        asset_ids = [row["asset_id"] for row in cards]
        rules = collect_asset_query_rules(query)
        field_paths = list(dict.fromkeys(str(rule.get("field_path")) for rule in rules if rule.get("field_path") and rule.get("operator") != "not_exists"))
        evidence_rows = []
        if asset_ids and field_paths:
            evidence_rows = conn.execute(
                """
                SELECT asset_id, entity_path, field_path, field_name, value_type,
                       value_text, value_number, value_boolean
                FROM asset_card_search_fields
                WHERE asset_id = ANY(%s) AND field_path = ANY(%s)
                ORDER BY asset_id, entity_path, field_path, id
                """,
                (asset_ids, field_paths),
            ).fetchall()
    evidence_by_asset: dict[str, list[dict[str, Any]]] = {asset_id: [] for asset_id in asset_ids}
    for raw in evidence_rows:
        item = dict(raw)
        matching_rules = [rule for rule in rules if rule.get("field_path") == item["field_path"]]
        if not any(asset_query_evidence_matches(item, rule) for rule in matching_rules):
            continue
        item["value"] = first_non_empty(item.get("value_text"), item.get("value_number"), item.get("value_boolean"))
        evidence_by_asset[item["asset_id"]].append(item)
    decoded = []
    for card in cards:
        summary = decode_asset_card_summary(dict(card))
        summary["matches"] = evidence_by_asset.get(card["asset_id"], [])[:50]
        decoded.append(summary)
    return {"total": int(total or 0), "rows": decoded, "limit": limit, "offset": offset, **asset_card_search_index_coverage()}
