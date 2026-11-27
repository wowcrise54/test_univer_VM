from __future__ import annotations

import builtins
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from ..persistence import connection, schema
from ..persistence.codecs import decimal_to_number, json_loads

VulnerabilitySource = Literal["os", "software", "docker"]
VULNERABILITY_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
VULNERABILITY_TRENDS_SCOPE = "all_asset_cards"
VULNERABILITY_TRENDS_RETENTION_DAYS = 90
_RETENTION_ADVISORY_LOCK_KEY = 530_951_729_318_346


def _normalized_severity(expression: str) -> str:
    return (
        "CASE "
        f"WHEN LOWER(TRIM(COALESCE({expression}, ''))) IN ('critical', 'high', 'medium', 'low') "
        f"THEN LOWER(TRIM({expression})) ELSE 'unknown' END"
    )


def _severity_rank(expression: str) -> str:
    normalized = _normalized_severity(expression)
    return (
        f"CASE {normalized} WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
    )


# The selector is stored on each finding (migration 0036, filled by a trigger
# from vulnerability_selector()); every query here aliases the findings table as
# ``finding``. The reference expression below is the formula the SQL function
# implements and is only used to prove the two stay identical.
VULNERABILITY_SELECTOR_SQL = "finding.selector"

VULNERABILITY_SELECTOR_REFERENCE_SQL = """
CASE
    WHEN NULLIF(TRIM(finding.vulnerability_id), '') IS NOT NULL
        THEN 'id:' || TRIM(finding.vulnerability_id)
            || CASE WHEN vulnerability_group.source_type = 'docker'
                THEN '|source:docker' ELSE '' END
    WHEN NULLIF(TRIM(finding.cve_name), '') IS NOT NULL
        THEN 'cve:' || UPPER(TRIM(finding.cve_name))
            || CASE WHEN vulnerability_group.source_type = 'docker'
                THEN '|source:docker' ELSE '' END
    WHEN NULLIF(TRIM(finding.name), '') IS NOT NULL
        THEN 'name:' || LOWER(REGEXP_REPLACE(TRIM(finding.name), '\\s+', ' ', 'g'))
            || '|source:' || vulnerability_group.source_type
            || '|object:' || LOWER(REGEXP_REPLACE(TRIM(COALESCE(vulnerability_group.name, '')), '\\s+', ' ', 'g'))
    ELSE 'instance:' || TRIM(finding.vulnerability_instance_id)
END
""".strip()


CAPTURE_SNAPSHOT_SQL = f"""
WITH findings AS (
    SELECT
        {VULNERABILITY_SELECTOR_SQL} AS selector,
        finding.asset_id,
        finding.cve_name AS cve,
        {_normalized_severity("finding.severity")} AS severity,
        {_severity_rank("finding.severity")} AS severity_rank
    FROM asset_card_vulnerabilities AS finding
    JOIN asset_card_vulnerability_groups AS vulnerability_group
        ON vulnerability_group.id = finding.group_id
    JOIN asset_cards AS card
        ON card.asset_id = finding.asset_id
    WHERE COALESCE(
        NULLIF(TRIM(finding.vulnerability_id), ''),
        NULLIF(TRIM(finding.cve_name), ''),
        NULLIF(TRIM(finding.name), ''),
        NULLIF(TRIM(finding.vulnerability_instance_id), '')
    ) IS NOT NULL
),
coverage AS (
    SELECT
        COUNT(DISTINCT card.asset_id) AS cards_total,
        (SELECT COUNT(DISTINCT asset_id) FROM findings) AS cards_with_findings,
        COUNT(DISTINCT vulnerability_group.id)
            FILTER (WHERE vulnerability_group.truncated) AS truncated_groups,
        MIN(card.last_seen) AS oldest_at,
        MAX(card.last_seen) AS freshest_at
    FROM asset_cards AS card
    LEFT JOIN asset_card_vulnerability_groups AS vulnerability_group
        ON vulnerability_group.asset_id = card.asset_id
),
vulnerability_rollup AS (
    SELECT selector, MIN(severity_rank) AS severity_rank
    FROM findings
    GROUP BY selector
),
totals AS (
    SELECT
        COUNT(DISTINCT asset_id) AS affected_hosts,
        COUNT(*) AS findings,
        COUNT(DISTINCT selector) AS unique_vulnerabilities,
        COUNT(DISTINCT UPPER(TRIM(cve)))
            FILTER (WHERE NULLIF(TRIM(cve), '') IS NOT NULL) AS unique_cves,
        COUNT(DISTINCT asset_id) FILTER (WHERE severity_rank <= 2) AS high_risk_hosts,
        (SELECT COUNT(*) FROM vulnerability_rollup WHERE severity_rank = 5)
            AS unrated_vulnerabilities
    FROM findings
),
severity_names(severity, severity_rank) AS (
    VALUES ('critical', 1), ('high', 2), ('medium', 3), ('low', 4), ('unknown', 5)
),
severity_rollup AS (
    SELECT
        severity,
        COUNT(*) AS findings,
        COUNT(DISTINCT asset_id) AS affected_hosts,
        COUNT(DISTINCT selector) AS unique_vulnerabilities
    FROM findings
    GROUP BY severity
),
inserted_snapshot AS (
    INSERT INTO vulnerability_aggregate_snapshots (
        scope, trigger_kind, trigger_id, captured_at,
        hosts_total, affected_hosts, findings, unique_vulnerabilities,
        unique_cves, high_risk_hosts, unrated_vulnerabilities,
        coverage_cards_total, coverage_cards_with_findings,
        coverage_truncated_groups, coverage_complete,
        coverage_oldest_at, coverage_freshest_at
    )
    SELECT
        %s, %s, %s, %s,
        coverage.cards_total, totals.affected_hosts, totals.findings,
        totals.unique_vulnerabilities, totals.unique_cves,
        totals.high_risk_hosts, totals.unrated_vulnerabilities,
        coverage.cards_total, coverage.cards_with_findings,
        coverage.truncated_groups, coverage.truncated_groups = 0,
        coverage.oldest_at, coverage.freshest_at
    FROM coverage CROSS JOIN totals
    ON CONFLICT (trigger_kind, trigger_id) DO NOTHING
    RETURNING *
),
inserted_severity AS (
    INSERT INTO vulnerability_aggregate_snapshot_severity (
        snapshot_id, severity, findings, affected_hosts, unique_vulnerabilities
    )
    SELECT
        inserted_snapshot.id,
        severity_names.severity,
        COALESCE(severity_rollup.findings, 0),
        COALESCE(severity_rollup.affected_hosts, 0),
        COALESCE(severity_rollup.unique_vulnerabilities, 0)
    FROM inserted_snapshot
    CROSS JOIN severity_names
    LEFT JOIN severity_rollup USING (severity)
    ON CONFLICT (snapshot_id, severity) DO NOTHING
    RETURNING snapshot_id
)
SELECT inserted_snapshot.*,
       (SELECT COUNT(*) FROM inserted_severity) AS inserted_severity_count
FROM inserted_snapshot
"""


SNAPSHOT_SELECT_COLUMNS = """
snapshot.id,
snapshot.scope,
snapshot.trigger_kind,
snapshot.trigger_id,
snapshot.captured_at,
snapshot.hosts_total,
snapshot.affected_hosts,
snapshot.findings,
snapshot.unique_vulnerabilities,
snapshot.unique_cves,
snapshot.high_risk_hosts,
snapshot.unrated_vulnerabilities,
snapshot.coverage_cards_total,
snapshot.coverage_cards_with_findings,
snapshot.coverage_truncated_groups,
snapshot.coverage_complete,
snapshot.coverage_oldest_at,
snapshot.coverage_freshest_at,
severity.severity,
severity.findings AS severity_findings,
severity.affected_hosts AS severity_affected_hosts,
severity.unique_vulnerabilities AS severity_unique_vulnerabilities
""".strip()


def _page_bounds(limit: int, offset: int, *, maximum: int = 500) -> tuple[int, int]:
    return max(1, min(int(limit), maximum)), max(0, int(offset))


def _sort_sql(
    sort_by: str | None,
    sort_dir: str | None,
    allowed: dict[str, str],
    *,
    default: str,
    default_direction: str,
) -> tuple[str, str]:
    key = sort_by or default
    if key not in allowed:
        raise ValueError(f"Unsupported sort column: {key}")
    direction = (sort_dir or default_direction).lower()
    if direction not in {"asc", "desc"}:
        raise ValueError("sort_dir must be 'asc' or 'desc'")
    return allowed[key], direction.upper()


_PASSPORT_FIX_KEYS = (
    "howToFix",
    "solution",
    "recommendation",
    "remediation",
    "fixDescription",
)


def _passport_fix_sql(passport_alias: str) -> str:
    parts: list[str] = []
    for key in _PASSPORT_FIX_KEYS:
        parts.append(
            "NULLIF(CASE "
            f"WHEN jsonb_typeof({passport_alias}.raw_detail_json::jsonb -> '{key}') = 'string' "
            f"THEN {passport_alias}.raw_detail_json::jsonb ->> '{key}' "
            "END, '')"
        )
        parts.append(
            f"NULLIF({passport_alias}.raw_detail_json::jsonb #>> '{{{key},text}}', '')"
        )
        parts.append(
            f"NULLIF({passport_alias}.raw_detail_json::jsonb #>> '{{{key},description}}', '')"
        )
    return "COALESCE(\n    " + ",\n    ".join(parts) + "\n)"


def _has_fix_exists_sql(fix_text: str | None = None) -> tuple[str, list[Any]]:
    text_filter = ""
    params: list[Any] = []
    if fix_text:
        text_filter = f"\n      AND {_passport_fix_sql('fix_passport')} ILIKE %s"
        params.append(f"%{fix_text.strip()}%")
    return (
        "EXISTS (\n"
        "    SELECT 1\n"
        "    FROM asset_card_vulnerability_passports AS fix_link\n"
        "    JOIN vulnerability_passports AS fix_passport\n"
        "        ON fix_passport.internal_id = fix_link.passport_internal_id\n"
        "    WHERE fix_link.asset_vulnerability_id = finding.id\n"
        f"      AND {_passport_fix_sql('fix_passport')} IS NOT NULL{text_filter}\n"
        ")"
    ), params


def _fix_rollup_cte(
    selector_params: list[Any] | None = None,
    restrict_to_filtered: bool = False,
) -> str:
    selector_filter = ""
    if selector_params is not None:
        placeholders = ", ".join(["%s"] * len(selector_params))
        if placeholders:
            selector_filter = f"\n        AND {VULNERABILITY_SELECTOR_SQL} IN ({placeholders})"
        else:
            selector_filter = "\n        AND 1 = 0"
    elif restrict_to_filtered:
        # The filter sits in the inner query, where only ``finding`` is in scope.
        selector_filter = (
            f"\n        AND {VULNERABILITY_SELECTOR_SQL} IN "
            "(SELECT DISTINCT selector FROM filtered_findings)"
        )
    return (
        ", fix_rollup AS (\n"
        "    SELECT\n"
        "        fix_findings.selector,\n"
        "        MAX(fix_findings.how_to_fix) "
        "FILTER (WHERE fix_findings.how_to_fix IS NOT NULL) AS how_to_fix\n"
        "    FROM (\n"
        "        SELECT\n"
        f"            {VULNERABILITY_SELECTOR_SQL} AS selector,\n"
        f"            {_passport_fix_sql('fix_passport')} AS how_to_fix\n"
        "        FROM asset_card_vulnerabilities AS finding\n"
        "        JOIN asset_card_vulnerability_groups AS vulnerability_group\n"
        "            ON vulnerability_group.id = finding.group_id\n"
        "        JOIN asset_card_vulnerability_passports AS fix_link\n"
        "            ON fix_link.asset_vulnerability_id = finding.id\n"
        "        JOIN vulnerability_passports AS fix_passport\n"
        "            ON fix_passport.internal_id = fix_link.passport_internal_id\n"
        "        WHERE COALESCE(\n"
        "            NULLIF(TRIM(finding.vulnerability_id), ''),\n"
        "            NULLIF(TRIM(finding.cve_name), ''),\n"
        "            NULLIF(TRIM(finding.name), ''),\n"
        "            NULLIF(TRIM(finding.vulnerability_instance_id), '')\n"
        "        ) IS NOT NULL"
        f"{selector_filter}\n"
        "    ) AS fix_findings\n"
        "    GROUP BY fix_findings.selector\n"
        ")"
    )


def _fix_text_query(selectors: list[Any]) -> tuple[str, list[Any]]:
    """Bounded follow-up lookup: fix text only for the selected selectors."""
    unique_selectors = [value for value in dict.fromkeys(selectors) if value]
    if not unique_selectors:
        return "", []
    placeholders = ", ".join(["%s"] * len(unique_selectors))
    return (
        """
        SELECT
            fix_findings.selector,
            MAX(fix_findings.how_to_fix)
                FILTER (WHERE fix_findings.how_to_fix IS NOT NULL) AS how_to_fix
        FROM (
            SELECT
                """
        + VULNERABILITY_SELECTOR_SQL
        + """ AS selector,
                """
        + _passport_fix_sql("fix_passport")
        + """ AS how_to_fix
            FROM asset_card_vulnerabilities AS finding
            JOIN asset_card_vulnerability_groups AS vulnerability_group
                ON vulnerability_group.id = finding.group_id
            JOIN asset_card_vulnerability_passports AS fix_link
                ON fix_link.asset_vulnerability_id = finding.id
            JOIN vulnerability_passports AS fix_passport
                ON fix_passport.internal_id = fix_link.passport_internal_id
            WHERE COALESCE(
                NULLIF(TRIM(finding.vulnerability_id), ''),
                NULLIF(TRIM(finding.cve_name), ''),
                NULLIF(TRIM(finding.name), ''),
                NULLIF(TRIM(finding.vulnerability_instance_id), '')
            ) IS NOT NULL
              AND """
        + VULNERABILITY_SELECTOR_SQL
        + f" IN ({placeholders})\n"
        "        ) AS fix_findings\n"
        "        GROUP BY fix_findings.selector\n"
    ), unique_selectors


def _attach_fix_text(
    rows: list[dict[str, Any]],
    fix_map: dict[Any, Any] | None,
) -> list[dict[str, Any]]:
    for row in rows:
        how_to_fix = (fix_map or {}).get(row.get("selector"))
        row["how_to_fix"] = (how_to_fix or "").strip() or None
        row["has_fix"] = bool((how_to_fix or "").strip())
    return rows


HAS_FIX_FILTER_VALUES = {"yes", "no", "any"}
SUMMARY_FINDINGS_TABLE = "vulnerability_summary_findings"


def _filtered_findings_cte(
    *,
    q: str | None = None,
    host_q: str | None = None,
    os: str | None = None,
    asset_type: str | None = None,
    asset_id: str | None = None,
    severity: str | None = None,
    source: VulnerabilitySource | None = None,
    has_fix: str | None = None,
    fix_q: str | None = None,
    selector: str | None = None,
    include_details: bool = True,
) -> tuple[str, list[Any]]:
    filters = [
        "COALESCE(NULLIF(TRIM(finding.vulnerability_id), ''), "
        "NULLIF(TRIM(finding.cve_name), ''), NULLIF(TRIM(finding.name), ''), "
        "NULLIF(TRIM(finding.vulnerability_instance_id), '')) IS NOT NULL"
    ]
    params: list[Any] = []
    if q:
        like = f"%{q.strip()}%"
        # One UNION branch per searched column: an OR that spans finding and
        # group columns cannot use any index, while each branch can use its own
        # trigram index (migration 0035). Matches exactly the same findings.
        filters.append(
            "finding.id IN ("
            "SELECT id FROM asset_card_vulnerabilities WHERE vulnerability_id ILIKE %s "
            "UNION SELECT id FROM asset_card_vulnerabilities WHERE cve_name ILIKE %s "
            "UNION SELECT id FROM asset_card_vulnerabilities WHERE name ILIKE %s "
            "UNION SELECT matched.id FROM asset_card_vulnerability_groups AS matched_group "
            "JOIN asset_card_vulnerabilities AS matched ON matched.group_id = matched_group.id "
            "WHERE matched_group.name ILIKE %s)"
        )
        params.extend([like, like, like, like])
    if host_q:
        like = f"%{host_q.strip()}%"
        filters.append(
            "(card.asset_id ILIKE %s OR card.display_name ILIKE %s OR card.hostname ILIKE %s "
            "OR card.fqdn ILIKE %s OR card.ip_address ILIKE %s)"
        )
        params.extend([like, like, like, like, like])
    if os:
        like = f"%{os.strip()}%"
        filters.append("(card.os_name ILIKE %s OR card.os_version ILIKE %s)")
        params.extend([like, like])
    if asset_type:
        filters.append("card.asset_type ILIKE %s")
        params.append(f"%{asset_type.strip()}%")
    if asset_id:
        filters.append("card.asset_id = %s")
        params.append(asset_id.strip())
    if severity:
        normalized = severity.strip().lower()
        normalized = normalized if normalized in {"critical", "high", "medium", "low"} else "unknown"
        filters.append(f"{_normalized_severity('finding.severity')} = %s")
        params.append(normalized)
    if source:
        filters.append("vulnerability_group.source_type = %s")
        params.append(source)
    if has_fix:
        normalized = has_fix.strip().lower()
        if normalized not in HAS_FIX_FILTER_VALUES:
            raise ValueError(f"Unsupported has_fix filter: {has_fix}")
        if normalized == "yes":
            sql, fix_params = _has_fix_exists_sql(fix_q)
            filters.append(sql)
            params.extend(fix_params)
        elif normalized == "no":
            sql, fix_params = _has_fix_exists_sql(fix_q)
            filters.append(f"NOT {sql}")
            params.extend(fix_params)
    if selector:
        filters.append(f"({VULNERABILITY_SELECTOR_SQL}) = %s")
        params.append(selector)

    where = " AND ".join(filters)
    detail_columns = f""",
                finding.id AS finding_id,
                finding.vulnerability_id,
                finding.vulnerability_instance_id,
                finding.cve_name AS cve,
                finding.name,
                {_normalized_severity("finding.severity")} AS severity,
                {_severity_rank("finding.severity")} AS severity_rank,
                finding.cvss_score,
                finding.updated_at,
                vulnerability_group.id AS group_id,
                vulnerability_group.source_type,
                vulnerability_group.collection_id,
                vulnerability_group.name AS object_name,
                vulnerability_group.truncated,
                CASE
                    WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                        NULLIF(finding.vulnerability_json::jsonb ->> 'container_name', ''),
                        NULLIF(finding.vulnerability_json::jsonb #>> '{{docker_container,container_name}}', ''),
                        NULLIF(vulnerability_group.group_json::jsonb ->> 'container_name', ''),
                        NULLIF(vulnerability_group.name, '')
                    )
                    ELSE NULL
                END AS container_name,
                CASE
                    WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                        NULLIF(finding.vulnerability_json::jsonb #>> '{{docker_image,image_name}}', ''),
                        NULLIF(vulnerability_group.group_json::jsonb ->> 'image_name', ''),
                        NULLIF(finding.vulnerability_json::jsonb ->> 'image_id', ''),
                        NULLIF(finding.vulnerability_json::jsonb #>> '{{docker_image,image_key}}', '')
                    )
                    ELSE NULL
                END AS image_name,
                card.asset_id,
                card.display_name,
                card.hostname,
                card.fqdn,
                card.ip_address,
                card.os_name,
                card.os_version,
                card.asset_type,
                card.last_seen
    """ if include_details else ""
    cte = f"""
        WITH filtered_findings AS (
            SELECT
                {VULNERABILITY_SELECTOR_SQL} AS selector
                {detail_columns}
            FROM asset_card_vulnerabilities AS finding
            JOIN asset_card_vulnerability_groups AS vulnerability_group
                ON vulnerability_group.id = finding.group_id
            JOIN asset_cards AS card
                ON card.asset_id = finding.asset_id
            WHERE {where}
        )
    """
    return cte, params


def _decode_vulnerability(row: dict[str, Any]) -> dict[str, Any]:
    cvss_score = decimal_to_number(row.get("cvss_score"))
    passports = list(row.get("passports") or [])
    short_description = next(
        (
            str(passport.get("short_description")).strip()
            for passport in passports
            if isinstance(passport, dict) and passport.get("short_description")
        ),
        None,
    )
    return {
        "selector": row.get("selector"),
        "vulnerability_id": row.get("vulnerability_id"),
        "cve": row.get("cve"),
        "name": row.get("name"),
        "severity": row.get("severity") or "unknown",
        "cvss_score": cvss_score,
        "max_cvss": cvss_score,
        "affected_hosts": int(row.get("affected_hosts") or 0),
        "findings": int(row.get("findings") or 0),
        "affected_objects": int(row.get("affected_objects") or 0),
        "components": list(row.get("components") or []),
        "sources": list(row.get("sources") or []),
        "docker_containers": list(row.get("docker_containers") or []),
        "docker_images": list(row.get("docker_images") or []),
        "passports": passports,
        "short_description": short_description,
        "how_to_fix": (row.get("how_to_fix") or "").strip() or None,
        "has_fix": bool((row.get("how_to_fix") or "").strip()),
        "last_seen": row.get("last_seen"),
    }


def _decode_trending_passport(row: dict[str, Any]) -> dict[str, Any]:
    cves = json_loads(row.get("cves_json"), [])
    cves = cves if isinstance(cves, list) else []
    cve = None
    for item in cves:
        if isinstance(item, str) and item.strip():
            cve = item.strip()
            break
        if isinstance(item, dict):
            cve = next(
                (
                    str(item.get(key)).strip()
                    for key in ("display_name", "displayName", "cve", "name", "value", "id")
                    if item.get(key)
                ),
                None,
            )
            if cve:
                break
    external_id = row.get("external_id")
    if not cve and str(external_id or "").upper().startswith("CVE-"):
        cve = str(external_id)

    score = decimal_to_number(row.get("score_numeric"))
    if score is None:
        score = row.get("score")
    severity = str(row.get("severity") or "").strip().lower()
    if severity not in {"critical", "high", "medium", "low"}:
        numeric_score = decimal_to_number(row.get("score_numeric"))
        if numeric_score is None:
            severity = "unknown"
        elif numeric_score >= 9:
            severity = "critical"
        elif numeric_score >= 7:
            severity = "high"
        elif numeric_score >= 4:
            severity = "medium"
        else:
            severity = "low"

    vendors = json_loads(row.get("vendors_json"), [])
    components = json_loads(row.get("affected_components_json"), [])
    sources = list(row.get("sources") or [])
    contexts = []
    if "docker" in sources:
        contexts.append("docker")
    if any(source in {"os", "software"} for source in sources):
        contexts.append("software_os")
    return {
        "internal_id": row.get("internal_id"),
        "external_id": external_id,
        "cve": cve,
        "name": row.get("name"),
        "severity": severity,
        "score": score,
        "description": row.get("description"),
        "issue_time": row.get("issue_time"),
        "is_trend_since": row.get("is_trend_since"),
        "vendors": vendors if isinstance(vendors, list) else [],
        "affected_components": components if isinstance(components, list) else [],
        "affected_hosts": int(row.get("affected_hosts") or 0),
        "affected_hosts_total": int(row.get("affected_hosts_total") or 0),
        "docker_affected_hosts": int(row.get("docker_affected_hosts") or 0),
        "software_os_affected_hosts": int(row.get("software_os_affected_hosts") or 0),
        "findings": int(row.get("findings") or 0),
        "findings_total": int(row.get("findings_total") or 0),
        "docker_findings": int(row.get("docker_findings") or 0),
        "software_os_findings": int(row.get("software_os_findings") or 0),
        "sources": sources,
        "contexts": contexts,
        "docker_containers": list(row.get("docker_containers") or []),
        "docker_images": list(row.get("docker_images") or []),
        "synced_at": row.get("synced_at"),
    }


def _decode_host(row: dict[str, Any]) -> dict[str, Any]:
    cvss_score = decimal_to_number(row.get("cvss_score"))
    remediation = None
    if row.get("remediation_case_id"):
        remediation = {
            "case_id": row.get("remediation_case_id"),
            "version": int(row.get("remediation_version") or 0),
            "status": row.get("remediation_status"),
            "assignee": row.get("remediation_assignee"),
            "due_at": row.get("remediation_due_at"),
            "resolved_at": row.get("remediation_resolved_at"),
            "overdue": bool(row.get("remediation_overdue")),
        }
    return {
        "asset_id": row.get("asset_id"),
        "display_name": row.get("display_name"),
        "hostname": row.get("hostname"),
        "fqdn": row.get("fqdn"),
        "ip_address": row.get("ip_address"),
        "os_name": row.get("os_name"),
        "os_version": row.get("os_version"),
        "asset_type": row.get("asset_type"),
        "severity": row.get("severity") or "unknown",
        "cvss_score": cvss_score,
        "max_cvss": cvss_score,
        "finding_count": int(row.get("finding_count") or 0),
        "unique_vulnerabilities": int(row.get("unique_vulnerabilities") or 0),
        "high_risk_vulnerabilities": int(row.get("high_risk_vulnerabilities") or 0),
        "objects": list(row.get("objects") or []),
        "sources": list(row.get("sources") or []),
        "docker_containers": list(row.get("docker_containers") or []),
        "docker_images": list(row.get("docker_images") or []),
        "last_seen": row.get("last_seen"),
        "remediation": remediation,
    }


def _decode_snapshot_rows(rows: list[Any]) -> list[dict[str, Any]]:
    snapshots: dict[int, dict[str, Any]] = {}
    for raw_row in rows:
        row = dict(raw_row)
        snapshot_id = int(row["id"])
        snapshot = snapshots.get(snapshot_id)
        if snapshot is None:
            snapshot = {
                "id": snapshot_id,
                "scope": row.get("scope") or VULNERABILITY_TRENDS_SCOPE,
                "trigger_kind": row.get("trigger_kind"),
                "trigger_id": row.get("trigger_id"),
                "captured_at": row.get("captured_at"),
                "totals": {
                    "hosts_total": int(row.get("hosts_total") or 0),
                    "affected_hosts": int(row.get("affected_hosts") or 0),
                    "findings": int(row.get("findings") or 0),
                    "unique_vulnerabilities": int(row.get("unique_vulnerabilities") or 0),
                    "unique_cves": int(row.get("unique_cves") or 0),
                    "high_risk_hosts": int(row.get("high_risk_hosts") or 0),
                    "unrated_vulnerabilities": int(row.get("unrated_vulnerabilities") or 0),
                },
                "by_severity": {
                    severity: {
                        "findings": 0,
                        "affected_hosts": 0,
                        "unique_vulnerabilities": 0,
                    }
                    for severity in VULNERABILITY_SEVERITIES
                },
                "coverage": {
                    "cards_total": int(row.get("coverage_cards_total") or 0),
                    "cards_with_findings": int(row.get("coverage_cards_with_findings") or 0),
                    "truncated_groups": int(row.get("coverage_truncated_groups") or 0),
                    "complete": bool(row.get("coverage_complete")),
                    "oldest_at": row.get("coverage_oldest_at"),
                    "freshest_at": row.get("coverage_freshest_at"),
                },
            }
            snapshots[snapshot_id] = snapshot

        severity = row.get("severity")
        if severity in VULNERABILITY_SEVERITIES:
            snapshot["by_severity"][severity] = {
                "findings": int(row.get("severity_findings") or 0),
                "affected_hosts": int(row.get("severity_affected_hosts") or 0),
                "unique_vulnerabilities": int(row.get("severity_unique_vulnerabilities") or 0),
            }
    return list(snapshots.values())


_VALID_FINDING_SQL = """COALESCE(
    NULLIF(TRIM(finding.vulnerability_id), ''),
    NULLIF(TRIM(finding.cve_name), ''),
    NULLIF(TRIM(finding.name), ''),
    NULLIF(TRIM(finding.vulnerability_instance_id), '')
) IS NOT NULL"""

# Shared by the live aggregate and the rollup fast path: both provide ``paged``
# (one row per selector of the page) and ``filtered_findings`` (selector,
# finding_id of the findings behind those selectors).
_PASSPORT_PAGE_CTES = """, mapped_passports AS (
                SELECT
                    paged.selector,
                    passport.internal_id,
                    passport.external_id,
                    passport.name,
                    passport.severity,
                    passport.score,
                    passport.issue_time,
                    passport.package_id,
                    passport.package_version,
                    COALESCE(NULLIF(passport.cves_json, ''), '[]')::jsonb AS cves,
                    COALESCE(
                        NULLIF(CASE
                            WHEN jsonb_typeof(passport.raw_detail_json::jsonb -> 'description') = 'string'
                            THEN passport.raw_detail_json::jsonb ->> 'description'
                        END, ''),
                        NULLIF(passport.raw_detail_json::jsonb #>> '{description,text}', ''),
                        NULLIF(passport.raw_detail_json::jsonb #>> '{description,description}', ''),
                        NULLIF(CASE
                            WHEN jsonb_typeof(passport.raw_detail_json::jsonb -> 'vulnerabilityDescription') = 'string'
                            THEN passport.raw_detail_json::jsonb ->> 'vulnerabilityDescription'
                        END, ''),
                        NULLIF(passport.raw_detail_json::jsonb #>> '{vulnerabilityDescription,text}', ''),
                        NULLIF(passport.raw_detail_json::jsonb #>> '{details,description}', ''),
                        NULLIF(CASE
                            WHEN jsonb_typeof(passport.raw_detail_json::jsonb -> 'localizedDescription') = 'string'
                            THEN passport.raw_detail_json::jsonb ->> 'localizedDescription'
                        END, ''),
                        NULLIF(passport.raw_detail_json::jsonb #>> '{localizedDescription,text}', '')
                    ) AS short_description,
                    BOOL_OR(passport.raw_detail_json IS NOT NULL) AS has_detail,
                    MIN(
                        CASE link.match_method WHEN 'vulner_id' THEN 0 ELSE 1 END
                    ) AS match_priority
                FROM paged
                JOIN filtered_findings
                    ON filtered_findings.selector = paged.selector
                JOIN asset_card_vulnerability_passports AS link
                    ON link.asset_vulnerability_id = filtered_findings.finding_id
                JOIN vulnerability_passports AS passport
                    ON passport.internal_id = link.passport_internal_id
                GROUP BY
                    paged.selector,
                    passport.internal_id,
                    passport.external_id,
                    passport.name,
                    passport.severity,
                    passport.score,
                    passport.issue_time,
                    passport.package_id,
                    passport.package_version,
                    passport.cves_json,
                    passport.raw_detail_json
            ), passport_rollup AS (
                SELECT
                    selector,
                    JSONB_AGG(
                        JSONB_BUILD_OBJECT(
                            'internal_id', internal_id,
                            'external_id', external_id,
                            'name', name,
                            'severity', severity,
                            'score', score,
                            'issue_time', issue_time,
                            'package_id', package_id,
                            'package_version', package_version,
                            'cves', cves,
                            'short_description', short_description,
                            'has_detail', has_detail
                        ) ORDER BY match_priority, internal_id
                    ) AS passports
                FROM mapped_passports
                GROUP BY selector
            )
"""

# The unfiltered list is served from the exact, trigger-maintained rollup table
# (migration 0037). The switch exists to fall back to the live aggregate.
ROLLUP_ENABLED = os.getenv("MPVM_VULNERABILITY_ROLLUP_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
# Sorts that need data the rollup does not hold go through the live aggregate.
_ROLLUP_SORTS = {None, "", "affected_hosts", "findings", "severity", "cvss_score", "max_cvss", "name", "cve"}


class VulnerabilityAnalyticsRepository:
    """Analytics over the latest asset cards and their retained aggregates."""

    def capture_snapshot(
        self,
        *,
        trigger_kind: str,
        trigger_id: str,
        captured_at: datetime | None = None,
        scope: str = VULNERABILITY_TRENDS_SCOPE,
        retention_days: int = VULNERABILITY_TRENDS_RETENTION_DAYS,
    ) -> dict[str, Any]:
        clean_kind = trigger_kind.strip()
        clean_id = trigger_id.strip()
        clean_scope = scope.strip()
        if not clean_kind or not clean_id:
            raise ValueError("trigger_kind and trigger_id must not be empty")
        if not clean_scope:
            raise ValueError("scope must not be empty")
        if retention_days < 1:
            raise ValueError("retention_days must be positive")

        capture_time = captured_at or datetime.now(UTC)
        if capture_time.tzinfo is None:
            capture_time = capture_time.replace(tzinfo=UTC)
        else:
            capture_time = capture_time.astimezone(UTC)

        schema.init_db()
        with connection.connect() as conn:
            inserted = conn.execute(
                CAPTURE_SNAPSHOT_SQL,
                (clean_scope, clean_kind, clean_id, capture_time),
            ).fetchone()
            created = inserted is not None
            if inserted is not None:
                self._prune_retained_snapshots(
                    conn,
                    snapshot_id=int(inserted["id"]),
                    captured_at=capture_time,
                    retention_days=retention_days,
                    scope=clean_scope,
                )
            snapshot = self._snapshot_by_trigger(conn, clean_kind, clean_id)

        if snapshot is None:
            raise RuntimeError("Snapshot insert did not return or persist a row")
        return {"created": created, "snapshot": snapshot}

    def ensure_baseline(
        self,
        *,
        captured_at: datetime | None = None,
        trigger_id: str = "vulnerability-trends-v1",
    ) -> dict[str, Any]:
        return self.capture_snapshot(
            trigger_kind="baseline",
            trigger_id=trigger_id,
            captured_at=captured_at,
        )

    def trend_snapshots(
        self,
        *,
        from_at: datetime,
        to_at: datetime,
        scope: str = VULNERABILITY_TRENDS_SCOPE,
    ) -> list[dict[str, Any]]:
        schema.init_db()
        with connection.connect() as conn:
            rows = conn.execute(
                f"""
                WITH range_snapshots AS (
                    SELECT source.*
                    FROM vulnerability_aggregate_snapshots AS source
                    WHERE source.scope = %s
                      AND source.captured_at >= %s
                      AND source.captured_at <= %s
                ),
                predecessor AS (
                    SELECT source.*
                    FROM vulnerability_aggregate_snapshots AS source
                    WHERE source.scope = %s
                      AND source.captured_at < %s
                    ORDER BY source.captured_at DESC, source.id DESC
                    LIMIT 1
                ),
                selected_snapshots AS (
                    SELECT * FROM range_snapshots
                    UNION ALL
                    SELECT * FROM predecessor
                )
                SELECT {SNAPSHOT_SELECT_COLUMNS}
                FROM selected_snapshots AS snapshot
                LEFT JOIN vulnerability_aggregate_snapshot_severity AS severity
                    ON severity.snapshot_id = snapshot.id
                ORDER BY
                    snapshot.captured_at ASC,
                    snapshot.id ASC,
                    CASE severity.severity
                        WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4 ELSE 5
                    END
                """,
                (scope, from_at, to_at, scope, from_at),
            ).fetchall()
        return _decode_snapshot_rows(rows)

    def _snapshot_by_trigger(
        self,
        conn: Any,
        trigger_kind: str,
        trigger_id: str,
    ) -> dict[str, Any] | None:
        rows = conn.execute(
            f"""
            SELECT {SNAPSHOT_SELECT_COLUMNS}
            FROM vulnerability_aggregate_snapshots AS snapshot
            LEFT JOIN vulnerability_aggregate_snapshot_severity AS severity
                ON severity.snapshot_id = snapshot.id
            WHERE snapshot.trigger_kind = %s AND snapshot.trigger_id = %s
            ORDER BY CASE severity.severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                WHEN 'low' THEN 4 ELSE 5
            END
            """,
            (trigger_kind, trigger_id),
        ).fetchall()
        decoded = _decode_snapshot_rows(rows)
        return decoded[0] if decoded else None

    def _prune_retained_snapshots(
        self,
        conn: Any,
        *,
        snapshot_id: int,
        captured_at: datetime,
        retention_days: int,
        scope: str,
    ) -> None:
        lock_row = conn.execute(
            "SELECT pg_try_advisory_xact_lock(%s) AS acquired",
            (_RETENTION_ADVISORY_LOCK_KEY,),
        ).fetchone()
        if not lock_row or not bool(lock_row.get("acquired")):
            return
        due_row = conn.execute(
            """
            SELECT NOT EXISTS (
                SELECT 1
                FROM vulnerability_aggregate_snapshots
                WHERE scope = %s
                  AND id <> %s
                  AND captured_at >= date_trunc('day', %s::timestamptz)
                  AND captured_at < date_trunc('day', %s::timestamptz) + INTERVAL '1 day'
            ) AS due
            """,
            (scope, snapshot_id, captured_at, captured_at),
        ).fetchone()
        if due_row and bool(due_row.get("due")):
            conn.execute(
                """
                DELETE FROM vulnerability_aggregate_snapshots
                WHERE scope = %s
                  AND captured_at < %s::timestamptz - make_interval(days => %s)
                """,
                (scope, captured_at, retention_days),
            )

    def summary(
        self,
        *,
        q: str | None = None,
        host_q: str | None = None,
        os: str | None = None,
        asset_type: str | None = None,
        asset_id: str | None = None,
        severity: str | None = None,
        source: VulnerabilitySource | None = None,
        has_fix: str | None = None,
        fix_q: str | None = None,
    ) -> dict[str, Any]:
        schema.init_db()
        use_rollup = ROLLUP_ENABLED and not any(
            (q, host_q, os, asset_type, asset_id, severity, source, has_fix, fix_q)
        )
        cte, params = _filtered_findings_cte(
            q=q,
            host_q=host_q,
            os=os,
            asset_type=asset_type,
            asset_id=asset_id,
            severity=severity,
            source=source,
            has_fix=has_fix,
            fix_q=fix_q,
        )
        findings_cte = f"WITH filtered_findings AS (SELECT * FROM {SUMMARY_FINDINGS_TABLE})"
        with connection.connect() as conn:
            # Per-card EXISTS stops at the first finding instead of joining every finding row.
            coverage_row = dict(
                conn.execute(
                    """
                    SELECT
                        COUNT(*) AS cards_total,
                        COUNT(*) FILTER (WHERE EXISTS (
                            SELECT 1
                            FROM asset_card_vulnerability_groups AS vulnerability_group
                            JOIN asset_card_vulnerabilities AS finding
                                ON finding.group_id = vulnerability_group.id
                            WHERE vulnerability_group.asset_id = card.asset_id
                              AND COALESCE(
                                NULLIF(TRIM(finding.vulnerability_id), ''),
                                NULLIF(TRIM(finding.cve_name), ''),
                                NULLIF(TRIM(finding.name), ''),
                                NULLIF(TRIM(finding.vulnerability_instance_id), '')
                              ) IS NOT NULL
                        )) AS cards_with_findings,
                        (
                            SELECT COUNT(*)
                            FROM asset_card_vulnerability_groups AS vulnerability_group
                            JOIN asset_cards AS owner ON owner.asset_id = vulnerability_group.asset_id
                            WHERE vulnerability_group.truncated
                        ) AS truncated_groups,
                        MIN(card.last_seen) AS oldest_at,
                        MAX(card.last_seen) AS freshest_at
                    FROM asset_cards AS card
                    """
                ).fetchone()
                or {}
            )
            if use_rollup:
                (
                    totals_row,
                    severity_rows,
                    top_vulnerability_rows,
                    top_host_rows,
                ) = self._rollup_summary_rows(conn)
                fix_map = self._top_fix_map(conn, top_vulnerability_rows)
            else:
                # The filtered join is the expensive part: run it once and aggregate the snapshot.
                conn.execute(
                    f"CREATE TEMP TABLE {SUMMARY_FINDINGS_TABLE} ON COMMIT DROP AS "
                    + cte
                    + " SELECT * FROM filtered_findings",
                    params,
                )
                totals_row = dict(
                    conn.execute(
                        findings_cte
                        + """
                        , vulnerability_rollup AS (
                            SELECT selector, MIN(severity_rank) AS severity_rank
                            FROM filtered_findings
                            GROUP BY selector
                        )
                        SELECT
                            COUNT(DISTINCT asset_id) AS affected_hosts,
                            COUNT(*) AS findings,
                            COUNT(DISTINCT selector) AS unique_vulnerabilities,
                            COUNT(DISTINCT UPPER(TRIM(cve)))
                                FILTER (WHERE NULLIF(TRIM(cve), '') IS NOT NULL) AS unique_cves,
                            COUNT(DISTINCT asset_id) FILTER (WHERE severity_rank <= 2) AS high_risk_hosts,
                            (SELECT COUNT(*) FROM vulnerability_rollup WHERE severity_rank = 5)
                                AS unrated_vulnerabilities
                        FROM filtered_findings
                        """,
                    ).fetchone()
                    or {}
                )
                severity_rows = conn.execute(
                    findings_cte
                    + """
                    SELECT
                        severity,
                        MIN(severity_rank) AS severity_rank,
                        COUNT(*) AS findings,
                        COUNT(DISTINCT asset_id) AS affected_hosts,
                        COUNT(DISTINCT selector) AS unique_vulnerabilities
                    FROM filtered_findings
                    GROUP BY severity
                    ORDER BY severity_rank
                    """,
                ).fetchall()
                top_vulnerability_rows = conn.execute(
                    findings_cte
                    + """
                    SELECT
                        aggregated.selector,
                        aggregated.vulnerability_id,
                        aggregated.cve,
                        aggregated.name,
                        aggregated.severity,
                        aggregated.severity_rank,
                        aggregated.cvss_score,
                        aggregated.affected_hosts,
                        aggregated.findings,
                        aggregated.affected_objects,
                        aggregated.components,
                        aggregated.sources,
                        aggregated.docker_containers,
                        aggregated.docker_images,
                        aggregated.passports,
                        aggregated.last_seen
                    FROM (
                        SELECT
                            selector,
                            MAX(NULLIF(vulnerability_id, '')) AS vulnerability_id,
                            MAX(NULLIF(cve, '')) AS cve,
                            MAX(NULLIF(name, '')) AS name,
                            CASE MIN(severity_rank)
                                WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                                WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                            MIN(severity_rank) AS severity_rank,
                            MAX(cvss_score) AS cvss_score,
                            COUNT(DISTINCT asset_id) AS affected_hosts,
                            COUNT(*) AS findings,
                            COUNT(DISTINCT group_id) AS affected_objects,
                            ARRAY_AGG(DISTINCT object_name ORDER BY object_name)
                                FILTER (WHERE NULLIF(object_name, '') IS NOT NULL)
                                AS components,
                            ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                            ARRAY_AGG(DISTINCT container_name ORDER BY container_name)
                                FILTER (WHERE NULLIF(container_name, '') IS NOT NULL)
                                AS docker_containers,
                            ARRAY_AGG(DISTINCT image_name ORDER BY image_name)
                                FILTER (WHERE NULLIF(image_name, '') IS NOT NULL)
                                AS docker_images,
                            '[]'::jsonb AS passports,
                            MAX(last_seen) AS last_seen
                        FROM filtered_findings
                        GROUP BY selector
                        ORDER BY affected_hosts DESC, findings DESC, selector ASC
                        LIMIT 8
                    ) AS aggregated
                    ORDER BY aggregated.affected_hosts DESC, aggregated.findings DESC,
                        aggregated.selector ASC
                    """,
                ).fetchall()
                fix_map = self._top_fix_map(conn, top_vulnerability_rows)
                top_host_rows = conn.execute(
                    findings_cte
                    + """
                    SELECT
                        asset_id,
                        MAX(display_name) AS display_name,
                        MAX(hostname) AS hostname,
                        MAX(fqdn) AS fqdn,
                        MAX(ip_address) AS ip_address,
                        MAX(os_name) AS os_name,
                        MAX(os_version) AS os_version,
                        MAX(asset_type) AS asset_type,
                        CASE MIN(severity_rank)
                            WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                            WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                        MAX(cvss_score) AS cvss_score,
                        COUNT(*) AS finding_count,
                        COUNT(DISTINCT selector) AS unique_vulnerabilities,
                        COUNT(DISTINCT selector) FILTER (WHERE severity_rank <= 2)
                            AS high_risk_vulnerabilities,
                        ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                        MAX(last_seen) AS last_seen
                    FROM filtered_findings
                    GROUP BY asset_id
                    ORDER BY finding_count DESC, high_risk_vulnerabilities DESC,
                        unique_vulnerabilities DESC, asset_id
                    LIMIT 8
                    """,
                ).fetchall()

        coverage = {
            "cards_total": int(coverage_row.get("cards_total") or 0),
            "cards_with_findings": int(coverage_row.get("cards_with_findings") or 0),
            "truncated_groups": int(coverage_row.get("truncated_groups") or 0),
            "complete": int(coverage_row.get("truncated_groups") or 0) == 0,
            "scope": "all_asset_cards",
            "oldest_at": coverage_row.get("oldest_at"),
            "freshest_at": coverage_row.get("freshest_at"),
        }
        totals = {
            "hosts_total": coverage["cards_total"],
            "affected_hosts": int(totals_row.get("affected_hosts") or 0),
            "findings": int(totals_row.get("findings") or 0),
            "unique_vulnerabilities": int(totals_row.get("unique_vulnerabilities") or 0),
            "unique_cves": int(totals_row.get("unique_cves") or 0),
            "high_risk_hosts": int(totals_row.get("high_risk_hosts") or 0),
            "unrated_vulnerabilities": int(totals_row.get("unrated_vulnerabilities") or 0),
        }
        return {
            "source": {
                "kind": "asset_cards",
                "label": "Сохранённые карточки активов PostgreSQL",
                "as_of": coverage["freshest_at"],
                "historical": False,
            },
            "filters": {
                "q": q or "",
                "host_q": host_q or "",
                "os": os or "",
                "asset_type": asset_type or "",
                "asset_id": asset_id or "",
                "severity": severity or "",
                "source": source or "",
                "has_fix": has_fix or "",
                "fix_q": fix_q or "",
            },
            "totals": totals,
            "by_severity": [
                {
                    "severity": row.get("severity") or "unknown",
                    "findings": int(row.get("findings") or 0),
                    "affected_hosts": int(row.get("affected_hosts") or 0),
                    "unique_vulnerabilities": int(row.get("unique_vulnerabilities") or 0),
                }
                for row in severity_rows
            ],
            "coverage": coverage,
            "top_vulnerabilities": [
                _decode_vulnerability(dict(row))
                for row in _attach_fix_text(top_vulnerability_rows, fix_map)
            ],
            "top_hosts": [_decode_host(dict(row)) for row in top_host_rows],
        }

    def trending(self, *, limit: int = 20, context: str = "all") -> dict[str, Any]:
        limit = min(100, max(1, int(limit)))
        if context not in {"all", "docker", "host"}:
            raise ValueError("Unsupported trending vulnerability context.")
        context_filter = {
            "all": "",
            "docker": "WHERE COALESCE(host_counts.docker_affected_hosts, 0) > 0",
            "host": "WHERE COALESCE(host_counts.software_os_affected_hosts, 0) > 0",
        }[context]
        affected_hosts_expression = {
            "all": "COALESCE(host_counts.affected_hosts_total, 0)",
            "docker": "COALESCE(host_counts.docker_affected_hosts, 0)",
            "host": "COALESCE(host_counts.software_os_affected_hosts, 0)",
        }[context]
        findings_expression = {
            "all": "COALESCE(host_counts.findings_total, 0)",
            "docker": "COALESCE(host_counts.docker_findings, 0)",
            "host": "COALESCE(host_counts.software_os_findings, 0)",
        }[context]
        schema.init_db()
        with connection.connect() as conn:
            rows = conn.execute(
                f"""
                WITH trend_passports AS (
                    SELECT
                        passport.internal_id,
                        passport.external_id,
                        passport.name,
                        passport.severity,
                        passport.score,
                        passport.issue_time,
                        passport.cves_json,
                        trend.description,
                        trend.is_trend_since,
                        trend.vendors_json,
                        trend.affected_components_json,
                        trend.synced_at,
                        CASE
                            WHEN REPLACE(COALESCE(passport.score, ''), ',', '.')
                                ~ '^[0-9]+([.][0-9]+)?$'
                            THEN REPLACE(passport.score, ',', '.')::numeric
                            ELSE NULL
                        END AS score_numeric
                    FROM vulnerability_passport_trends AS trend
                    JOIN vulnerability_passports AS passport
                        ON passport.internal_id = trend.passport_internal_id
                ), trend_findings AS (
                    SELECT
                        link.passport_internal_id,
                        finding.asset_id,
                        vulnerability_group.source_type,
                        CASE
                            WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                                NULLIF(finding.vulnerability_json::jsonb ->> 'container_name', ''),
                                NULLIF(finding.vulnerability_json::jsonb -> 'docker_container' ->> 'container_name', ''),
                                NULLIF(vulnerability_group.group_json::jsonb ->> 'container_name', ''),
                                NULLIF(vulnerability_group.name, '')
                            )
                            ELSE NULL
                        END AS container_name,
                        CASE
                            WHEN vulnerability_group.source_type = 'docker' THEN COALESCE(
                                NULLIF(finding.vulnerability_json::jsonb -> 'docker_image' ->> 'image_name', ''),
                                NULLIF(vulnerability_group.group_json::jsonb ->> 'image_name', ''),
                                NULLIF(finding.vulnerability_json::jsonb ->> 'image_id', ''),
                                NULLIF(finding.vulnerability_json::jsonb -> 'docker_image' ->> 'image_key', '')
                            )
                            ELSE NULL
                        END AS image_name
                    FROM trend_passports
                    JOIN asset_card_vulnerability_passports AS link
                        ON link.passport_internal_id = trend_passports.internal_id
                    JOIN asset_card_vulnerabilities AS finding
                        ON finding.id = link.asset_vulnerability_id
                    JOIN asset_card_vulnerability_groups AS vulnerability_group
                        ON vulnerability_group.id = finding.group_id
                ), host_counts AS (
                    SELECT
                        passport_internal_id,
                        COUNT(DISTINCT asset_id) AS affected_hosts_total,
                        COUNT(DISTINCT asset_id) FILTER (WHERE source_type = 'docker')
                            AS docker_affected_hosts,
                        COUNT(DISTINCT asset_id) FILTER (WHERE source_type IN ('os', 'software'))
                            AS software_os_affected_hosts,
                        COUNT(*) AS findings_total,
                        COUNT(*) FILTER (WHERE source_type = 'docker') AS docker_findings,
                        COUNT(*) FILTER (WHERE source_type IN ('os', 'software'))
                            AS software_os_findings,
                        ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                        ARRAY_AGG(DISTINCT container_name ORDER BY container_name)
                            FILTER (WHERE NULLIF(container_name, '') IS NOT NULL)
                            AS docker_containers,
                        ARRAY_AGG(DISTINCT image_name ORDER BY image_name)
                            FILTER (WHERE NULLIF(image_name, '') IS NOT NULL)
                            AS docker_images
                    FROM trend_findings
                    GROUP BY passport_internal_id
                ), filtered_trends AS (
                    SELECT
                        trend_passports.*,
                        {affected_hosts_expression} AS affected_hosts,
                        COALESCE(host_counts.affected_hosts_total, 0) AS affected_hosts_total,
                        COALESCE(host_counts.docker_affected_hosts, 0) AS docker_affected_hosts,
                        COALESCE(host_counts.software_os_affected_hosts, 0)
                            AS software_os_affected_hosts,
                        {findings_expression} AS findings,
                        COALESCE(host_counts.findings_total, 0) AS findings_total,
                        COALESCE(host_counts.docker_findings, 0) AS docker_findings,
                        COALESCE(host_counts.software_os_findings, 0) AS software_os_findings,
                        COALESCE(host_counts.sources, ARRAY[]::text[]) AS sources,
                        COALESCE(host_counts.docker_containers, ARRAY[]::text[])
                            AS docker_containers,
                        COALESCE(host_counts.docker_images, ARRAY[]::text[]) AS docker_images
                    FROM trend_passports
                    LEFT JOIN host_counts
                        ON host_counts.passport_internal_id = trend_passports.internal_id
                    {context_filter}
                )
                SELECT
                    filtered_trends.*,
                    COUNT(*) OVER() AS trend_total
                FROM filtered_trends
                ORDER BY
                    filtered_trends.affected_hosts DESC,
                    filtered_trends.is_trend_since DESC NULLS LAST,
                    filtered_trends.issue_time DESC NULLS LAST,
                    filtered_trends.internal_id ASC
                LIMIT %s
                """,
                (limit,),
            ).fetchall()
        decoded = [_decode_trending_passport(dict(row)) for row in rows]
        return {
            "total": int(rows[0].get("trend_total") or 0) if rows else 0,
            "limit": limit,
            "context": context,
            "rows": decoded,
            "synced_at": decoded[0].get("synced_at") if decoded else None,
        }

    def list(
        self,
        *,
        q: str | None = None,
        host_q: str | None = None,
        os: str | None = None,
        asset_type: str | None = None,
        asset_id: str | None = None,
        severity: str | None = None,
        source: VulnerabilitySource | None = None,
        has_fix: str | None = None,
        fix_q: str | None = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str | None = None,
        sort_dir: str | None = None,
        include_total: bool = True,
    ) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset)
        expression, direction = _sort_sql(
            sort_by,
            sort_dir,
            {
                "affected_hosts": "affected_hosts",
                "findings": "findings",
                "severity": "severity_rank",
                "cvss_score": "cvss_score",
                "max_cvss": "cvss_score",
                "name": "LOWER(COALESCE(name, cve, selector))",
                "cve": "LOWER(COALESCE(cve, ''))",
                "how_to_fix": "CASE WHEN COALESCE(how_to_fix, '') = '' "
                "THEN 1 ELSE 0 END, LEFT(how_to_fix, 80)",
                "has_fix": "CASE WHEN COALESCE(how_to_fix, '') = '' "
                "THEN 1 ELSE 0 END",
                "last_seen": "last_seen",
            },
            default="affected_hosts",
            default_direction="desc",
        )
        sort_by_fix_columns = sort_by in {"how_to_fix", "has_fix"}
        schema.init_db()
        use_rollup = (
            ROLLUP_ENABLED
            and not any((q, host_q, os, asset_type, asset_id, severity, source, has_fix, fix_q))
            and sort_by in _ROLLUP_SORTS
        )
        cte, params = _filtered_findings_cte(
            q=q,
            host_q=host_q,
            os=os,
            asset_type=asset_type,
            asset_id=asset_id,
            severity=severity,
            source=source,
            has_fix=has_fix,
            fix_q=fix_q,
        )
        if sort_by_fix_columns:
            cte = f"{cte}{_fix_rollup_cte(restrict_to_filtered=True)}"
        aggregate = """
            , aggregated AS (
                SELECT
                    selector,
                    MAX(NULLIF(vulnerability_id, '')) AS vulnerability_id,
                    MAX(NULLIF(cve, '')) AS cve,
                    MAX(NULLIF(name, '')) AS name,
                    CASE MIN(severity_rank)
                        WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                        WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                    MIN(severity_rank) AS severity_rank,
                    MAX(cvss_score) AS cvss_score,
                    COUNT(DISTINCT asset_id) AS affected_hosts,
                    COUNT(*) AS findings,
                    COUNT(DISTINCT group_id) AS affected_objects,
                    ARRAY_AGG(DISTINCT object_name ORDER BY object_name)
                        FILTER (WHERE NULLIF(object_name, '') IS NOT NULL)
                        AS components,
                    ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                    ARRAY_AGG(DISTINCT container_name ORDER BY container_name)
                        FILTER (WHERE NULLIF(container_name, '') IS NOT NULL)
                        AS docker_containers,
                    ARRAY_AGG(DISTINCT image_name ORDER BY image_name)
                        FILTER (WHERE NULLIF(image_name, '') IS NOT NULL)
                        AS docker_images,
                    MAX(last_seen) AS last_seen
                FROM filtered_findings
                GROUP BY selector
            ), fix_joined AS (
                SELECT
                    aggregated.*
                {fix_select}
                FROM aggregated
                {fix_join}
            ), paged AS (
                SELECT fix_joined.*
                FROM fix_joined
                ORDER BY {expression} {direction} NULLS LAST, fix_joined.selector ASC
                LIMIT %s OFFSET %s
            )
        """ + _PASSPORT_PAGE_CTES
        with connection.connect() as conn:
            total = 0
            if use_rollup:
                total, rows = self._rollup_page(
                    conn,
                    expression=expression,
                    direction=direction,
                    limit=limit,
                    offset=offset,
                    include_total=include_total,
                )
            else:
                if include_total:
                    count_cte, count_params = _filtered_findings_cte(
                        q=q,
                        host_q=host_q,
                        os=os,
                        asset_type=asset_type,
                        asset_id=asset_id,
                        severity=severity,
                        source=source,
                        has_fix=has_fix,
                        fix_q=fix_q,
                        include_details=False,
                    )
                    count_row = conn.execute(
                        count_cte
                        + "SELECT COUNT(DISTINCT selector) AS count FROM filtered_findings",
                        count_params,
                    ).fetchone()
                    total = int((count_row or {}).get("count") or 0)
                if sort_by_fix_columns:
                    aggregate_sql = aggregate.replace(
                        "{fix_select}", ", fix_rollup.how_to_fix"
                    ).replace(
                        "{fix_join}",
                        "LEFT JOIN fix_rollup\n"
                        "                    ON fix_rollup.selector = aggregated.selector",
                    )
                else:
                    aggregate_sql = aggregate.replace(
                        "{fix_select}", ""
                    ).replace("{fix_join}", "")
                rows = conn.execute(
                    cte
                    + aggregate_sql.replace("{expression}", expression).replace("{direction}", direction)
                    + f"""
                    SELECT page.*
                    FROM (
                        SELECT
                            aggregated.*,
                            COALESCE(passport_rollup.passports, '[]'::jsonb) AS passports
                        FROM paged AS aggregated
                        LEFT JOIN passport_rollup
                            ON passport_rollup.selector = aggregated.selector
                    ) AS page
                    ORDER BY {expression} {direction} NULLS LAST, page.selector ASC
                    """,
                    [*params, limit, offset],
                ).fetchall()
            decoded_rows = [_decode_vulnerability(dict(row)) for row in rows]
            fix_map: dict[Any, Any] = {}
            if not sort_by_fix_columns:
                page_selectors = [row["selector"] for row in decoded_rows if row.get("selector")]
                if page_selectors:
                    fix_sql, fix_params = _fix_text_query(page_selectors)
                    fix_rows = conn.execute(fix_sql, fix_params).fetchall()
                    fix_map = {row["selector"]: row.get("how_to_fix") for row in fix_rows}
                decoded_rows = _attach_fix_text(decoded_rows, fix_map)
            return {
                "total": total,
                "rows": decoded_rows,
                "limit": limit,
                "offset": offset,
            }

    @staticmethod
    def _top_fix_map(conn: Any, top_vulnerability_rows: Any) -> dict[Any, Any]:
        """Fix text for the few selectors shown in the top list (bounded follow-up lookup)."""
        top_selectors = [row["selector"] for row in top_vulnerability_rows if row.get("selector")]
        if not top_selectors:
            return {}
        fix_sql, fix_params = _fix_text_query(top_selectors)
        fix_rows = conn.execute(fix_sql, fix_params).fetchall()
        return {row["selector"]: row.get("how_to_fix") for row in fix_rows}

    def _rollup_summary_rows(
        self, conn: Any
    ) -> tuple[dict[str, Any], builtins.list[dict[str, Any]], builtins.list[dict[str, Any]], builtins.list[dict[str, Any]]]:
        """Unfiltered summary pieces, read from the exact selector and host rollups."""
        totals_row = dict(
            conn.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM vulnerability_host_rollup) AS affected_hosts,
                    (SELECT COALESCE(SUM(findings), 0) FROM vulnerability_host_rollup) AS findings,
                    (SELECT COUNT(*) FROM vulnerability_rollup) AS unique_vulnerabilities,
                    (SELECT COUNT(*) FROM (SELECT cve_name FROM vulnerability_rollup, UNNEST(cves) AS cve_name GROUP BY cve_name) AS distinct_cves) AS unique_cves,
                    (SELECT COUNT(*) FROM vulnerability_host_rollup WHERE severity_rank <= 2) AS high_risk_hosts,
                    (SELECT COUNT(*) FROM vulnerability_rollup WHERE severity_rank = 5)
                        AS unrated_vulnerabilities
                """
            ).fetchone()
            or {}
        )
        by_host = dict(
            conn.execute(
                """
                SELECT
                    COALESCE(SUM(findings_critical), 0) AS findings_1,
                    COUNT(*) FILTER (WHERE findings_critical > 0) AS hosts_1,
                    COALESCE(SUM(findings_high), 0) AS findings_2,
                    COUNT(*) FILTER (WHERE findings_high > 0) AS hosts_2,
                    COALESCE(SUM(findings_medium), 0) AS findings_3,
                    COUNT(*) FILTER (WHERE findings_medium > 0) AS hosts_3,
                    COALESCE(SUM(findings_low), 0) AS findings_4,
                    COUNT(*) FILTER (WHERE findings_low > 0) AS hosts_4,
                    COALESCE(SUM(findings_unknown), 0) AS findings_5,
                    COUNT(*) FILTER (WHERE findings_unknown > 0) AS hosts_5
                FROM vulnerability_host_rollup
                """
            ).fetchone()
            or {}
        )
        by_selector = dict(
            conn.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE 1 = ANY(severity_ranks)) AS vulns_1,
                    COUNT(*) FILTER (WHERE 2 = ANY(severity_ranks)) AS vulns_2,
                    COUNT(*) FILTER (WHERE 3 = ANY(severity_ranks)) AS vulns_3,
                    COUNT(*) FILTER (WHERE 4 = ANY(severity_ranks)) AS vulns_4,
                    COUNT(*) FILTER (WHERE 5 = ANY(severity_ranks)) AS vulns_5
                FROM vulnerability_rollup
                """
            ).fetchone()
            or {}
        )
        severity_rows = [
            {
                "severity": label,
                "severity_rank": rank,
                "findings": int(by_host.get(f"findings_{rank}") or 0),
                "affected_hosts": int(by_host.get(f"hosts_{rank}") or 0),
                "unique_vulnerabilities": int(by_selector.get(f"vulns_{rank}") or 0),
            }
            for rank, label in enumerate(VULNERABILITY_SEVERITIES, start=1)
            if int(by_host.get(f"findings_{rank}") or 0) > 0
        ]
        top_vulnerability_rows = conn.execute(
            f"""
            SELECT
                top.*,
                '[]'::jsonb AS passports,
                (
                    SELECT MAX(card.last_seen)
                    FROM asset_card_vulnerabilities AS finding
                    JOIN asset_cards AS card ON card.asset_id = finding.asset_id
                    WHERE finding.selector = top.selector AND {_VALID_FINDING_SQL}
                ) AS last_seen
            FROM (
                SELECT
                    rollup.selector,
                    rollup.vulnerability_id,
                    rollup.cve,
                    rollup.name,
                    CASE rollup.severity_rank
                        WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                        WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                    rollup.severity_rank,
                    rollup.cvss_score,
                    rollup.affected_hosts,
                    rollup.findings,
                    rollup.affected_objects,
                    rollup.components,
                    rollup.sources,
                    rollup.docker_containers,
                    rollup.docker_images
                FROM vulnerability_rollup AS rollup
                ORDER BY rollup.affected_hosts DESC, rollup.findings DESC, rollup.selector ASC
                LIMIT 8
            ) AS top
            ORDER BY top.affected_hosts DESC, top.findings DESC, top.selector ASC
            """
        ).fetchall()
        top_host_rows = conn.execute(
            """
            SELECT
                top.asset_id,
                card.display_name,
                card.hostname,
                card.fqdn,
                card.ip_address,
                card.os_name,
                card.os_version,
                card.asset_type,
                CASE top.severity_rank
                    WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                    WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                top.cvss_score,
                top.findings AS finding_count,
                top.unique_vulnerabilities,
                top.high_risk_vulnerabilities,
                top.sources,
                card.last_seen
            FROM (
                SELECT * FROM vulnerability_host_rollup
                ORDER BY findings DESC, high_risk_vulnerabilities DESC, unique_vulnerabilities DESC, asset_id
                LIMIT 8
            ) AS top
            JOIN asset_cards AS card ON card.asset_id = top.asset_id
            ORDER BY top.findings DESC, top.high_risk_vulnerabilities DESC,
                top.unique_vulnerabilities DESC, top.asset_id
            """
        ).fetchall()
        return totals_row, severity_rows, list(top_vulnerability_rows), list(top_host_rows)

    def _rollup_page(
        self,
        conn: Any,
        *,
        expression: str,
        direction: str,
        limit: int,
        offset: int,
        include_total: bool,
    ) -> tuple[int, Sequence[dict[str, Any]]]:
        """One page of the unfiltered list, read from the exact rollup table."""
        total = 0
        if include_total:
            count_row = conn.execute("SELECT COUNT(*) AS count FROM vulnerability_rollup").fetchone()
            total = int((count_row or {}).get("count") or 0)
        rows = conn.execute(
            f"""
            WITH paged AS (
                SELECT
                    page_rows.*,
                    -- Host-level and changes on its own, so it is read live, and only for
                    -- the page: computing it before LIMIT/OFFSET would cover every skipped row.
                    (
                        SELECT MAX(card.last_seen)
                        FROM asset_card_vulnerabilities AS finding
                        JOIN asset_cards AS card ON card.asset_id = finding.asset_id
                        WHERE finding.selector = page_rows.selector AND {_VALID_FINDING_SQL}
                    ) AS last_seen
                FROM (
                    SELECT
                        rollup.selector,
                        rollup.vulnerability_id,
                        rollup.cve,
                        rollup.name,
                        CASE rollup.severity_rank
                            WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                            WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                        rollup.severity_rank,
                        rollup.cvss_score,
                        rollup.affected_hosts,
                        rollup.findings,
                        rollup.affected_objects,
                        rollup.components,
                        rollup.sources,
                        rollup.docker_containers,
                        rollup.docker_images
                    FROM vulnerability_rollup AS rollup
                    ORDER BY {expression} {direction} NULLS LAST, rollup.selector ASC
                    LIMIT %s OFFSET %s
                ) AS page_rows
            ), filtered_findings AS (
                SELECT finding.selector AS selector, finding.id AS finding_id
                FROM asset_card_vulnerabilities AS finding
                WHERE finding.selector IN (SELECT selector FROM paged) AND {_VALID_FINDING_SQL}
            )
            {_PASSPORT_PAGE_CTES}
            SELECT page.*
            FROM (
                SELECT
                    aggregated.*,
                    COALESCE(passport_rollup.passports, '[]'::jsonb) AS passports
                FROM paged AS aggregated
                LEFT JOIN passport_rollup
                    ON passport_rollup.selector = aggregated.selector
            ) AS page
            ORDER BY {expression} {direction} NULLS LAST, page.selector ASC
            """,
            [limit, offset],
        ).fetchall()
        return total, rows

    def hosts(
        self,
        *,
        selector: str,
        asset_id: str | None = None,
        host_q: str | None = None,
        os: str | None = None,
        asset_type: str | None = None,
        severity: str | None = None,
        source: VulnerabilitySource | None = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str | None = None,
        sort_dir: str | None = None,
    ) -> dict[str, Any]:
        limit, offset = _page_bounds(limit, offset)
        expression, direction = _sort_sql(
            sort_by,
            sort_dir,
            {
                "severity": "severity_rank",
                "findings": "finding_count",
                "finding_count": "finding_count",
                "display_name": "LOWER(COALESCE(display_name, fqdn, hostname, ip_address, asset_id))",
                "ip_address": "ip_address",
                "os_name": "LOWER(COALESCE(os_name, ''))",
                "cvss_score": "cvss_score",
                "max_cvss": "cvss_score",
                "last_seen": "last_seen",
            },
            default="severity",
            default_direction="asc",
        )
        schema.init_db()
        cte, params = _filtered_findings_cte(
            host_q=host_q,
            os=os,
            asset_type=asset_type,
            severity=severity,
            source=source,
            selector=selector,
            asset_id=asset_id,
        )
        aggregate = """
            , aggregated_hosts AS (
                SELECT
                    asset_id,
                    MAX(display_name) AS display_name,
                    MAX(hostname) AS hostname,
                    MAX(fqdn) AS fqdn,
                    MAX(ip_address) AS ip_address,
                    MAX(os_name) AS os_name,
                    MAX(os_version) AS os_version,
                    MAX(asset_type) AS asset_type,
                    CASE MIN(severity_rank)
                        WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                        WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                    MIN(severity_rank) AS severity_rank,
                    MAX(cvss_score) AS cvss_score,
                    COUNT(*) AS finding_count,
                    COUNT(DISTINCT selector) AS unique_vulnerabilities,
                    COUNT(DISTINCT selector) FILTER (WHERE severity_rank <= 2)
                        AS high_risk_vulnerabilities,
                    ARRAY_AGG(DISTINCT object_name ORDER BY object_name)
                        FILTER (WHERE NULLIF(object_name, '') IS NOT NULL) AS objects,
                    ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                    ARRAY_AGG(DISTINCT container_name ORDER BY container_name)
                        FILTER (WHERE NULLIF(container_name, '') IS NOT NULL)
                        AS docker_containers,
                    ARRAY_AGG(DISTINCT image_name ORDER BY image_name)
                        FILTER (WHERE NULLIF(image_name, '') IS NOT NULL)
                        AS docker_images,
                    MAX(last_seen) AS last_seen
                FROM filtered_findings
                GROUP BY asset_id
            ), paged_hosts AS (
                SELECT aggregated_hosts.*
                FROM aggregated_hosts
                ORDER BY {expression} {direction} NULLS LAST, asset_id ASC
                LIMIT %s OFFSET %s
            )
        """
        with connection.connect() as conn:
            selection_row = conn.execute(
                cte
                + """
                SELECT
                    selection.selector,
                    selection.vulnerability_id,
                    selection.cve,
                    selection.name,
                    selection.severity,
                    selection.cvss_score,
                    selection.affected_hosts,
                    selection.findings,
                    selection.affected_objects,
                    selection.sources,
                    selection.docker_containers,
                    selection.docker_images,
                    selection.last_seen
                FROM (
                    SELECT
                        selector,
                        MAX(NULLIF(vulnerability_id, '')) AS vulnerability_id,
                        MAX(NULLIF(cve, '')) AS cve,
                        MAX(NULLIF(name, '')) AS name,
                        CASE MIN(severity_rank)
                            WHEN 1 THEN 'critical' WHEN 2 THEN 'high' WHEN 3 THEN 'medium'
                            WHEN 4 THEN 'low' ELSE 'unknown' END AS severity,
                        MAX(cvss_score) AS cvss_score,
                        COUNT(DISTINCT asset_id) AS affected_hosts,
                        COUNT(*) AS findings,
                        COUNT(DISTINCT group_id) AS affected_objects,
                        ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                        ARRAY_AGG(DISTINCT container_name ORDER BY container_name)
                            FILTER (WHERE NULLIF(container_name, '') IS NOT NULL)
                            AS docker_containers,
                        ARRAY_AGG(DISTINCT image_name ORDER BY image_name)
                            FILTER (WHERE NULLIF(image_name, '') IS NOT NULL)
                            AS docker_images,
                        MAX(last_seen) AS last_seen
                    FROM filtered_findings
                    GROUP BY selector
                ) AS selection
                """,
                params,
            ).fetchone()
            fix_map: dict[Any, Any] = {}
            if selection_row is not None and selection_row.get("selector"):
                fix_sql, fix_params = _fix_text_query([selection_row["selector"]])
                if fix_sql:
                    fix_rows = conn.execute(fix_sql, fix_params).fetchall()
                    fix_map = {row["selector"]: row.get("how_to_fix") for row in fix_rows}
            count_row = conn.execute(
                cte + "SELECT COUNT(DISTINCT asset_id) AS count FROM filtered_findings", params
            ).fetchone()
            total = int((count_row or {}).get("count") or 0)
            rows = conn.execute(
                cte
                + aggregate.replace("{expression}", expression).replace("{direction}", direction)
                + f"""
                SELECT host_page.*
                FROM (
                SELECT
                    aggregated_hosts.*,
                    remediation.case_id AS remediation_case_id,
                    remediation.version AS remediation_version,
                    remediation.status AS remediation_status,
                    remediation.assignee AS remediation_assignee,
                    remediation.due_at AS remediation_due_at,
                    remediation.resolved_at AS remediation_resolved_at,
                    (
                        remediation.status IN ('open', 'in_progress')
                        AND remediation.due_at < NOW()
                    ) AS remediation_overdue
                FROM paged_hosts AS aggregated_hosts
                LEFT JOIN remediation_cases AS remediation
                    ON remediation.asset_id = aggregated_hosts.asset_id
                   AND remediation.vulnerability_key = %s
                ) AS host_page
                ORDER BY {expression} {direction} NULLS LAST, asset_id ASC
                """,
                [*params, limit, offset, selector],
            ).fetchall()
        selection = None
        if selection_row:
            selection = _decode_vulnerability(dict(selection_row))
            how_to_fix = (fix_map.get(selection_row.get("selector")) or "").strip() or None
            selection["how_to_fix"] = how_to_fix
            selection["has_fix"] = bool(how_to_fix)
        return {
            "selection": selection,
            "total": total,
            "rows": [_decode_host(dict(row)) for row in rows],
            "limit": limit,
            "offset": offset,
        }
