from __future__ import annotations

from typing import Any, Literal

from .. import db

VulnerabilitySource = Literal["os", "software"]


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


VULNERABILITY_SELECTOR_SQL = """
CASE
    WHEN NULLIF(TRIM(finding.vulnerability_id), '') IS NOT NULL
        THEN 'id:' || TRIM(finding.vulnerability_id)
    WHEN NULLIF(TRIM(finding.cve_name), '') IS NOT NULL
        THEN 'cve:' || UPPER(TRIM(finding.cve_name))
    WHEN NULLIF(TRIM(finding.name), '') IS NOT NULL
        THEN 'name:' || LOWER(REGEXP_REPLACE(TRIM(finding.name), '\\s+', ' ', 'g'))
            || '|source:' || vulnerability_group.source_type
            || '|object:' || LOWER(REGEXP_REPLACE(TRIM(COALESCE(vulnerability_group.name, '')), '\\s+', ' ', 'g'))
    ELSE 'instance:' || TRIM(finding.vulnerability_instance_id)
END
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


def _filtered_findings_cte(
    *,
    q: str | None = None,
    host_q: str | None = None,
    severity: str | None = None,
    source: VulnerabilitySource | None = None,
    selector: str | None = None,
) -> tuple[str, list[Any]]:
    filters = [
        "COALESCE(NULLIF(TRIM(finding.vulnerability_id), ''), "
        "NULLIF(TRIM(finding.cve_name), ''), NULLIF(TRIM(finding.name), ''), "
        "NULLIF(TRIM(finding.vulnerability_instance_id), '')) IS NOT NULL"
    ]
    params: list[Any] = []
    if q:
        like = f"%{q.strip()}%"
        filters.append(
            "(finding.vulnerability_id ILIKE %s OR finding.cve_name ILIKE %s "
            "OR finding.name ILIKE %s OR vulnerability_group.name ILIKE %s)"
        )
        params.extend([like, like, like, like])
    if host_q:
        like = f"%{host_q.strip()}%"
        filters.append(
            "(card.asset_id ILIKE %s OR card.display_name ILIKE %s OR card.hostname ILIKE %s "
            "OR card.fqdn ILIKE %s OR card.ip_address ILIKE %s)"
        )
        params.extend([like, like, like, like, like])
    if severity:
        normalized = severity.strip().lower()
        normalized = normalized if normalized in {"critical", "high", "medium", "low"} else "unknown"
        filters.append(f"{_normalized_severity('finding.severity')} = %s")
        params.append(normalized)
    if source:
        filters.append("vulnerability_group.source_type = %s")
        params.append(source)
    if selector:
        filters.append(f"({VULNERABILITY_SELECTOR_SQL}) = %s")
        params.append(selector)

    where = " AND ".join(filters)
    cte = f"""
        WITH filtered_findings AS (
            SELECT
                {VULNERABILITY_SELECTOR_SQL} AS selector,
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
                card.asset_id,
                card.display_name,
                card.hostname,
                card.fqdn,
                card.ip_address,
                card.os_name,
                card.os_version,
                card.asset_type,
                card.last_seen
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
    cvss_score = db.decimal_to_number(row.get("cvss_score"))
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
        "sources": list(row.get("sources") or []),
        "last_seen": row.get("last_seen"),
    }


def _decode_host(row: dict[str, Any]) -> dict[str, Any]:
    cvss_score = db.decimal_to_number(row.get("cvss_score"))
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
        "last_seen": row.get("last_seen"),
    }


class VulnerabilityAnalyticsRepository:
    """Read-only analytics over the latest normalized asset-card snapshot."""

    def summary(
        self,
        *,
        q: str | None = None,
        host_q: str | None = None,
        severity: str | None = None,
        source: VulnerabilitySource | None = None,
    ) -> dict[str, Any]:
        db.init_db()
        cte, params = _filtered_findings_cte(q=q, host_q=host_q, severity=severity, source=source)
        with db.connect() as conn:
            coverage_row = dict(
                conn.execute(
                    """
                    SELECT
                        COUNT(DISTINCT card.asset_id) AS cards_total,
                        COUNT(DISTINCT finding.asset_id) FILTER (
                            WHERE COALESCE(
                                NULLIF(TRIM(finding.vulnerability_id), ''),
                                NULLIF(TRIM(finding.cve_name), ''),
                                NULLIF(TRIM(finding.name), ''),
                                NULLIF(TRIM(finding.vulnerability_instance_id), '')
                            ) IS NOT NULL
                        ) AS cards_with_findings,
                        COUNT(DISTINCT vulnerability_group.id)
                            FILTER (WHERE vulnerability_group.truncated) AS truncated_groups,
                        MIN(card.last_seen) AS oldest_at,
                        MAX(card.last_seen) AS freshest_at
                    FROM asset_cards AS card
                    LEFT JOIN asset_card_vulnerability_groups AS vulnerability_group
                        ON vulnerability_group.asset_id = card.asset_id
                    LEFT JOIN asset_card_vulnerabilities AS finding
                        ON finding.group_id = vulnerability_group.id
                    """
                ).fetchone()
            )
            totals_row = dict(
                conn.execute(
                    cte
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
                    params,
                ).fetchone()
            )
            severity_rows = conn.execute(
                cte
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
                params,
            ).fetchall()
            top_host_rows = conn.execute(
                cte
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
                params,
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
        top = self.list(
            q=q,
            host_q=host_q,
            severity=severity,
            source=source,
            limit=8,
            offset=0,
            sort_by="affected_hosts",
            sort_dir="desc",
            include_total=False,
        )
        return {
            "source": {
                "kind": "asset_cards",
                "label": "Сохранённые карточки активов PostgreSQL",
                "as_of": coverage["freshest_at"],
                "historical": False,
            },
            "filters": {"q": q or "", "host_q": host_q or "", "severity": severity or "", "source": source or ""},
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
            "top_vulnerabilities": top["rows"],
            "top_hosts": [_decode_host(dict(row)) for row in top_host_rows],
        }

    def list(
        self,
        *,
        q: str | None = None,
        host_q: str | None = None,
        severity: str | None = None,
        source: VulnerabilitySource | None = None,
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
                "last_seen": "last_seen",
            },
            default="affected_hosts",
            default_direction="desc",
        )
        db.init_db()
        cte, params = _filtered_findings_cte(q=q, host_q=host_q, severity=severity, source=source)
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
                    ARRAY_AGG(DISTINCT source_type ORDER BY source_type) AS sources,
                    MAX(last_seen) AS last_seen
                FROM filtered_findings
                GROUP BY selector
            )
        """
        with db.connect() as conn:
            total = 0
            if include_total:
                total = int(
                    conn.execute(
                        cte + "SELECT COUNT(DISTINCT selector) AS count FROM filtered_findings",
                        params,
                    ).fetchone()["count"]
                    or 0
                )
            rows = conn.execute(
                cte
                + aggregate
                + f"""
                SELECT * FROM aggregated
                ORDER BY {expression} {direction} NULLS LAST, selector ASC
                LIMIT %s OFFSET %s
                """,
                [*params, limit, offset],
            ).fetchall()
        return {
            "total": total,
            "rows": [_decode_vulnerability(dict(row)) for row in rows],
            "limit": limit,
            "offset": offset,
        }

    def hosts(
        self,
        *,
        selector: str,
        host_q: str | None = None,
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
        db.init_db()
        cte, params = _filtered_findings_cte(
            host_q=host_q,
            severity=severity,
            source=source,
            selector=selector,
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
                    MAX(last_seen) AS last_seen
                FROM filtered_findings
                GROUP BY asset_id
            )
        """
        with db.connect() as conn:
            selection_row = conn.execute(
                cte
                + """
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
                    MAX(last_seen) AS last_seen
                FROM filtered_findings
                GROUP BY selector
                """,
                params,
            ).fetchone()
            total = int(
                conn.execute(
                    cte + "SELECT COUNT(DISTINCT asset_id) AS count FROM filtered_findings", params
                ).fetchone()["count"]
                or 0
            )
            rows = conn.execute(
                cte
                + aggregate
                + f"""
                SELECT * FROM aggregated_hosts
                ORDER BY {expression} {direction} NULLS LAST, asset_id ASC
                LIMIT %s OFFSET %s
                """,
                [*params, limit, offset],
            ).fetchall()
        return {
            "selection": _decode_vulnerability(dict(selection_row)) if selection_row else None,
            "total": total,
            "rows": [_decode_host(dict(row)) for row in rows],
            "limit": limit,
            "offset": offset,
        }
