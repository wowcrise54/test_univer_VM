"""Repository for vulnerability report row iteration (local and Docker findings)."""

from __future__ import annotations

from ...persistence import connection, schema


def iter_vulnerability_report_rows(
    source_type: str,
    asset_ids: list[str] | None = None,
    *,
    batch_size: int = 1000,
):
    """Yield normalized host vulnerability findings using a single SQL query."""
    if source_type not in {"os", "software"}:
        raise ValueError("source_type must be 'os' or 'software'")
    selected_ids = list(dict.fromkeys(asset_ids or [])) or None
    schema.init_db()
    with connection.connect() as conn:
        cursor = conn.execute(
            """
            SELECT
                card.asset_id,
                card.ip_address,
                card.fqdn,
                card.hostname,
                card.os_name,
                card.os_version,
                card.last_seen,
                vulnerability_group.name AS object_name,
                finding.cve_name,
                finding.name AS vulnerability_name,
                finding.severity,
                finding.cvss_score
            FROM asset_card_vulnerabilities AS finding
            JOIN asset_card_vulnerability_groups AS vulnerability_group
              ON vulnerability_group.id = finding.group_id
            JOIN asset_cards AS card
              ON card.asset_id = finding.asset_id
            WHERE vulnerability_group.source_type = %s
              AND (%s::text[] IS NULL OR card.asset_id = ANY(%s))
            ORDER BY
                COALESCE(card.ip_address, ''),
                COALESCE(card.fqdn, ''),
                card.asset_id,
                COALESCE(vulnerability_group.name, ''),
                COALESCE(finding.cve_name, ''),
                COALESCE(finding.name, ''),
                finding.id
            """,
            (source_type, selected_ids, selected_ids),
        )
        while rows := cursor.fetchmany(batch_size):
            yield from (dict(row) for row in rows)


def iter_docker_vulnerability_report_rows(
    asset_ids: list[str] | None = None,
    *,
    batch_size: int = 1000,
):
    """Yield Docker container vulnerability findings from locally stored asset cards."""
    selected_ids = list(dict.fromkeys(asset_ids or [])) or None
    schema.init_db()
    with connection.connect() as conn:
        cursor = conn.execute(
            """
            WITH docker_findings AS (
                SELECT
                    card.asset_id,
                    card.ip_address,
                    card.fqdn,
                    card.hostname,
                    card.last_seen,
                    vulnerability_group.collection_id,
                    vulnerability_group.name AS group_name,
                    vulnerability_group.group_json::jsonb AS group_json,
                    finding.cve_name,
                    finding.name AS vulnerability_name,
                    finding.vulnerability_id,
                    finding.severity,
                    finding.cvss_score,
                    finding.vulnerability_json::jsonb AS finding_json
                FROM asset_card_vulnerabilities AS finding
                JOIN asset_card_vulnerability_groups AS vulnerability_group
                  ON vulnerability_group.id = finding.group_id
                JOIN asset_cards AS card
                  ON card.asset_id = finding.asset_id
                WHERE vulnerability_group.source_type = 'docker'
                  AND (%s::text[] IS NULL OR card.asset_id = ANY(%s))
            ),
            resolved_findings AS (
                SELECT
                asset_id,
                ip_address,
                fqdn,
                hostname,
                COALESCE(
                    NULLIF(finding_json ->> 'docker_engine', ''),
                    NULLIF(finding_json #>> '{docker_container,docker_engine}', ''),
                    NULLIF(group_json ->> 'docker_engine', '')
                ) AS docker_engine,
                COALESCE(
                    NULLIF(finding_json ->> 'container_name', ''),
                    NULLIF(finding_json #>> '{docker_container,container_name}', ''),
                    NULLIF(group_json ->> 'container_name', ''),
                    NULLIF(group_name, '')
                ) AS container_name,
                COALESCE(
                    NULLIF(finding_json ->> 'container_id', ''),
                    NULLIF(finding_json #>> '{docker_container,container_id}', ''),
                    NULLIF(group_json ->> 'container_id', ''),
                    NULLIF(collection_id, '')
                ) AS container_id,
                COALESCE(
                    NULLIF(finding_json #>> '{docker_image,image_name}', ''),
                    NULLIF(group_json ->> 'image_name', ''),
                    NULLIF(finding_json ->> 'image_id', '')
                ) AS image_name,
                COALESCE(
                    NULLIF(finding_json ->> 'image_id', ''),
                    NULLIF(finding_json #>> '{docker_container,image_id}', ''),
                    NULLIF(finding_json #>> '{docker_image,image_key}', ''),
                    NULLIF(group_json ->> 'image_id', ''),
                    NULLIF(group_json ->> 'image_key', '')
                ) AS image_id,
                COALESCE(
                    NULLIF(finding_json #>> '{docker_image,registry}', ''),
                    NULLIF(group_json ->> 'registry', '')
                ) AS registry,
                COALESCE(
                    NULLIF(finding_json #>> '{docker_image,repository}', ''),
                    NULLIF(group_json ->> 'repository', '')
                ) AS repository,
                COALESCE(
                    NULLIF(finding_json #>> '{docker_image,tag}', ''),
                    NULLIF(group_json ->> 'tag', '')
                ) AS tag,
                NULLIF(finding_json ->> 'package_name', '') AS package_name,
                NULLIF(finding_json ->> 'package_version', '') AS package_version,
                cve_name,
                vulnerability_name,
                vulnerability_id,
                severity,
                cvss_score,
                NULLIF(finding_json ->> 'status', '') AS vulnerability_status,
                NULLIF(finding_json ->> 'fixed_version', '') AS fixed_version,
                NULLIF(finding_json ->> 'how_to_fix', '') AS how_to_fix,
                    last_seen
                FROM docker_findings
            )
            SELECT *
            FROM resolved_findings
            ORDER BY
                COALESCE(ip_address, ''),
                COALESCE(fqdn, ''),
                asset_id,
                COALESCE(container_name, ''),
                COALESCE(package_name, ''),
                COALESCE(package_version, ''),
                COALESCE(cve_name, ''),
                COALESCE(vulnerability_name, '')
            """,
            (selected_ids, selected_ids),
        )
        while rows := cursor.fetchmany(batch_size):
            yield from (dict(row) for row in rows)
