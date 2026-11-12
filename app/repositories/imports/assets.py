"""Repositories for assets and software rows written by CSV imports, including identity resolution and replacement cleanup."""

from __future__ import annotations

from typing import Any

import psycopg

from ...persistence import codecs
from ...persistence.codecs import first_value
from ...persistence.sql import chunked


def upsert_asset(conn: psycopg.Connection[dict[str, Any]], row: dict[str, str]) -> int | None:
    ip_address = first_value(row, "Host.IpAddress", "IpAddress", "IP")
    fqdn = first_value(row, "Host.Fqdn", "Fqdn", "HostName", "Hostname")
    mp_asset_id = first_value(row, "AssetId", "Host.@Id", "@Host", "HostId", "Id")
    if not ip_address and not fqdn and not mp_asset_id:
        return None
    asset_key = mp_asset_id or f"{ip_address or ''}|{(fqdn or '').casefold()}"
    current = codecs.now_utc()
    row_result = conn.execute(
        """
        INSERT INTO assets (asset_key, mp_asset_id, ip_address, fqdn, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT(asset_key) DO UPDATE SET
            mp_asset_id = COALESCE(EXCLUDED.mp_asset_id, assets.mp_asset_id),
            ip_address = COALESCE(EXCLUDED.ip_address, assets.ip_address),
            fqdn = COALESCE(EXCLUDED.fqdn, assets.fqdn),
            last_seen = EXCLUDED.last_seen
        RETURNING id
        """,
        (asset_key, mp_asset_id, ip_address, fqdn, current, current),
    ).fetchone()
    assert row_result is not None
    return int(row_result["id"])


def upsert_software(conn: psycopg.Connection[dict[str, Any]], row: dict[str, str]) -> int | None:
    name = first_value(row, "SoftName", "Host.Softs.Name", "SoftwareName")
    version = first_value(row, "SoftVersion", "Host.Softs.Version", "SoftwareVersion") or ""
    if not name:
        return None
    row_result = conn.execute(
        """
        INSERT INTO software (name, version)
        VALUES (%s, %s)
        ON CONFLICT(name, version) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
        """,
        (name, version),
    ).fetchone()
    assert row_result is not None
    return int(row_result["id"])


def collect_asset_identity(affected: dict[str, set[str]], row: dict[str, str]) -> None:
    fqdn = first_value(row, "Host.Fqdn", "Fqdn", "HostName", "Hostname")
    mp_asset_id = first_value(row, "AssetId", "Host.@Id", "@Host", "HostId", "Id")
    ip_address = first_value(row, "Host.IpAddress", "IpAddress", "IP")
    if fqdn:
        affected["fqdns"].add(fqdn.casefold())
    if mp_asset_id:
        affected["mp_asset_ids"].add(mp_asset_id)
    if ip_address:
        affected["ips"].add(ip_address)


def empty_asset_identity_set() -> dict[str, set[str]]:
    return {"fqdns": set(), "mp_asset_ids": set(), "ips": set()}


def resolve_assets_for_replacement(
    conn: psycopg.Connection[dict[str, Any]],
    affected: dict[str, set[str]],
    current_asset_ids: set[int],
) -> set[int]:
    """Find all local assets whose previous findings must be replaced by this import."""

    result = set(current_asset_ids)
    result.update(select_asset_ids_by_values(conn, "LOWER(fqdn)", affected["fqdns"]))
    result.update(select_asset_ids_by_values(conn, "mp_asset_id", affected["mp_asset_ids"]))

    # Use IP only for rows without a better identity; this keeps DHCP/reused IP
    # churn from wiping another host when FQDN is present in the export.
    if not affected["fqdns"] and not affected["mp_asset_ids"]:
        result.update(select_asset_ids_by_values(conn, "ip_address", affected["ips"]))
    return result


def select_asset_ids_by_values(
    conn: psycopg.Connection[dict[str, Any]],
    expression: str,
    values: set[str],
) -> set[int]:
    if not values:
        return set()
    result: set[int] = set()
    for chunk in chunked(sorted(values), 400):
        rows = conn.execute(
            f"SELECT id FROM assets WHERE {expression} = ANY(%s)",
            (chunk,),
        ).fetchall()
        result.update(int(row["id"]) for row in rows)
    return result


def delete_findings_for_assets(conn: psycopg.Connection[dict[str, Any]], asset_ids: set[int]) -> None:
    if not asset_ids:
        return
    for chunk in chunked(sorted(asset_ids), 400):
        conn.execute("DELETE FROM vulnerability_findings WHERE asset_id = ANY(%s)", (chunk,))


def cleanup_orphans(conn: psycopg.Connection[dict[str, Any]]) -> None:
    conn.execute(
        """
        DELETE FROM software
        WHERE NOT EXISTS (
            SELECT 1 FROM vulnerability_findings vf WHERE vf.software_id = software.id
        )
        """
    )
    conn.execute(
        """
        DELETE FROM assets
        WHERE NOT EXISTS (
            SELECT 1 FROM vulnerability_findings vf WHERE vf.asset_id = assets.id
        )
        """
    )
