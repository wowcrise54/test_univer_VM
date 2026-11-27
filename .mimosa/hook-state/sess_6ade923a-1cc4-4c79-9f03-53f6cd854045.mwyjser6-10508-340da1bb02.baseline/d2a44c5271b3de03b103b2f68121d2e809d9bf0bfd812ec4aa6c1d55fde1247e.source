"""Read the host package collection and matching local passport rules."""

from typing import Any

from ...persistence import connection, schema


def inventory_package_names() -> list[dict[str, Any]]:
    with connection.connect() as conn:
        return conn.execute(
            """
            SELECT DISTINCT card.os_name, card.os_version, item.data_json::jsonb ->> 'name' AS package
            FROM asset_cards AS card
            JOIN asset_card_collections AS collection ON collection.asset_id = card.asset_id
              AND collection.name = 'packages'
              AND collection.parent_object_id = card.root_json::jsonb ->> 'objectId'
            JOIN asset_card_collection_items AS item
              ON item.asset_id = collection.asset_id AND item.collection_path = collection.path
            WHERE item.object_type IN (
                'OperatingSystem.UNIX.Linux.Debian.UbuntuPackage',
                'OperatingSystem.UNIX.Linux.Debian.DebianPackage'
            )
            """
        ).fetchall()


def read_inventory(asset_id: str) -> dict[str, Any] | None:
    schema.init_db()
    with connection.connect() as conn:
        return conn.execute(
            """
            SELECT card.os_name, card.os_version, card.last_seen,
                   inventory.complete, inventory.packages
            FROM asset_cards AS card
            LEFT JOIN LATERAL (
                SELECT NOT collection.truncated
                       AND COUNT(*) = collection.reported_count
                       AND COUNT(*) = collection.fetched_count AS complete,
                       jsonb_agg(jsonb_build_array(item.data_json::jsonb->>'name',
                                                 item.data_json::jsonb->>'version')) AS packages
                FROM asset_card_collections AS collection
                JOIN asset_card_collection_items AS item
                  ON item.asset_id = collection.asset_id AND item.collection_path = collection.path
                WHERE collection.asset_id = card.asset_id
                  AND collection.name = 'packages'
                  AND collection.parent_object_id = card.root_json::jsonb->>'objectId'
                  AND item.object_type = CASE lower(card.os_name)
                      WHEN 'ubuntu' THEN 'OperatingSystem.UNIX.Linux.Debian.UbuntuPackage'
                      WHEN 'debian' THEN 'OperatingSystem.UNIX.Linux.Debian.DebianPackage'
                  END
                GROUP BY collection.path, collection.truncated,
                         collection.reported_count, collection.fetched_count
                ORDER BY collection.path
                LIMIT 1
            ) AS inventory ON TRUE
            WHERE card.asset_id = %s
            """,
            (asset_id,),
        ).fetchone()


def read_rules(vendor: str, release: str, packages: list[str]) -> list[dict[str, Any]]:
    with connection.connect() as conn:
        return conn.execute(
            """
            SELECT passport_id, package_name, default_status, versions
            FROM wazuh_cti_package_rules
            WHERE vendor = %s AND release = %s AND package_name = ANY(%s)
            ORDER BY package_name, passport_id
            """,
            (vendor, release, packages),
        ).fetchall()
