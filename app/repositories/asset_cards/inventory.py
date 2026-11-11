"""Repository for asset card software inventory rows and software entity classification."""

from __future__ import annotations

import re
from typing import Any

import psycopg

from ...persistence.codecs import clean_value, first_non_empty
from ...persistence.sql import copy_rows

SOFTWARE_ENTITY_MARKERS = (
    ".software[",
    ".softs[",
    "software[",
    "softs[",
    ".software.",
    ".softs.",
)


SOFTWARE_FIELD_ALIASES = {
    "name": "soft_name",
    "softname": "soft_name",
    "softwarename": "soft_name",
    "version": "soft_version",
    "softversion": "soft_version",
    "softwareversion": "soft_version",
    "vendor": "vendor",
    "publisher": "vendor",
    "manufacturer": "vendor",
    "architecture": "architecture",
    "arch": "architecture",
    "installpath": "install_path",
    "installationpath": "install_path",
    "path": "install_path",
}


SOFTWARE_ENTITY_PATTERN = r"(^|[.])(software|softs)\[[^]]+\]$"


def _is_software_entity(entity_path: str, field_path: str) -> bool:
    # Only direct fields of an installed-software item belong in inventory.
    # Descendant collections (containers, users, services, etc.) are separate entities.
    return bool(
        re.search(SOFTWARE_ENTITY_PATTERN, entity_path, re.IGNORECASE)
        and re.search(r"(^|[.])(software|softs)(\[[^]]+\])?[.][^.]+$", field_path, re.IGNORECASE)
    )


def _software_field_leaf(field_path: str, field_name: str) -> str:
    leaf = asset_path_leaf(field_path).lower()
    return re.sub(r"[^a-z0-9]", "", leaf or field_name.lower())


def asset_path_leaf(path: str) -> str:
    return re.split(r"[.\[]", str(path))[-1].rstrip("]") or str(path)


def build_asset_card_software_inventory_rows(
    card: dict[str, Any],
) -> list[
    tuple[
        str,
        str,
        str,
        str,
        str,
        str,
        str | None,
        str | None,
        str | None,
        bool,
    ]
]:
    """Flatten software entities once so preset queries do not rebuild them."""
    from .search_index import build_asset_card_search_rows


    asset_id = clean_value(card.get("asset_id"))
    if not asset_id:
        return []

    root = card.get("root")
    if not isinstance(root, dict):
        root = {}
    root_data = root.get("data")
    if not isinstance(root_data, dict):
        root_data = {}
    asset_type = first_non_empty(card.get("asset_type"), root.get("type"))
    os_name = first_non_empty(card.get("os_name"), root_data.get("osName"))
    is_windows = (
        "windows" in str(asset_type or "").lower()
        or "windows" in str(os_name or "").lower()
    )

    entities: dict[str, dict[str, str]] = {}
    for (
        entity_path,
        field_path,
        field_name,
        value_type,
        value_text,
        _value_text_normalized,
        _value_number,
        _value_boolean,
    ) in build_asset_card_search_rows(card):
        if not _is_software_entity(entity_path, field_path):
            continue
        alias = SOFTWARE_FIELD_ALIASES.get(_software_field_leaf(field_path, field_name))
        if not alias or value_type != "text" or value_text is None:
            continue
        entity = entities.setdefault(entity_path, {})
        entity.setdefault(alias, value_text)

    rows = []
    for entity_path, entity in entities.items():
        soft_name = clean_value(entity.get("soft_name"))
        if not soft_name:
            continue
        soft_version = clean_value(entity.get("soft_version")) or ""
        vendor = clean_value(entity.get("vendor"))
        architecture = clean_value(entity.get("architecture"))
        install_path = clean_value(entity.get("install_path"))
        rows.append(
            (
                asset_id,
                entity_path,
                soft_name,
                soft_name.lower(),
                soft_version,
                soft_version.lower(),
                vendor,
                architecture,
                install_path,
                is_windows,
            )
        )
    return sorted(rows, key=lambda row: (row[2].lower(), row[4].lower(), row[1]))


def replace_asset_card_software_inventory(
    conn: psycopg.Connection[dict[str, Any]],
    asset_id: str,
    card: dict[str, Any],
    updated_at: str,
) -> int:
    conn.execute(
        "DELETE FROM asset_card_software_inventory WHERE asset_id = %s",
        (asset_id,),
    )
    rows = build_asset_card_software_inventory_rows(card)
    with conn.cursor() as cur:
        copy_rows(
            cur,
            "asset_card_software_inventory",
            (
                "asset_id",
                "entity_path",
                "soft_name",
                "soft_name_normalized",
                "soft_version",
                "soft_version_normalized",
                "vendor",
                "architecture",
                "install_path",
                "is_windows",
                "updated_at",
            ),
            [(asset_id, *row[1:], updated_at) for row in rows],
        )
    conn.execute(
        """
        UPDATE asset_cards
        SET software_inventory_updated_at = %s
        WHERE asset_id = %s
        """,
        (updated_at, asset_id),
    )
    return len(rows)
