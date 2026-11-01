from __future__ import annotations

import re
from typing import Any

from ..mpvm_client import extract_uuid
from .common import (
    as_dict,
    clean_text,
    first_present,
    json_dumps_compact,
    normalize_asset_metadata_key,
    number_or_none,
    number_or_zero,
)

ASSET_CARD_STAGE_PROGRESS = {
    "queued": 0,
    "starting": 5,
    "collecting": 5,
    "timeline": 10,
    "root": 15,
    "tree_and_vulnerabilities": 25,
    "tree_ready": 60,
    "vulnerabilities_ready": 60,
    "assembling": 85,
    "saving": 95,
    "completed": 100,
}


# Windows asset-card branches that are intentionally excluded from collection
# discovery.  Keep the comparison normalized because MP VM metadata has used
# both camelCase and snake_case names across versions.
WINDOWS_ASSET_CARD_EXCLUDED_COLLECTIONS = frozenset({
    "aclaccesslist",
    "aclaccesslists",
    "accountlockoutpolicy",
    "accountlockoutpolicies",
    "appliedaccesslists",
    "appliedaccesslist",
    "arp",
    "arptable",
    "arptables",
    "auditpolicy",
    "auditpolicies",
    "bios",
    "certificates",
    "certificate",
    "cpu",
    "cpus",
    "centralprocessor",
    "dnscache",
    "dnsclientsettings",
    "dnsclient",
    "dynamicrouting",
    "eventlog",
    "eventlogsettings",
    "eventlogs",
    "gpcredentials",
    "groups",
    "group",
    "hdds",
    "hdd",
    "harddisks",
    "harddisk",
    "hypervisors",
    "hypervisor",
    "ipv6settings",
    "ipv6",
    "lanmanserver",
    "lanmanworkstation",
    "logicaldisks",
    "logicaldisk",
    "motherboard",
    "nattable",
    "nattables",
    "neighbors",
    "neighbor",
    "neighbordevices",
    "networkadapters",
    "networkadapter",
    "networkconnections",
    "networkconnection",
    "os_candidates",
    "oscandidates",
    "operatingsystemcandidates",
    "osfingerprints",
    "operatingsystemfingerprint",
    "passwordpolicy",
    "passwordpolicies",
    "pcidevice",
    "pcidevices",
    "peripherals",
    "peripheraldevices",
    "powermanagement",
    "printers",
    "printer",
    "roles",
    "traces",
    "trace",
    "traceroutes",
    "usbdevices",
    "usbdevice",
})


def normalize_asset_vulnerabilities_header(header: dict[str, Any]) -> dict[str, Any]:
    return {
        "os_soft_vulnerabilities_count": number_or_zero(header.get("osSoftVulnerabilitiesCount")),
        "network_services_vulnerabilities_count": number_or_zero(header.get("networkServicesVulnerabilitiesCount")),
    }


def vulnerability_collection_id(item: dict[str, Any]) -> str:
    vulnerabilities = as_dict(item.get("vulnerabilities"))
    return clean_text(first_present(vulnerabilities.get("key"), item.get("id"), item.get("key"))).strip()


def normalize_asset_vulnerability_item(item: dict[str, Any]) -> dict[str, Any]:
    description = as_dict(item.get("description"))
    image = next(
        (value for value in (item.get("image"), item.get("imageSet"), item.get("containerImage")) if isinstance(value, dict)),
        {},
    )
    package = as_dict(item.get("package"))
    docker_image = {
        "image_key": clean_text(first_present(item.get("imageKey"), item.get("imageSetId"), item.get("imageId"), image.get("key"), image.get("id"), image.get("objectId"))),
        "image_name": clean_text(first_present(item.get("imageName"), item.get("imageSetName"), image.get("name"), image.get("displayName"))),
        "registry": clean_text(first_present(item.get("registry"), image.get("registry"))),
        "repository": clean_text(first_present(item.get("repository"), image.get("repository"))),
        "tag": clean_text(first_present(item.get("tag"), image.get("tag"))),
        "digest": clean_text(first_present(item.get("digest"), item.get("imageDigest"), image.get("digest"))),
        "image_os_name": clean_text(first_present(item.get("imageOsName"), image.get("osName"))),
        "image_os_version": clean_text(first_present(item.get("imageOsVersion"), image.get("osVersion"))),
    }
    normalized = {
        "level": item.get("level"),
        "name": clean_text(item.get("name")),
        "cve_name": clean_text(first_present(item.get("cveName"), item.get("cve"))),
        "description_key": clean_text(first_present(description.get("key"), item.get("descriptionKey"))),
        "cvss_score": number_or_none(item.get("cvssScore")),
        "object_id": clean_text(item.get("objectId")),
        "vulnerability_id": clean_text(first_present(item.get("vulnerId"), item.get("vulnerabilityId"))),
        "vulnerability_instance_id": clean_text(first_present(item.get("vulnerabilityInstanceId"), item.get("id"))),
        "package_name": clean_text(first_present(item.get("packageName"), package.get("name"))),
        "package_version": clean_text(first_present(item.get("packageVersion"), package.get("version"))),
        "fixed_version": clean_text(first_present(item.get("fixedVersion"), package.get("fixedVersion"))),
        "status": clean_text(item.get("status")),
    }
    if any(docker_image.values()):
        normalized["docker_image"] = docker_image
    return normalized


def metadata_properties_by_name(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    properties = metadata.get("properties")
    if not isinstance(properties, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name"):
            result[str(prop["name"])] = prop
    return result


def metadata_property_for_name(properties: dict[str, dict[str, Any]], name: Any) -> dict[str, Any]:
    if name in properties:
        return properties[name]
    normalized_name = normalize_asset_metadata_key(name)
    for prop_name, prop in properties.items():
        if normalize_asset_metadata_key(prop_name) == normalized_name:
            return prop
    return {}


def metadata_collection_properties(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(prop: Any, *, known_collection: bool = False) -> None:
        if isinstance(prop, str):
            prop = {"name": prop}
        if not isinstance(prop, dict):
            return
        if not known_collection and not metadata_property_is_collection(prop):
            return
        name = metadata_collection_name(prop)
        if not name:
            return
        key = normalize_asset_metadata_key(name)
        if key in seen:
            return
        seen.add(key)
        result.append(prop)

    properties = metadata.get("properties")
    if isinstance(properties, list):
        for prop in properties:
            add(prop)

    for key in ("collections", "collectionProperties", "collection_properties"):
        collection_props = metadata.get(key)
        if isinstance(collection_props, list):
            for prop in collection_props:
                add(prop, known_collection=True)
        elif isinstance(collection_props, dict):
            for name, prop in collection_props.items():
                if isinstance(prop, dict):
                    add({"name": name, **prop}, known_collection=True)
                else:
                    add({"name": name, "title": prop}, known_collection=True)

    return result


def metadata_property_is_collection(prop: dict[str, Any]) -> bool:
    for key in (
        "isCollection",
        "is_collection",
        "collection",
        "hasItems",
        "has_items",
        "isArray",
        "is_array",
        "isList",
        "is_list",
        "multiple",
    ):
        value = prop.get(key)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in {"true", "1", "yes"}:
            return True

    for key in ("kind", "valueKind", "propertyKind", "relationKind", "cardinality", "multiplicity"):
        value = prop.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        if "collection" in normalized or normalized in {"array", "list", "many", "multiple"}:
            return True

    for key in ("type", "valueType", "dataType", "propertyType"):
        value = prop.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.strip().lower()
        if normalized in {"collection", "array", "list"}:
            return True
        if normalized.endswith("[]") or normalized.startswith(("collection<", "list<", "array<")):
            return True

    return False


def metadata_collection_name(prop: dict[str, Any], fallback: Any = None) -> str:
    return clean_text(
        first_present(
            prop.get("collectionName"),
            prop.get("collection_name"),
            prop.get("name"),
            prop.get("propertyName"),
            fallback,
        )
    )


def metadata_data_has_property(data: dict[str, Any], name: Any) -> bool:
    normalized_name = normalize_asset_metadata_key(name)
    return any(normalize_asset_metadata_key(key) == normalized_name for key in data)


def is_windows_asset_card_root(root: dict[str, Any]) -> bool:
    """Return whether an MP VM asset tree represents a Windows host."""
    if not isinstance(root, dict):
        return False
    data = as_dict(root.get("data"))
    values = (
        root.get("type"),
        root.get("assetType"),
        root.get("osName"),
        root.get("os_name"),
        data.get("osName"),
        data.get("os_name"),
        data.get("operatingSystem"),
    )
    return any("windows" in str(value or "").casefold() for value in values)


def is_excluded_windows_asset_card_branch(*values: Any) -> bool:
    """Match a collection/node property against the Windows exclusion list."""
    for value in values:
        normalized = normalize_asset_metadata_key(value)
        if normalized in WINDOWS_ASSET_CARD_EXCLUDED_COLLECTIONS:
            return True
    return False


def filter_windows_asset_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Remove excluded Windows collection definitions from cached metadata."""
    if not isinstance(metadata, dict):
        return {}
    filtered = dict(metadata)
    properties = metadata.get("properties")
    if isinstance(properties, list):
        filtered["properties"] = [
            prop for prop in properties
            if not isinstance(prop, dict)
            or not is_excluded_windows_asset_card_branch(
                prop.get("name"), prop.get("collectionName"), prop.get("collection_name"), prop.get("title")
            )
        ]
    for key in ("collections", "collectionProperties", "collection_properties"):
        value = metadata.get(key)
        if isinstance(value, list):
            filtered[key] = [
                prop for prop in value
                if not is_excluded_windows_asset_card_branch(
                    prop.get("name") if isinstance(prop, dict) else prop,
                    prop.get("collectionName") if isinstance(prop, dict) else None,
                    prop.get("title") if isinstance(prop, dict) else None,
                )
            ]
        elif isinstance(value, dict):
            filtered[key] = {
                name: prop for name, prop in value.items()
                if not is_excluded_windows_asset_card_branch(
                    name, prop.get("collectionName") if isinstance(prop, dict) else None,
                    prop.get("title") if isinstance(prop, dict) else prop,
                )
            }
    return filtered


def should_fetch_collection(prop: dict[str, Any], value: Any) -> bool:
    if isinstance(value, dict) and "hasItems" in value:
        return True
    return metadata_property_is_collection(prop)


def is_object_ref(value: Any) -> bool:
    return isinstance(value, dict) and bool(value.get("objectId")) and bool(value.get("type"))


def asset_value_to_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "hasItems" in value:
            return "есть элементы" if value.get("hasItems") else "нет элементов"
        label = first_present(value.get("displayName"), value.get("name"), value.get("title"), value.get("objectId"))
        if label:
            return str(label)
    try:
        return json_dumps_compact(value)
    except TypeError:
        return str(value)


def normalize_asset_candidate_record(record: dict[str, Any]) -> dict[str, Any]:
    host = as_dict(record.get("@Host"))
    host_value = record.get("@Host")
    asset_id = first_present(
        host.get("internalId"),
        host.get("id"),
        host.get("objectId"),
        record.get("Host.@Id"),
        record.get("AssetId"),
        record.get("assetId"),
    )
    if not asset_id and isinstance(host_value, str):
        asset_id = extract_uuid(host_value)
    display_name = first_present(
        host.get("displayName"),
        host.get("name"),
        host.get("title"),
        record.get("HostName"),
        host_value if isinstance(host_value, str) else None,
    )
    return {
        "asset_id": asset_id,
        "display_name": display_name,
        "os_name": first_present(record.get("Host.OsName"), host.get("osName")),
        "creation_time": first_present(record.get("Host.@CreationTime"), host.get("creationTime")),
        "update_time": first_present(record.get("Host.@UpdateTime"), host.get("updateTime")),
        "raw_record": record,
    }


def dedupe_asset_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for candidate in candidates:
        key = candidate.get("asset_id") or candidate.get("display_name")
        if key is None:
            result.append(candidate)
            continue
        key_text = str(key)
        if key_text in seen:
            continue
        seen.add(key_text)
        result.append(candidate)
    return result


def is_hidden_asset_technical_field(key: Any) -> bool:
    normalized = str(key or "").replace("_", "").replace("-", "").lower()
    return normalized in {"type", "objectid"}


def labelize_asset_key(key: Any) -> str:
    labels = {
        "ipAddress": "IP-адрес",
        "fqdn": "Полное имя узла",
        "hostname": "Имя узла",
        "hostType": "Тип узла",
        "macAddress": "MAC-адрес",
        "osName": "Название ОС",
        "osVersion": "Версия ОС",
        "isVirtual": "Виртуальное устройство",
        "displayName": "Название",
        "vulnerabilityLevel": "Уровень уязвимости",
    }
    text = str(key or "")
    return labels.get(text) or re.sub(r"([a-zа-яё])([A-ZА-ЯЁ])", r"\1 \2", text)


def sanitize_asset_card_for_response(card: dict[str, Any]) -> dict[str, Any]:
    cleaned = strip_raw_asset_values(card)
    if isinstance(cleaned, dict):
        cleaned.pop("timeline_token", None)
        cleaned.pop("asset_token", None)
    return cleaned if isinstance(cleaned, dict) else {}


def strip_raw_asset_values(value: Any) -> Any:
    raw_keys = {"raw", "raw_card", "raw_record", "raw_detail", "raw_value"}
    if isinstance(value, list):
        return [strip_raw_asset_values(item) for item in value]
    if isinstance(value, dict):
        return {
            key: strip_raw_asset_values(item)
            for key, item in value.items()
            if key not in raw_keys
        }
    return value
