from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException

from ..mpvm_client import MpVmClient
from .common import as_dict, clean_text, first_present, number_or_none
from .scan_results import extract_asset_grid_records, extract_asset_grid_total

DOCKER_PDQL_REQUIRED_FIELDS = (
    "@Host",
    "Docker",
    "Container",
    "ContainerId",
    "ImageId",
    "Q.Package",
    "Q.Vulner",
    "Q.VulnerStatus",
    "Q.HowToFix",
)


def validate_docker_vulnerability_pdql(pdql: str) -> str:
    value = str(pdql or "").strip()
    select_clauses = re.findall(
        r"(?:^|\|)\s*select\s*\((.*?)\)\s*(?=\|)",
        value,
        re.IGNORECASE | re.DOTALL,
    )
    output_contract = select_clauses[-1] if select_clauses else ""
    missing = [
        field
        for field in DOCKER_PDQL_REQUIRED_FIELDS
        if not re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
            output_contract,
            re.IGNORECASE,
        )
    ]
    problems: list[str] = []
    if missing:
        problems.append(f"missing fields: {', '.join(missing)}")
    if not re.search(r"\|\s*group\s*\(", value, re.IGNORECASE):
        problems.append("group(...) is required")
    if problems:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_DOCKER_PDQL",
                "message": "; ".join(problems),
                "required_fields": list(DOCKER_PDQL_REQUIRED_FIELDS),
            },
        )
    return value


def render_docker_vulnerability_pdql(template: str, asset_id: str, asset_type: str | None) -> str:
    if "${ASSET_SELECTOR}" not in template:
        return template
    asset_alias = "ImageSet" if str(asset_type or "").lower() == "imageset" else "Host"
    try:
        asset_uuid = str(uuid.UUID(str(asset_id).strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("asset_id must be a UUID for Docker PDQL filtering") from exc
    # UUID is a native PDQL value type and must not be quoted. Parsing it first
    # keeps the placeholder safe while preserving the type expected by @Id.
    selector = f"{asset_alias}.@Id = {asset_uuid}"
    return template.replace("${ASSET_SELECTOR}", selector)


def docker_scan_group_name(run_id: str) -> str:
    run_key = re.sub(r"[^a-zA-Z0-9-]", "", str(run_id)) or str(uuid.uuid4())
    return f"docker containers [mpvm scan] {run_key[:80]}"


def docker_dynamic_group_from_options(options: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(options, dict):
        return None
    group = options.get("docker_dynamic_group")
    if not isinstance(group, dict) or not (group.get("id") or group.get("name")):
        return None
    return dict(group)


def _docker_record_raw_value(record: dict[str, Any], alias: str) -> Any:
    normalized_alias = re.sub(r"[^a-z0-9]", "", alias.lower())
    for key, value in record.items():
        if re.sub(r"[^a-z0-9]", "", str(key).lower()) != normalized_alias:
            continue
        return value
    return None


def _docker_record_value(record: dict[str, Any], alias: str) -> Any:
    value = _docker_record_raw_value(record, alias)
    if value is not None:
        if isinstance(value, dict):
            return first_present(
                value.get("value"), value.get("displayName"), value.get("name"),
                value.get("id"), value.get("key"),
            )
        if isinstance(value, list):
            return first_present(*value)
        return value
    return None


def _docker_mapping_text(value: Any, *keys: str) -> str:
    if not isinstance(value, dict):
        return clean_text(value)
    return clean_text(first_present(*(value.get(key) for key in keys)))


def _docker_package_parts(value: Any) -> tuple[str, str, str]:
    if isinstance(value, dict):
        name = _docker_mapping_text(value, "name", "displayName", "packageName", "id")
        version = _docker_mapping_text(value, "version", "packageVersion")
        label = _docker_mapping_text(value, "value", "displayName")
        if not label:
            label = name + (f" ({version})" if version else "")
        return label, name, version

    label = clean_text(value).strip()
    match = re.fullmatch(r"(.+?)\s*\((.*)\)\s*", label)
    if not match:
        return label, label, ""
    return label, match.group(1).strip(), match.group(2).strip()


def _docker_cve(value: Any) -> str:
    try:
        searchable = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        searchable = clean_text(value)
    match = re.search(r"\bCVE-\d{4}-\d{4,}\b", searchable, re.IGNORECASE)
    return match.group(0).upper() if match else ""


def _docker_instance_id(
    *, asset_id: str, container_id: str, container_name: str, image_id: str,
    package_label: str, vulnerability_id: str, cve_name: str, vulnerability_name: str,
) -> str:
    identity = "|".join((
        asset_id,
        container_id or container_name,
        image_id,
        package_label,
        vulnerability_id or cve_name or vulnerability_name,
    ))
    return f"docker:{uuid.uuid5(uuid.NAMESPACE_URL, identity).hex}"


def normalize_docker_vulnerability_record(
    record: dict[str, Any], *, fallback_asset_id: str = "",
) -> dict[str, Any]:
    host = _docker_record_raw_value(record, "@Host")
    vulnerability = _docker_record_raw_value(record, "Q.Vulner")
    if not isinstance(vulnerability, dict):
        vulnerability = {}
    vulnerability_status = _docker_record_raw_value(record, "Q.VulnerStatus")
    if not isinstance(vulnerability_status, dict):
        vulnerability_status = {}

    asset_id = _docker_mapping_text(host, "id", "objectId", "key") or clean_text(
        first_present(_docker_record_value(record, "AssetId"), fallback_asset_id)
    )
    host_name = _docker_mapping_text(host, "name", "displayName")
    docker_engine = clean_text(_docker_record_value(record, "Docker"))
    container_name = clean_text(_docker_record_value(record, "Container"))
    container_id = clean_text(_docker_record_value(record, "ContainerId"))
    image_id = clean_text(first_present(
        _docker_record_value(record, "ImageId"),
        _docker_record_value(record, "ImageKey"),
        _docker_record_value(record, "Digest"),
    ))

    package_value = _docker_record_raw_value(record, "Q.Package")
    if package_value is None:
        package_name = clean_text(_docker_record_value(record, "PackageName"))
        package_version = clean_text(_docker_record_value(record, "PackageVersion"))
        package_label = package_name + (f" ({package_version})" if package_version else "")
    else:
        package_label, package_name, package_version = _docker_package_parts(package_value)

    vulnerability_name = _docker_mapping_text(vulnerability, "name", "displayName", "value")
    vulnerability_kb = _docker_mapping_text(vulnerability, "kb", "knowledgeBase")
    vulnerability_internal_id = _docker_mapping_text(vulnerability, "internalId", "internal_id")
    source_vulnerability_id = _docker_mapping_text(vulnerability, "id", "objectId")
    vulnerability_id = clean_text(first_present(
        vulnerability_internal_id,
        _docker_record_value(record, "VulnerabilityId"),
        source_vulnerability_id,
    ))
    cve_name = _docker_cve(vulnerability) or clean_text(_docker_record_value(record, "CVE"))
    level = _docker_mapping_text(vulnerability, "severityRating", "severity", "level") or clean_text(
        _docker_record_value(record, "Severity")
    )
    status = _docker_mapping_text(vulnerability_status, "value", "name", "displayName") or clean_text(
        first_present(_docker_record_value(record, "VulnerStatus"), _docker_record_value(record, "Status"))
    )
    status_id = _docker_mapping_text(vulnerability_status, "id", "key")
    how_to_fix = clean_text(_docker_record_value(record, "Q.HowToFix"))

    image = {
        "image_key": image_id,
        "image_name": clean_text(first_present(_docker_record_value(record, "ImageName"), image_id)),
        "registry": clean_text(_docker_record_value(record, "Registry")),
        "repository": clean_text(_docker_record_value(record, "Repository")),
        "tag": clean_text(_docker_record_value(record, "Tag")),
        "digest": clean_text(first_present(_docker_record_value(record, "Digest"), image_id)),
        "image_os_name": clean_text(_docker_record_value(record, "ImageOsName")),
        "image_os_version": clean_text(_docker_record_value(record, "ImageOsVersion")),
    }
    repository = "/".join(filter(None, (image["registry"], image["repository"])))
    image["image_key"] = clean_text(first_present(
        image["image_key"], image["digest"], repository + (f":{image['tag']}" if image["tag"] else ""),
    ))
    legacy_instance_id = clean_text(_docker_record_value(record, "VulnerabilityInstanceId"))
    instance_id = (
        _docker_instance_id(
            asset_id=asset_id,
            container_id=container_id,
            container_name=container_name,
            image_id=image_id,
            package_label=package_label,
            vulnerability_id=vulnerability_id,
            cve_name=cve_name,
            vulnerability_name=vulnerability_name,
        )
        if container_id or container_name
        else legacy_instance_id
    )
    container = {
        "container_id": container_id,
        "container_name": container_name,
        "docker_engine": docker_engine,
        "image_id": image_id,
    }
    return {
        "asset_id": asset_id,
        "host_name": host_name,
        "level": level,
        "name": clean_text(first_present(vulnerability_name, cve_name, vulnerability_id, package_name)),
        "cve_name": cve_name,
        "cvss_score": number_or_none(_docker_record_value(record, "CvssScore")),
        "vulnerability_id": vulnerability_id,
        "vulnerability_instance_id": instance_id,
        "source_vulnerability_instance_id": source_vulnerability_id or legacy_instance_id,
        "vulnerability_kb": vulnerability_kb,
        "package_name": package_name,
        "package_version": package_version,
        "package_label": package_label,
        "fixed_version": clean_text(_docker_record_value(record, "FixedVersion")),
        "status": status,
        "status_id": status_id,
        "how_to_fix": how_to_fix,
        "object_id": image_id,
        "container_id": container_id,
        "container_name": container_name,
        "docker_engine": docker_engine,
        "image_id": image_id,
        "docker_container": container,
        "docker_image": image,
    }


def _docker_image_label(image: dict[str, Any]) -> str:
    repository = "/".join(filter(None, (image.get("registry"), image.get("repository"))))
    if repository:
        return repository + (f":{image.get('tag')}" if image.get("tag") else "")
    return clean_text(first_present(image.get("image_name"), image.get("digest"), image.get("image_key"), "Docker image"))


def _docker_container_key(finding: dict[str, Any]) -> str:
    container = as_dict(finding.get("docker_container"))
    image = as_dict(finding.get("docker_image"))
    return clean_text(first_present(
        container.get("container_id"),
        finding.get("container_id"),
        container.get("container_name"),
        finding.get("container_name"),
        image.get("image_key"),
        image.get("digest"),
        _docker_image_label(image),
    ))


def _docker_container_label(finding: dict[str, Any]) -> str:
    container = as_dict(finding.get("docker_container"))
    image = as_dict(finding.get("docker_image"))
    return clean_text(first_present(
        container.get("container_name"), finding.get("container_name"),
        container.get("container_id"), finding.get("container_id"),
        _docker_image_label(image), "Docker container",
    ))


def _docker_finding_key(finding: dict[str, Any]) -> str:
    instance_id = clean_text(finding.get("vulnerability_instance_id"))
    if instance_id:
        return f"instance:{instance_id}"
    vulnerability_id = clean_text(finding.get("vulnerability_id"))
    package_name = clean_text(finding.get("package_name"))
    package_version = clean_text(finding.get("package_version"))
    if vulnerability_id:
        return (
            f"vulnerability:{vulnerability_id}|package:{package_name}"
            f"|version:{package_version}"
        )
    return "|".join((
        f"cve:{clean_text(finding.get('cve_name'))}",
        f"package:{package_name}",
        f"version:{package_version}",
    ))


def _docker_finding_candidate_keys(finding: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    instance_id = clean_text(finding.get("vulnerability_instance_id"))
    vulnerability_id = clean_text(finding.get("vulnerability_id"))
    cve_name = clean_text(finding.get("cve_name"))
    package_name = clean_text(finding.get("package_name"))
    package_version = clean_text(finding.get("package_version"))
    if instance_id:
        keys.add(f"instance:{instance_id}")
    if vulnerability_id:
        keys.add(
            f"vulnerability:{vulnerability_id}|package:{package_name}"
            f"|version:{package_version}"
        )
    if cve_name:
        keys.add(f"cve:{cve_name}|package:{package_name}|version:{package_version}")
    return keys or {_docker_finding_key(finding)}


def _docker_groups(findings: list[dict[str, Any]], *, truncated: bool = False) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    seen: dict[str, set[str]] = {}
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    for finding in findings:
        image = as_dict(finding.get("docker_image"))
        container = as_dict(finding.get("docker_container"))
        key = _docker_container_key(finding)
        if not key:
            continue
        group = groups.setdefault(key, {
            "source": "docker", "collection_type": "DockerContainerVulnerabilities", "collection_id": key,
            "name": _docker_container_label(finding), "level": None, "vulnerabilities_count": 0,
            "cvss_score": None, "order": len(groups), "truncated": truncated,
            **image, **container, "items": [],
        })
        finding_key = _docker_finding_key(finding)
        if finding_key and finding_key in seen.setdefault(key, set()):
            continue
        if finding_key:
            seen[key].add(finding_key)
        group["items"].append(finding)
        level = clean_text(finding.get("level")).lower()
        if severity_rank.get(level, 0) > severity_rank.get(clean_text(group.get("level")).lower(), 0):
            group["level"] = level
        score = number_or_none(finding.get("cvss_score"))
        if score is not None and (group["cvss_score"] is None or score > group["cvss_score"]):
            group["cvss_score"] = score
    for group in groups.values():
        group["vulnerabilities_count"] = len(group["items"])
    return list(groups.values())


def _extract_docker_fallback(sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for source in sources:
        if source.get("source") != "software":
            continue
        retained_groups: list[dict[str, Any]] = []
        for group in source.get("groups") or []:
            original_items = group.get("items") or []
            retained: list[dict[str, Any]] = []
            for finding in original_items:
                image = finding.get("docker_image") if isinstance(finding, dict) else None
                if image and any(image.get(key) for key in ("image_key", "digest", "repository")):
                    findings.append(finding)
                else:
                    retained.append(finding)
            group["items"] = retained
            if original_items:
                group["vulnerabilities_count"] = len(retained)
            if retained or not original_items:
                retained_groups.append(group)
        source["groups"] = retained_groups
        source["vulnerabilities_count"] = sum(
            int(group.get("vulnerabilities_count") or 0) for group in retained_groups
        )
    return findings


def build_docker_vulnerability_source(
    *, token: str, asset_id: str, asset_type: str | None, pdql_template: str,
    max_items: int, sources: list[dict[str, Any]],
    remote_call: Callable[[Callable[[MpVmClient], Any], str], Any],
) -> tuple[dict[str, Any], str | None]:
    fallback = _extract_docker_fallback(sources)
    primary: list[dict[str, Any]] = []
    group_headers: list[dict[str, Any]] = []
    primary_truncated = False
    warning: str | None = None
    try:
        inline_selector = "${ASSET_SELECTOR}" in pdql_template
        pdql = render_docker_vulnerability_pdql(pdql_template, asset_id, asset_type)
        pdql_token = remote_call(
            lambda remote: remote.create_pdql_token(
                token,
                pdql,
                asset_ids=[] if inline_selector else [asset_id],
            ),
            "docker_pdql_token",
        )
        header_response = remote_call(
            lambda remote: remote.fetch_asset_grid_data(
                token,
                pdql_token,
                limit=1001,
            ),
            "docker_pdql_groups",
        )
        group_headers = extract_asset_grid_records(header_response)
        offset = 0
        reported_total: int | None = None
        while offset < max_items:
            page_limit = min(1001, max_items - offset)
            def fetch_group_page(remote: Any, offset: int = offset, page_limit: int = page_limit) -> Any:
                return remote.fetch_asset_grid_group_data(
                    token,
                    pdql_token,
                    limit=page_limit,
                    offset=offset or None,
                )

            response = remote_call(fetch_group_page, "docker_pdql_group_page")
            rows = extract_asset_grid_records(response)
            for row in rows:
                finding = normalize_docker_vulnerability_record(row, fallback_asset_id=asset_id)
                raw_vulnerability = _docker_record_raw_value(row, "Q.Vulner")
                if raw_vulnerability or finding.get("vulnerability_id") or finding.get("cve_name"):
                    primary.append(finding)
            page_total = extract_asset_grid_total(response)
            if page_total is not None:
                reported_total = page_total
            if not rows:
                primary_truncated = reported_total is not None and offset < reported_total
                break
            offset += len(rows)
            if reported_total is not None:
                if offset >= reported_total:
                    break
                if offset >= max_items:
                    primary_truncated = reported_total > max_items
                    break
                continue
            if len(rows) < page_limit:
                break
            if offset >= max_items:
                primary_truncated = True
    except Exception as exc:
        primary_truncated = bool(primary)
        warning = f"Docker container PDQL is unavailable: {exc}"

    selected = primary if primary else fallback
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in selected:
        container_key = _docker_container_key(finding)
        candidate_keys = {f"{container_key}|{key}" for key in _docker_finding_candidate_keys(finding)}
        if seen.intersection(candidate_keys):
            continue
        seen.update(candidate_keys)
        if not clean_text(finding.get("vulnerability_instance_id")):
            identity = f"{container_key}|{_docker_finding_key(finding)}"
            finding["vulnerability_instance_id"] = f"docker:{uuid.uuid5(uuid.NAMESPACE_URL, identity).hex}"
        merged.append(finding)
    groups = _docker_groups(merged, truncated=primary_truncated)
    mode = "containers" if primary else "fallback" if fallback else "unavailable" if warning else "empty"
    return ({
        "source": "docker", "collection_type": "DockerContainerVulnerabilities", "title": "Docker containers",
        "status": mode, "fallback_used": bool(fallback and not primary),
        "reported_container_groups": len(group_headers),
        "vulnerabilities_count": sum(len(group["items"]) for group in groups), "groups": groups,
    }, warning)
