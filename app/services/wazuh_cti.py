"""Load and cache the public Wazuh CTI record for a local CVE passport."""

import re
from typing import Any

import requests
from fastapi import HTTPException

from ..repositories.passports.wazuh_cti import save_detail

PASSPORT_ID = re.compile(r"wazuh-cti:(CVE-[0-9]{4}-[0-9]{4,})")


def refresh_passport(passport_id: str) -> dict[str, Any]:
    match = PASSPORT_ID.fullmatch(passport_id)
    if not match:
        raise HTTPException(status_code=404, detail="Паспорт Wazuh CTI не найден.")
    cve = match[1]
    url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve}"
    try:
        response = requests.get(f"{url}/json5", timeout=(3, 10), allow_redirects=False)
        response.raise_for_status()
        record = response.json()
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"{cve} отсутствует в Wazuh CTI.") from exc
        raise HTTPException(status_code=502, detail="Wazuh CTI временно недоступен.") from exc
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Не удалось загрузить запись Wazuh CTI.") from exc

    metadata = record.get("cveMetadata") if isinstance(record, dict) else None
    containers = record.get("containers") if isinstance(record, dict) else None
    if not isinstance(metadata, dict) or metadata.get("cveId") != cve or not isinstance(containers, dict):
        raise HTTPException(status_code=502, detail="Wazuh CTI вернул некорректную запись CVE.")
    adp = containers.get("adp")
    providers = [containers.get("cna"), *(adp if isinstance(adp, list) else [])]
    descriptions = []
    scores = []
    references: dict[str, None] = {}
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        for reference in provider.get("references") or []:
            link = reference.get("url") if isinstance(reference, dict) else None
            if isinstance(link, str) and link.lower().startswith(("https://", "http://")):
                references[link] = None
        for item in provider.get("descriptions") or []:
            if isinstance(item, dict) and isinstance(item.get("value"), str):
                descriptions.append(item)
        for metric in provider.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                score = metric.get(key)
                if isinstance(score, dict) and type(score.get("baseScore")) in (float, int):
                    scores.append(score)
    cvss = max(scores, key=lambda score: score["baseScore"], default={})
    description = next(
        (item["value"] for item in descriptions if item.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else None,
    )
    saved = save_detail(passport_id, {
        "source": "wazuh-cti",
        "url": url,
        "cves": [cve],
        "description": description,
        "severity": cvss.get("baseSeverity"),
        "score": cvss.get("baseScore"),
        "publishedAt": metadata.get("datePublished"),
        "references": list(references),
    })
    if saved is None:
        raise HTTPException(status_code=404, detail="Паспорт Wazuh CTI не найден.")
    return saved
