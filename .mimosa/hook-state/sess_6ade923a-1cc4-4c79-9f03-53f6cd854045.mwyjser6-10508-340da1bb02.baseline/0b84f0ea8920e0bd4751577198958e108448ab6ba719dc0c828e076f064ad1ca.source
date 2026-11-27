from __future__ import annotations

import csv
import io
from typing import Any, Literal

VULNERABILITY_REPORT_HEADERS = {
    "os": [
        "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "ОС", "Версия ОС",
        "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
    ],
    "software": [
        "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "Программное обеспечение",
        "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
    ],
    "docker": [
        "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "Docker Engine", "Контейнер",
        "Container ID", "Образ", "Image ID", "Registry", "Repository", "Tag", "Пакет",
        "Версия пакета", "CVE", "Уязвимость", "Vulnerability ID", "Критичность",
        "CVSS", "Статус", "Исправленная версия", "Рекомендация", "Дата обновления карточки",
    ],
}


def safe_csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def stream_vulnerability_report_csv(report_type: Literal["os", "software", "docker"], rows):
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(VULNERABILITY_REPORT_HEADERS[report_type])
    yield "\ufeff" + output.getvalue()
    for row in rows:
        output.seek(0)
        output.truncate(0)
        common = [
            row.get("asset_id"), row.get("ip_address"), row.get("fqdn"), row.get("hostname"),
        ]
        if report_type == "os":
            values = common + [row.get("os_name"), row.get("os_version")]
        elif report_type == "software":
            values = common + [row.get("object_name")]
        else:
            values = common + [
                row.get("docker_engine"), row.get("container_name"), row.get("container_id"),
                row.get("image_name"), row.get("image_id"), row.get("registry"),
                row.get("repository"), row.get("tag"), row.get("package_name"),
                row.get("package_version"), row.get("cve_name"), row.get("vulnerability_name"),
                row.get("vulnerability_id"), row.get("severity"), row.get("cvss_score"),
                row.get("vulnerability_status"), row.get("fixed_version"), row.get("how_to_fix"),
                row.get("last_seen"),
            ]
        if report_type != "docker":
            values += [
                row.get("cve_name"), row.get("vulnerability_name"), row.get("severity"),
                row.get("cvss_score"), row.get("last_seen"),
            ]
        writer.writerow([safe_csv_cell(value) for value in values])
        yield output.getvalue()
