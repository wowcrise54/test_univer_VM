from __future__ import annotations

from io import BytesIO
from typing import Any, Iterable

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter


def _safe_cell(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def _write_sheet(sheet, headers: list[str], rows: Iterable[Iterable[Any]]) -> None:
    sheet.append(headers)
    for row in rows:
        sheet.append([_safe_cell(value) for value in row])
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.alignment = Alignment(wrap_text=True)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for column in range(1, len(headers) + 1):
        values = [str(sheet.cell(row, column).value or "") for row in range(1, sheet.max_row + 1)]
        sheet.column_dimensions[get_column_letter(column)].width = min(max(map(len, values), default=0) + 2, 48)


OS_HEADERS = [
    "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "ОС", "Версия ОС",
    "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
]
SOFTWARE_HEADERS = [
    "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "Программное обеспечение",
    "CVE", "Уязвимость", "Критичность", "CVSS", "Дата обновления карточки",
]
DOCKER_HEADERS = [
    "Asset ID", "IP-адрес", "FQDN", "Имя хоста", "Docker Engine", "Контейнер",
    "Container ID", "Образ", "Image ID", "Registry", "Repository", "Tag", "Пакет",
    "Версия пакета", "CVE", "Уязвимость", "Vulnerability ID", "Критичность",
    "CVSS", "Статус", "Исправленная версия", "Рекомендация", "Дата обновления карточки",
]


def _common(row: dict[str, Any]) -> list[Any]:
    return [row.get("asset_id"), row.get("ip_address"), row.get("fqdn"), row.get("hostname")]


def render_vulnerability_xlsx(
    asset: dict[str, Any],
    os_rows: Iterable[dict[str, Any]],
    software_rows: Iterable[dict[str, Any]],
    docker_rows: Iterable[dict[str, Any]],
) -> bytes:
    workbook = Workbook()
    asset_sheet = workbook.active
    asset_sheet.title = "Актив"
    asset_headers = ["Поле", "Значение"]
    asset_rows = [
        ["Asset ID", asset.get("asset_id")],
        ["Имя", asset.get("display_name")],
        ["Имя хоста", asset.get("hostname")],
        ["IP-адрес", asset.get("ip_address")],
        ["FQDN", asset.get("fqdn")],
        ["Тип актива", asset.get("asset_type")],
        ["ОС", asset.get("os_name")],
        ["Версия ОС", asset.get("os_version")],
        ["Уровень уязвимости", asset.get("vulnerability_level")],
        ["Первое обнаружение", asset.get("first_seen")],
        ["Последнее обновление карточки", asset.get("last_seen")],
    ]
    _write_sheet(asset_sheet, asset_headers, asset_rows)

    os_sheet = workbook.create_sheet("Уязвимости ОС")
    _write_sheet(os_sheet, OS_HEADERS, (
        _common(row) + [
            row.get("os_name"), row.get("os_version"), row.get("cve_name"),
            row.get("vulnerability_name"), row.get("severity"), row.get("cvss_score"),
            row.get("last_seen"),
        ]
        for row in os_rows
    ))

    software_sheet = workbook.create_sheet("Уязвимости ПО")
    _write_sheet(software_sheet, SOFTWARE_HEADERS, (
        _common(row) + [
            row.get("object_name"), row.get("cve_name"), row.get("vulnerability_name"),
            row.get("severity"), row.get("cvss_score"), row.get("last_seen"),
        ]
        for row in software_rows
    ))

    docker_sheet = workbook.create_sheet("Уязвимости Docker")
    _write_sheet(docker_sheet, DOCKER_HEADERS, (
        _common(row) + [
            row.get("docker_engine"), row.get("container_name"), row.get("container_id"),
            row.get("image_name"), row.get("image_id"), row.get("registry"),
            row.get("repository"), row.get("tag"), row.get("package_name"),
            row.get("package_version"), row.get("cve_name"), row.get("vulnerability_name"),
            row.get("vulnerability_id"), row.get("severity"), row.get("cvss_score"),
            row.get("vulnerability_status"), row.get("fixed_version"), row.get("how_to_fix"),
            row.get("last_seen"),
        ]
        for row in docker_rows
    ))

    output = BytesIO()
    workbook.save(output)
    return output.getvalue()
