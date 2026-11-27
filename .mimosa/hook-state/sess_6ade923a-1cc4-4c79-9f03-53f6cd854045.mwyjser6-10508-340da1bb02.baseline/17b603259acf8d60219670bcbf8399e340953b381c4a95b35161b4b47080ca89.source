"""Repository for asset card query presets."""

from __future__ import annotations

from typing import Any

ASSET_CARD_QUERY_PRESETS: dict[str, dict[str, Any]] = {
    "windows-software": {
        "id": "windows-software",
        "name": "ПО Windows",
        "description": "Установленное ПО на Windows-активах, сгруппированное по названию.",
        "kind": "software",
        "windows_only": True,
        "grouping": "name",
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            "filter(WindowsHost.Softs) | select(@WindowsHost, WindowsHost.Softs.Name as SoftName, "
            "WindowsHost.Softs.Version as SoftVersion, WindowsHost.Softs.Vendor, "
            "WindowsHost.Softs.Architecture, WindowsHost.Softs.InstallPath as InstallPath, "
            "WindowsHost.@UpdateTime) | unique() | sort(@WindowsHost ASC, SoftName ASC, "
            "SoftVersion ASC, InstallPath ASC) | group(SoftName, COUNT(*)) | sort(SoftName ASC)"
        ),
    },
    "windows-software-by-version": {
        "id": "windows-software-by-version",
        "name": "ПО Windows, сгруппированное по версиям",
        "description": "Установленное ПО на Windows-активах по названию и версии.",
        "kind": "software",
        "windows_only": True,
        "grouping": "name_version",
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "soft_version", "label": "Версия"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            "filter(WindowsHost.Softs) | select(@WindowsHost, WindowsHost.Softs.Name as SoftName, "
            "WindowsHost.Softs.Version as SoftVersion, WindowsHost.Softs.Vendor, "
            "WindowsHost.Softs.Architecture, WindowsHost.Softs.InstallPath as InstallPath, "
            "WindowsHost.@UpdateTime) | unique() | sort(@WindowsHost ASC, InstallPath ASC) | "
            "group(SoftName, SoftVersion, COUNT(*)) | sort(SoftName ASC, SoftVersion ASC)"
        ),
    },
    "windows-software-search": {
        "id": "windows-software-search",
        "name": "Поиск определённого ПО на активах Windows",
        "description": "Поиск по части названия без учёта регистра и маске версии ПО только на Windows-активах.",
        "kind": "software",
        "windows_only": True,
        "grouping": "name_version",
        "search": True,
        "defaults": {"software_name": "OpenSSL", "software_version_like": "3.%"},
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "soft_version", "label": "Версия"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            'filter(WindowsHost.Softs) | select(@Host, Host.Softs.Name as SoftName, '
            "Host.Softs.Version as SoftVersion, Host.@UpdateTime) | unique() | sort(@Host ASC) | "
            'group(SoftName, SoftVersion, COUNT(*)) | filter(SoftName = "OpenSSL" and '
            'SoftVersion like "3.%") | sort(SoftName, SoftVersion)'
        ),
    },
    "software": {
        "id": "software",
        "name": "ПО на активах",
        "description": "Установленное ПО на всех локальных карточках, сгруппированное по названию.",
        "kind": "software",
        "windows_only": False,
        "grouping": "name",
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            "filter(Host.Softs) | select(@Host, Host.Softs.Name as SoftName, "
            "Host.Softs.Version as SoftVersion, Host.Softs.Vendor, Host.Softs.Architecture, "
            "Host.Softs.InstallPath as InstallPath, Host.@UpdateTime) | sort(@Host ASC, "
            "SoftName ASC, SoftVersion ASC, InstallPath ASC) | group(SoftName, COUNT(*)) | "
            "sort(SoftName ASC)"
        ),
    },
    "software-by-version": {
        "id": "software-by-version",
        "name": "ПО на активах, сгруппированное по версиям",
        "description": "Установленное ПО на всех локальных карточках по названию и версии.",
        "kind": "software",
        "windows_only": False,
        "grouping": "name_version",
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "soft_version", "label": "Версия"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            "filter(Host.Softs) | select(@Host, Host.Softs.Name as SoftName, "
            "Host.Softs.Version as SoftVersion, Host.Softs.Vendor, Host.Softs.Architecture, "
            "Host.Softs.InstallPath as InstallPath, Host.@UpdateTime) | sort(@Host ASC, "
            "InstallPath ASC) | group(SoftName, SoftVersion, COUNT(*)) | "
            "sort(SoftName ASC, SoftVersion ASC)"
        ),
    },
    "software-search": {
        "id": "software-search",
        "name": "Поиск определённого ПО на активах",
        "description": "Поиск по части названия без учёта регистра и маске версии ПО на всех локальных карточках.",
        "kind": "software",
        "windows_only": False,
        "grouping": "name_version",
        "search": True,
        "defaults": {"software_name": "OpenSSL", "software_version_like": "3.%"},
        "columns": [
            {"key": "soft_name", "label": "ПО"},
            {"key": "soft_version", "label": "Версия"},
            {"key": "count", "label": "Количество установок"},
        ],
        "pdql": (
            'filter(Host.Softs) | select(@Host, Host.Softs.Name as SoftName, '
            "Host.Softs.Version as SoftVersion, Host.@UpdateTime) | unique() | sort(@Host ASC) | "
            'group(SoftName, SoftVersion, COUNT(*)) | filter(SoftName = "OpenSSL" and '
            'SoftVersion like "3.%") | sort(SoftName, SoftVersion)'
        ),
    },
    "software-vendors": {
        "id": "software-vendors",
        "name": "Вендоры ПО",
        "description": "Количество записей установленного ПО по вендорам.",
        "kind": "software",
        "windows_only": False,
        "grouping": "vendor",
        "columns": [
            {"key": "vendor", "label": "Вендор"},
            {"key": "soft_number", "label": "Количество ПО"},
        ],
        "pdql": (
            "filter(Host.Softs) | select(@Host, Host.Softs.Name as SoftName, "
            "Host.Softs.Version as SoftVersion, Host.Softs.Vendor as Vendor, "
            "Host.Softs.Architecture, Host.Softs.InstallPath as InstallPath, Host.@UpdateTime) | "
            "sort(@Host ASC, SoftName ASC, SoftVersion ASC, InstallPath ASC) | "
            "group(Vendor, COUNT(*) as SoftNumber) | sort(SoftNumber DESC)"
        ),
    },
    "os-versions": {
        "id": "os-versions",
        "name": "Версии ОС",
        "description": "Активы, сгруппированные по названию и версии операционной системы.",
        "kind": "os",
        "columns": [
            {"key": "os_name", "label": "ОС"},
            {"key": "os_version", "label": "Версия"},
            {"key": "count", "label": "Количество активов"},
        ],
        "pdql": (
            "select(@Host, Host.OsName, Host.OsVersion, Host.@UpdateTime) | "
            "group(Host.OsName, Host.OsVersion, COUNT(*)) | "
            "sort(Host.OsName ASC, Host.OsVersion ASC)"
        ),
    },
}




def public_asset_card_query_preset(preset: dict[str, Any]) -> dict[str, Any]:
    public_keys = {"id", "name", "description", "columns", "pdql", "search", "defaults", "kind"}
    return {key: value for key, value in preset.items() if key in public_keys}


def list_asset_card_query_presets() -> list[dict[str, Any]]:
    return [
        public_asset_card_query_preset(preset)
        for preset in ASSET_CARD_QUERY_PRESETS.values()
    ]
