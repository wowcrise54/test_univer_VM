"""Recommended task presets for Windows and Linux engineers.

The catalogue follows the MaxPatrol VM 28.0 help: «Рекомендации по использованию профилей»,
«Создание задач на аудит», «Определение ОС модулем Pentest», «Модуль Audit», «Модуль Pentest»
and «Создание регулярных задач». MP VM object IDs differ between stands, so a template names
standard MP VM profiles and is resolved against the live lookups when a draft is requested.
"""

from __future__ import annotations

import builtins
from typing import Any

DOCS_URL = "https://help.ptsecurity.com/ru-RU/projects/vm/28.0/help/7723547531"

# os_family -> (system role key, display name) of the team that receives the preset.
TEAM_ROLES = {
    "windows": ("engineer_windows", "Инженер Windows"),
    "linux": ("engineer_linux", "Инженер Linux"),
}

_WINDOWS_ADMIN = "Доменная учётная запись из группы локальных администраторов (WMI/RPC)."
_LINUX_SUDO = ("SSH-учётная запись с sudo: ALL=(ALL) ALL или sudo-обёртки из audit_sudo_wrappers.zip. "
               "Ключи — только в формате OpenSSH.")
_NO_CREDENTIAL = "Не нужна: сканирование методом чёрного ящика."
_BLACK_BOX_NOTE = "Проверка подключения MP VM работает только для задач аудита, поэтому precheck выключен."

PRESET_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "template_id": "windows-audit",
        "os_family": "windows",
        "name": "Windows. Полный аудит",
        "description": "Полный аудит Windows: конфигурация ОС, установленное ПО и уязвимости. "
                       "Для ключевых серверов, до 15 минут на узел.",
        "purpose": "Полная конфигурация ОС и ПО для поиска уязвимостей и проверки политик на ключевых серверах.",
        "module": "Audit",
        "profile_names": ["Windows Audit"],
        "credential": "required",
        "credential_hint": _WINDOWS_ADMIN,
        "name_prefix": "[Audit][WIN]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 3,
        "max_active_tasks": 2,
        "notes": [
            "До 15 минут на актив; подхватывает обновления экспертизы audit_expertise_extension.",
            "Коллектору на Linux нужен FQDN цели; подключение по FQDN нужно и для Kerberos.",
            "Адаптивный контроль аномалий Kaspersky Endpoint Security блокирует WMI: добавьте учётную запись "
            "в исключения правила «Запуск Windows PowerShell с помощью WMI».",
        ],
    },
    {
        "template_id": "windows-vulnerabilities",
        "os_family": "windows",
        "name": "Windows. Поиск уязвимостей",
        "description": "Поиск уязвимостей Windows без полного аудита конфигурации. "
                       "Для регулярных проверок серверов и рабочих станций.",
        "purpose": "Регулярный поиск уязвимостей: собирает только сведения об ОС и приложениях.",
        "module": "Audit",
        "profile_names": ["Windows Audit Vulnerabilities Discovery"],
        "credential": "required",
        "credential_hint": _WINDOWS_ADMIN,
        "name_prefix": "[VM][WIN]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 5,
        "max_active_tasks": 3,
        "notes": [
            "По данным PT на 16% быстрее Windows Audit, результаты занимают на 30% меньше места.",
            "Не предназначен для узлов АСУ ТП.",
        ],
    },
    {
        "template_id": "windows-updates",
        "os_family": "windows",
        "name": "Windows. Контроль обновлений",
        "description": "Быстрая проверка установленных обновлений Windows, до 2 минут на узел. "
                       "Для рабочих станций и некритичных серверов.",
        "purpose": "Контроль SLA на установку обновлений на массе некритичных узлов.",
        "module": "Audit",
        "profile_names": ["Windows Updates Discovery"],
        "credential": "required",
        "credential_hint": _WINDOWS_ADMIN,
        "name_prefix": "[SLA][WIN]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 10,
        "max_active_tasks": 3,
        "notes": ["Собирает ограниченный объём данных: для полной картины используйте полный аудит."],
    },
    {
        "template_id": "windows-domain-controller",
        "os_family": "windows",
        "name": "Windows. Аудит Active Directory",
        "description": "Аудит контроллера домена и каталога Active Directory. "
                       "Запускайте по одному контроллеру: нагрузка на AD высокая.",
        "purpose": "Сбор данных о ресурсах службы каталогов и аудит Windows на контроллере домена (LDAP и RPC).",
        "module": "Audit",
        "profile_names": ["Windows DC Audit", "Microsoft Active Directory Audit"],
        "credential": "required",
        "credential_hint": "Доменная учётная запись с правами администратора на контроллере домена.",
        "name_prefix": "[AD][WIN]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 1,
        "max_active_tasks": 1,
        "notes": [
            "Один контроллер в сети: Windows DC Audit. Несколько: Microsoft Active Directory Audit на одном-двух "
            "контроллерах, остальные — пресетом полного аудита Windows.",
            "Разрешите в пресете группу только с выбранными контроллерами домена.",
            "Для высоконагруженного AD PT рекомендует коллектор на Linux: нужен FQDN, NTLM для LDAP не поддерживается.",
            "Чтобы увидеть результаты, создайте динамическую группу активов с условием ActiveDirectory.",
        ],
    },
    {
        "template_id": "windows-services-discovery",
        "os_family": "windows",
        "name": "Windows. Определение ОС и служб",
        "description": "Определение Windows, открытых портов и служб без учётной записи. "
                       "Используйте для новых узлов перед аудитом.",
        "purpose": "Разложить найденные HostDiscovery активы по группам: находит узлы Windows и их службы.",
        "module": "Pentest",
        "profile_names": ["Windows Services Discovery"],
        "credential": "none",
        "credential_hint": _NO_CREDENTIAL,
        "name_prefix": "[Discovery][WIN]",
        "precheck_enabled": False,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 5,
        "max_active_tasks": 2,
        "notes": [
            _BLACK_BOX_NOTE,
            "PT рекомендует сканировать им группу «Активы вне групп», затем собрать динамическую группу WindowsHost.",
        ],
    },
    {
        "template_id": "windows-safe-pentest",
        "os_family": "windows",
        "name": "Windows. Безопасный пентест",
        "description": "Поиск уязвимостей сетевых служб без учётной записи, "
                       "без подбора паролей и DoS-проверок.",
        "purpose": "Взгляд атакующего из сети: уязвимости служб на популярных портах с безопасными проверками.",
        "module": "Pentest",
        "profile_names": ["Safe PenTest"],
        "credential": "none",
        "credential_hint": _NO_CREDENTIAL,
        "name_prefix": "[Pentest][WIN]",
        "precheck_enabled": False,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 3,
        "max_active_tasks": 1,
        "notes": [
            _BLACK_BOX_NOTE,
            "Сканирует 4741 популярный порт TCP и все поддерживаемые UDP-порты.",
            "Отдельные проверки пробуют стандартные логины (root, admin): согласуйте политику блокировок с ИБ.",
        ],
    },
    {
        "template_id": "linux-audit",
        "os_family": "linux",
        "name": "Linux. Полный аудит",
        "description": "Полный аудит Linux по SSH с повышением привилегий через sudo: конфигурация, ПО и уязвимости. "
                       "До 5 минут на узел.",
        "purpose": "Полная конфигурация ОС семейства Unix и установленного ПО для поиска уязвимостей и политик.",
        "module": "Audit",
        "profile_names": ["Unix SSH Audit"],
        "credential": "required",
        "credential_hint": _LINUX_SUDO,
        "name_prefix": "[Audit][LNX]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 3,
        "max_active_tasks": 2,
        "notes": [
            "До 5 минут на актив; подхватывает обновления экспертизы audit_expertise_extension.",
            "В 28.0 собирает конфигурацию sudo, файлы с SUID/SGID и SSH-ключи.",
            "Узлы с ядром Linux 2.6.38 и ниже или dmidecode 2.8 и ниже не будут добавлены.",
            "Astra Linux SE: настройте уровень целостности учётной записи; «Альт»: политику control для sudo.",
        ],
    },
    {
        "template_id": "linux-vulnerabilities",
        "os_family": "linux",
        "name": "Linux. Поиск уязвимостей",
        "description": "Поиск уязвимостей Linux без полного аудита конфигурации. "
                       "Быстрее и легче для регулярных проверок.",
        "purpose": "Регулярный поиск уязвимостей: собирает только сведения об ОС и приложениях.",
        "module": "Audit",
        "profile_names": ["Unix Audit Vulnerabilities Discovery"],
        "credential": "required",
        "credential_hint": _LINUX_SUDO,
        "name_prefix": "[VM][LNX]",
        "precheck_enabled": True,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 5,
        "max_active_tasks": 3,
        "notes": [
            "По данным PT на 30% быстрее Unix SSH Audit, результаты в 10 раз компактнее, "
            "пиковое потребление памяти ниже на 29–45%.",
            "Не предназначен для узлов АСУ ТП.",
        ],
    },
    {
        "template_id": "linux-services-discovery",
        "os_family": "linux",
        "name": "Linux. Инвентаризация служб",
        "description": "Открытые порты и работающие службы без учётной записи. Уязвимости не ищет.",
        "purpose": "Быстрая инвентаризация сетевых служб на известных портах перед аудитом или для узлов без учётки.",
        "module": "Pentest",
        "profile_names": ["Service Discovery on well-known ports", "Service Discovery"],
        "credential": "none",
        "credential_hint": _NO_CREDENTIAL,
        "name_prefix": "[Discovery][LNX]",
        "precheck_enabled": False,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 5,
        "max_active_tasks": 2,
        "notes": [
            _BLACK_BOX_NOTE,
            "Не проверяет UDP и сканирует ограниченный список портов TCP. Полный охват — профиль "
            "Service Discovery (все 65535 TCP и UDP), но он заметно дольше.",
        ],
    },
    {
        "template_id": "linux-safe-pentest",
        "os_family": "linux",
        "name": "Linux. Безопасный пентест",
        "description": "Поиск уязвимостей сетевых служб без учётной записи, "
                       "без подбора паролей и DoS-проверок.",
        "purpose": "Взгляд атакующего из сети: уязвимости служб на популярных портах с безопасными проверками.",
        "module": "Pentest",
        "profile_names": ["Safe PenTest"],
        "credential": "none",
        "credential_hint": _NO_CREDENTIAL,
        "name_prefix": "[Pentest][LNX]",
        "precheck_enabled": False,
        "host_discovery_enabled": False,
        "is_fqdn_priority": True,
        "max_groups_per_task": 3,
        "max_active_tasks": 1,
        "notes": [
            _BLACK_BOX_NOTE,
            "Сканирует 4741 популярный порт TCP и все поддерживаемые UDP-порты.",
            "Отдельные проверки пробуют стандартные логины (root, admin): согласуйте политику блокировок с ИБ.",
        ],
    },
)

# Standard profiles that should not be handed to engineers as a preset.
AVOID_PROFILES: tuple[dict[str, str], ...] = (
    {"profile": "Full PenTest",
     "reason": "С 28.0 сканирует все 65535 портов TCP и все UDP-порты: задача может идти очень долго."},
    {"profile": "Unsafe PenTest", "reason": "DoS-проверки могут сделать службы и узлы недоступными."},
    {"profile": "Bruteforce PenTest", "reason": "Подбор паролей может заблокировать учётные записи."},
    {"profile": "HostDiscovery",
     "reason": "Ищет новые узлы по подсетям, а пресет ограничивает цели известными группами активов."},
)

_TEMPLATES_BY_ID = {template["template_id"]: template for template in PRESET_TEMPLATES}


def template_catalogue() -> dict[str, Any]:
    rows = [{**template, "role_label": TEAM_ROLES[template["os_family"]][1]} for template in PRESET_TEMPLATES]
    return {"rows": rows, "avoid": [dict(item) for item in AVOID_PROFILES], "docs_url": DOCS_URL}


def find_template(template_id: str) -> dict[str, Any]:
    template = _TEMPLATES_BY_ID.get(template_id)
    if not template:
        raise LookupError("Task preset template not found.")
    return template


def find_profile(
    profiles: builtins.list[dict[str, Any]], names: builtins.list[str],
) -> tuple[str, str] | None:
    """Return ``(id, name)`` of the first standard profile from ``names`` that MP VM knows, ignoring case."""
    by_name: dict[str, str] = {}
    for profile in profiles:
        name = str(profile.get("name") or "").strip().casefold()
        if name and profile.get("id"):
            by_name.setdefault(name, str(profile["id"]))
    for name in names:
        if name.casefold() in by_name:
            return by_name[name.casefold()], name
    return None


def build_template_draft(
    template: dict[str, Any], lookups: dict[str, Any], role_ids: builtins.list[int],
) -> tuple[dict[str, Any], builtins.list[str]]:
    """Build an unsaved preset draft for the admin form and the warnings about unresolved values."""
    warnings: builtins.list[str] = []
    names = template["profile_names"]
    profile = find_profile(lookups.get("scanner_profiles") or [], names)
    if not profile:
        listed = " или ".join(f"«{name}»" for name in names)
        warnings.append(f"В MP VM не найден стандартный профиль {listed}. Выберите профиль модуля "
                        f"{template['module']} вручную.")
    elif profile[1] != names[0]:
        warnings.append(f"Профиль «{names[0]}» не найден в MP VM, подставлен «{profile[1]}».")
    scopes = lookups.get("scopes") or []
    if not role_ids:
        warnings.append(f"Роль «{TEAM_ROLES[template['os_family']][1]}» не найдена. Отметьте роли вручную.")
    draft = {
        "name": template["name"],
        "description": template["description"],
        "os_family": template["os_family"],
        "scope_id": str(scopes[0]["id"]) if len(scopes) == 1 else "",
        "profile_id": profile[0] if profile else "",
        "credential_id": None,
        "agent_ids": [],
        "host_discovery_enabled": template["host_discovery_enabled"],
        "host_discovery_profile_id": None,
        "is_fqdn_priority": template["is_fqdn_priority"],
        "trigger_parameters": None,
        "denied_scan_settings": None,
        "start_options": {"precheck_enabled": template["precheck_enabled"], "precheck_profile_id": None},
        "allowed_asset_groups": [],
        "allowed_targets": [],
        "max_groups_per_task": template["max_groups_per_task"],
        "max_active_tasks": template["max_active_tasks"],
        "name_prefix": template["name_prefix"],
        "role_ids": role_ids,
        "template_id": template["template_id"],
    }
    return draft, warnings
