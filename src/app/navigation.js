export const defaultRoutePath = "/vm";

export const navigationGroups = [
  { id: "primary", label: "Основное" },
  { id: "tools", label: "Инструменты" },
  { id: "admin", label: "Администрирование" },
];

export const workflowSteps = [
  { id: "overview", label: "Обзор", hint: "VM-контур", path: "/vm", routes: ["vm"] },
  { id: "scan", label: "Сканирование", hint: "Запуск и контроль", path: "/tasks", routes: ["connection", "tasks", "asset-groups", "operations"] },
  { id: "review", label: "Находки", hint: "Риск и активы", path: "/vulnerabilities", routes: ["vulnerabilities", "asset-cards", "passports", "asset-query"] },
  { id: "fix", label: "Устранение", hint: "SLA и проверка", path: "/remediation", routes: ["remediation"] },
  { id: "report", label: "Отчётность", hint: "CSV и сценарии", path: "/export", routes: ["export", "automations"] },
];

export const routes = [
  {
    id: "vm", requiredPermission: "operations.read", group: "primary", icon: "◆", path: "/vm",
    label: "VM Management", title: "VM Management",
    description: "Единый цикл сканирования, приоритизации, устранения и подтверждения результата.",
  },
  {
    id: "users",
    requiredAnyPermission: ["security.users.read", "security.roles.read", "security.audit.read"],
    group: "admin",
    icon: "◎",
    path: "/users",
    label: "Пользователи",
    title: "Пользователи и роли",
    description: "Управление доступом к приложению, ролями и состоянием учётных записей.",
  },
  {
    id: "connection",
    requiredPermission: "connection.read",
    group: "tools",
    icon: "⌁",
    path: "/connection",
    label: "Подключение",
    title: "Подключение к MP VM",
    description:
      "Настройте адрес MP VM и проверьте авторизацию для остальных разделов.",
  },
  {
    id: "tasks",
    requiredPermission: "tasks.read",
    group: "tools",
    icon: "◎",
    path: "/tasks",
    label: "Задачи",
    title: "Задачи сканирования",
    description: "Создание, запуск и контроль задач сканирования в MP VM.",
  },
  {
    id: "asset-groups",
    requiredPermission: "asset_groups.read",
    group: "tools",
    icon: "▤",
    path: "/asset-groups",
    label: "Группы активов",
    title: "Группы активов MP VM",
    description: "Просмотр и управление иерархией групп активов в MP VM.",
  },
  {
    id: "operations",
    requiredPermission: "operations.read",
    group: "tools",
    icon: "◔",
    path: "/operations",
    label: "Операции",
    title: "Центр операций",
    description:
      "Единое состояние фоновых заданий, повторов, отмены и диагностики.",
  },
  {
    id: "export",
    requiredPermission: "imports_exports.read",
    group: "primary",
    icon: "⇩",
    path: "/export",
    label: "PDQL экспорт",
    title: "PDQL экспорт",
    description:
      "Выгрузка и сохранение результатов PDQL-запросов в локальную БД.",
  },
  {
    id: "vulnerabilities",
    requiredPermission: "assets.read",
    group: "primary",
    icon: "◈",
    path: "/vulnerabilities",
    label: "Уязвимости",
    title: "Обзор уязвимостей",
    description:
      "Общая статистика, критичность и переход от уязвимости к затронутым хостам.",
  },
  {
    id: "remediation", requiredPermission: "remediation.read", group: "primary", icon: "✓", path: "/remediation", label: "Устранение",
    title: "Устранение уязвимостей", description: "Рабочая очередь, ответственные, SLA и подтверждение устранения.",
  },
  {
    id: "asset-cards",
    requiredPermission: "asset_cards.read",
    group: "tools",
    icon: "▦",
    path: "/asset-cards",
    label: "Карточки активов",
    title: "Карточки активов",
    description:
      "Поиск, построение и сохранение детальных карточек активов в локальную БД.",
  },
  {
    id: "automations",
    requiredPermission: "automations.read",
    group: "tools",
    icon: "⎇",
    path: "/automations",
    label: "Автоматизация",
    title: "Автоматизация",
    description:
      "Последовательные сценарии, расписания, история запусков и уведомления.",
  },
  {
    id: "asset-query",
    requiredPermission: "asset_cards.read",
    group: "tools",
    icon: "⌕",
    path: "/asset-query",
    label: "Выборки активов",
    title: "Выборки по карточкам активов",
    description:
      "Локальные выборки по firewall и другим индексированным полям карточек активов.",
  },
  {
    id: "passports",
    requiredPermission: "passports.read",
    group: "tools",
    icon: "◇",
    path: "/passports",
    label: "Паспорта",
    title: "Паспорта уязвимостей",
    description:
      "Поиск паспортов уязвимостей и просмотр подробной информации из MP VM.",
  },
];

const legacyRouteRedirects = new Map([["/assets", "/asset-cards"]]);

export function routeById(id) {
  return routes.find((route) => route.id === id) || null;
}

export function routeByPath(pathname) {
  const normalized = normalizeRoutePath(pathname);
  return routes.find((route) => route.path === normalized) || null;
}

export function normalizeRoutePath(pathname) {
  const value = String(pathname || "")
    .split("?")[0]
    .split("#")[0];
  if (!value || value === "/") return defaultRoutePath;
  const normalized = value.startsWith("/") ? value : "/" + value;
  const cleanPath = normalized.replace(/\/+$/, "") || defaultRoutePath;
  return legacyRouteRedirects.get(cleanPath) || cleanPath;
}
