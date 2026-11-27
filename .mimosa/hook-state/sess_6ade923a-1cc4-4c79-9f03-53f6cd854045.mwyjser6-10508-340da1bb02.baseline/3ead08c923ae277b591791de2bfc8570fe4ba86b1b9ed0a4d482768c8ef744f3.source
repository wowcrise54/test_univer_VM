export const defaultRoutePath = "/vm";

export const navigationGroups = [
  { id: "primary", label: "Основное" },
  { id: "tools", label: "Инструменты" },
  { id: "admin", label: "Администрирование" },
];

export const routes = [
  {
    id: "vm",
    requiredPermission: "operations.read",
    group: "primary",
    path: "/vm",
    label: "Обзор",
    title: "Обзор",
  },
  {
    id: "scans",
    requiredPermission: "tasks.team",
    group: "primary",
    path: "/scans",
    label: "Сканирование",
    title: "Сканирование",
  },
  {
    id: "task-presets",
    requiredPermission: "task_presets.manage",
    group: "admin",
    path: "/task-presets",
    label: "Пресеты задач",
    title: "Пресеты задач",
  },
  {
    id: "users",
    requiredAnyPermission: [
      "security.users.read",
      "security.roles.read",
      "security.audit.read",
    ],
    group: "admin",
    path: "/users",
    label: "Пользователи",
    title: "Пользователи",
  },
  {
    id: "connection",
    requiredPermission: "connection.read",
    group: "tools",
    path: "/connection",
    label: "Подключение",
    title: "Подключение",
  },
  {
    id: "tasks",
    requiredPermission: "tasks.read",
    group: "tools",
    path: "/tasks",
    label: "Задачи",
    title: "Задачи",
  },
  {
    id: "asset-groups",
    requiredPermission: "asset_groups.read",
    group: "tools",
    path: "/asset-groups",
    label: "Группы активов",
    title: "Группы активов",
  },
  {
    id: "operations",
    requiredPermission: "operations.read",
    group: "tools",
    path: "/operations",
    label: "Операции",
    title: "Операции",
  },
  {
    id: "export",
    requiredPermission: "imports_exports.read",
    group: "primary",
    path: "/export",
    label: "Отчётность",
    title: "Отчётность",
  },
  {
    id: "dashboards",
    requiredPermission: "assets.read",
    group: "primary",
    path: "/dashboards",
    label: "Дашборды",
    title: "Дашборды",
  },
  {
    id: "vulnerabilities",
    requiredPermission: "assets.read",
    group: "primary",
    path: "/vulnerabilities",
    label: "Уязвимости",
    title: "Уязвимости",
  },
  {
    id: "remediation",
    requiredPermission: "remediation.read",
    group: "primary",
    path: "/remediation",
    label: "Устранение",
    title: "Устранение",
  },
  {
    id: "asset-cards",
    requiredPermission: "asset_cards.read",
    group: "tools",
    path: "/asset-cards",
    label: "Карточки активов",
    title: "Карточки активов",
  },
  {
    id: "automations",
    requiredPermission: "automations.read",
    group: "tools",
    path: "/automations",
    label: "Автоматизация",
    title: "Автоматизация",
  },
  {
    id: "asset-query",
    requiredPermission: "asset_cards.read",
    group: "tools",
    path: "/asset-query",
    label: "Выборки активов",
    title: "Выборки активов",
  },
  {
    id: "passports",
    requiredPermission: "passports.read",
    group: "tools",
    path: "/passports",
    label: "Паспорта",
    title: "Паспорта",
  },
];

/**
 * Engineers without the full task workspace start on the preset page instead
 * of the operator overview.
 */
export function landingPathForUser(user) {
  const permissions = new Set(user?.permissions || []);
  if (permissions.has("tasks.team") && !permissions.has("tasks.read")) {
    return "/scans";
  }
  return defaultRoutePath;
}

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
