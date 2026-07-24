export const defaultRoutePath = "/connection";

export const navigationGroups = [
  { id: "overview", label: "Обзор" },
  { id: "scan", label: "Сканирования" },
  { id: "findings", label: "Находки" },
  { id: "remediation", label: "Устранение" },
  { id: "report", label: "Отчётность" },
  { id: "admin", label: "Администрирование" },
];

export const workflowSteps = [
  { id: "overview", label: "Обзор", hint: "VM-контур", path: "/vm", routes: ["vm"] },
  { id: "scan", label: "Сканирование", hint: "Запуск и контроль", path: "/tasks", routes: ["connection", "tasks", "operations"] },
  { id: "review", label: "Находки", hint: "Риск и активы", path: "/vulnerabilities", routes: ["vulnerabilities", "asset-cards", "assets", "passports", "asset-query"] },
  { id: "fix", label: "Устранение", hint: "SLA и проверка", path: "/remediation", routes: ["remediation"] },
  { id: "report", label: "Отчётность", hint: "CSV и сценарии", path: "/export", routes: ["export", "automations"] },
];

export const routes = [
  {
    id: "vm", requiredPermission: "operations.read", group: "overview", icon: "◆", path: "/vm",
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
    group: "scan",
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
    group: "scan",
    icon: "◎",
    path: "/tasks",
    label: "Задачи",
    title: "Задачи сканирования",
    description: "Создание, запуск и контроль задач сканирования в MP VM.",
  },
  {
    id: "operations",
    requiredPermission: "operations.read",
    group: "scan",
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
    group: "report",
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
    group: "findings",
    icon: "◈",
    path: "/vulnerabilities",
    label: "Уязвимости",
    title: "Обзор уязвимостей",
    description:
      "Общая статистика, критичность и переход от уязвимости к затронутым хостам.",
  },
  {
    id: "remediation", requiredPermission: "remediation.read", group: "remediation", icon: "✓", path: "/remediation", label: "Устранение",
    title: "Устранение уязвимостей", description: "Рабочая очередь, ответственные, SLA и подтверждение устранения.",
  },
  {
    id: "asset-cards",
    requiredPermission: "asset_cards.read",
    group: "findings",
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
    group: "report",
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
    group: "findings",
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
    group: "findings",
    icon: "◇",
    path: "/passports",
    label: "Паспорта",
    title: "Паспорта уязвимостей",
    description:
      "Поиск паспортов уязвимостей и просмотр подробной информации из MP VM.",
  },
  {
    id: "assets",
    requiredPermission: "assets.read",
    group: "findings",
    icon: "◫",
    path: "/assets",
    label: "Активы",
    title: "Активы и уязвимости",
    description:
      "Локальный снимок активов, установленного ПО и найденных уязвимостей.",
  },
];

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
  return normalized.replace(/\/+$/, "") || defaultRoutePath;
}
