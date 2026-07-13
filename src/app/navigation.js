export const defaultRoutePath = "/connection";

export const navigationGroups = [
  { id: "work", label: "Рабочий процесс" },
  { id: "data", label: "Данные и анализ" },
  { id: "manage", label: "Управление" },
];

export const workflowSteps = [
  { id: "connect", label: "Подключение", hint: "Доступ к MP VM", path: "/connection", routes: ["connection"] },
  { id: "scan", label: "Сканирование", hint: "Запуск и контроль", path: "/tasks", routes: ["tasks", "operations"] },
  { id: "review", label: "Результаты", hint: "Карточки и уязвимости", path: "/vulnerabilities", routes: ["vulnerabilities", "remediation", "coverage", "asset-cards", "assets", "passports", "asset-query"] },
  { id: "report", label: "Отчётность", hint: "CSV и сценарии", path: "/export", routes: ["export", "automations"] },
];

export const routes = [
  {
    id: "users",
    requiredAnyPermission: ["security.users.read", "security.roles.read", "security.audit.read"],
    group: "manage",
    icon: "◎",
    path: "/users",
    label: "Пользователи",
    title: "Пользователи и роли",
    description: "Управление доступом к приложению, ролями и состоянием учётных записей.",
  },
  {
    id: "connection",
    requiredPermission: "connection.read",
    group: "work",
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
    group: "work",
    icon: "◎",
    path: "/tasks",
    label: "Задачи",
    title: "Задачи сканирования",
    description: "Создание, запуск и контроль задач сканирования в MP VM.",
  },
  {
    id: "operations",
    requiredPermission: "operations.read",
    group: "work",
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
    group: "manage",
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
    group: "data",
    icon: "◈",
    path: "/vulnerabilities",
    label: "Уязвимости",
    title: "Обзор уязвимостей",
    description:
      "Общая статистика, критичность и переход от уязвимости к затронутым хостам.",
  },
  {
    id: "remediation", requiredPermission: "remediation.read", group: "work", icon: "✓", path: "/remediation", label: "Устранение",
    title: "Устранение уязвимостей", description: "Рабочая очередь, ответственные, SLA и подтверждение устранения.",
  },
  {
    id: "coverage", requiredPermission: "assets.read", group: "data", icon: "◉", path: "/coverage", label: "Покрытие",
    title: "Покрытие сканированием", description: "Свежесть и полнота карточек активов и результаты обновлений.",
  },
  {
    id: "asset-cards",
    requiredPermission: "asset_cards.read",
    group: "data",
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
    group: "manage",
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
    group: "data",
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
    group: "data",
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
    group: "data",
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
