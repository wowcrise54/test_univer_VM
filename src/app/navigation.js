export const defaultRoutePath = "/connection";

export const routes = [
  {
    id: "connection",
    path: "/connection",
    label: "Подключение",
    title: "Подключение к MP VM",
    description: "Настройте адрес MP VM и проверьте авторизацию для остальных разделов.",
  },
  {
    id: "tasks",
    path: "/tasks",
    label: "Задачи",
    title: "Задачи сканирования",
    description: "Создание, запуск и контроль задач сканирования в MP VM.",
  },
  {
    id: "operations",
    path: "/operations",
    label: "Операции",
    title: "Центр операций",
    description: "Единое состояние фоновых заданий, повторов, отмены и диагностики.",
  },
  {
    id: "export",
    path: "/export",
    label: "PDQL экспорт",
    title: "PDQL экспорт",
    description: "Выгрузка и сохранение результатов PDQL-запросов в локальную БД.",
  },
  {
    id: "asset-cards",
    path: "/asset-cards",
    label: "Карточки активов",
    title: "Карточки активов",
    description: "Поиск, построение и сохранение детальных карточек активов в локальную БД.",
  },
  {
    id: "passports",
    path: "/passports",
    label: "Паспорта",
    title: "Паспорта уязвимостей",
    description: "Поиск паспортов уязвимостей и просмотр подробной информации из MP VM.",
  },
  {
    id: "assets",
    path: "/assets",
    label: "Активы",
    title: "Активы и уязвимости",
    description: "Локальный снимок активов, установленного ПО и найденных уязвимостей.",
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
  const value = String(pathname || "").split("?")[0].split("#")[0];
  if (!value || value === "/") return defaultRoutePath;
  const normalized = value.startsWith("/") ? value : "/" + value;
  return normalized.replace(/\/+$/, "") || defaultRoutePath;
}
