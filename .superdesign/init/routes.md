# Routes

Routing is config-based and implemented with the browser History API. All feature pages render inside `AppShell` from `src/app/App.jsx`, which supplies `Sidebar`, `Topbar`, `WorkflowRail`, system status, and alerts. `AuthGate` wraps the shell; unauthenticated users see the login surface instead. The bare `/` path normalizes to `/connection`.

| URL | Route id | Page component | Layout | Purpose |
| --- | --- | --- | --- | --- |
| `/vm` | `vm` | `src/pages/VmManagementPage.jsx` | AuthGate → AppShell | Unified scan, prioritization, remediation, and verification overview. |
| `/users` | `users` | `src/features/auth/UsersPage.jsx` | AuthGate → AppShell | User, role, permission, and audit administration. |
| `/connection` | `connection` | `src/pages/ConnectionPage.jsx` | AuthGate → AppShell | MP VM endpoint and authentication setup; default route. |
| `/tasks` | `tasks` | `src/pages/TasksPage.jsx` | AuthGate → AppShell | Create, start, stop, inspect, and remove scanner tasks. |
| `/operations` | `operations` | `src/pages/OperationsPage.jsx` | AuthGate → AppShell | Background-operation health, retries, cancellation, and diagnostics. |
| `/vulnerabilities` | `vulnerabilities` | `src/pages/VulnerabilitiesPage.jsx` | AuthGate → AppShell | Vulnerability KPIs, trends, severity, top risks, tables, and host drill-down. |
| `/remediation` | `remediation` | `src/pages/RemediationPage.jsx` | AuthGate → AppShell | Remediation queue, ownership, deadlines, SLA policy, risk decisions, and verification. |
| `/coverage` | `coverage` | `src/pages/CoveragePage.jsx` | AuthGate → AppShell | Asset-card freshness, coverage gaps, and refresh outcomes. |
| `/asset-cards` | `asset-cards` | `src/pages/AssetCardsPage.jsx` | AuthGate → AppShell | Search, build, inspect, refresh, and delete local asset cards. |
| `/asset-query` | `asset-query` | `src/pages/AssetQueryPage.jsx` | AuthGate → AppShell | Nested AND/OR query builder over indexed asset-card fields with CSV export. |
| `/passports` | `passports` | `src/pages/PassportsPage.jsx` | AuthGate → AppShell | Query vulnerability passports, load details, and inspect passport records. |
| `/assets` | `assets` | `src/pages/AssetsPage.jsx` | AuthGate → AppShell | Local asset/software/vulnerability snapshot with filtering and sorting. |
| `/export` | `export` | `src/pages/ExportPage.jsx` | AuthGate → AppShell | Run PDQL exports and persist results locally. |
| `/automations` | `automations` | `src/pages/AutomationsPage.jsx` | AuthGate → AppShell | Build step-based automations, schedules, run history, and notifications. |

## `src/app/navigation.js`

```js
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
  { id: "review", label: "Находки", hint: "Риск и активы", path: "/vulnerabilities", routes: ["vulnerabilities", "coverage", "asset-cards", "assets", "passports", "asset-query"] },
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
    id: "coverage", requiredPermission: "assets.read", group: "findings", icon: "◉", path: "/coverage", label: "Покрытие",
    title: "Покрытие сканированием", description: "Свежесть и полнота карточек активов и результаты обновлений.",
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

```

## `src/app/router.js`

```js
import { useCallback, useEffect, useMemo, useState } from "react";
import { recordFrontendEvent } from "../diagnostics.js";
import { defaultRoutePath, normalizeRoutePath, routeById, routeByPath } from "./navigation.js";

function routePathFromHash(hash) {
  const id = String(hash || "").replace(/^#/, "");
  return routeById(id)?.path || null;
}

function currentBrowserPath() {
  if (typeof window === "undefined") return defaultRoutePath;
  const legacyPath = window.location.pathname === "/" ? routePathFromHash(window.location.hash) : null;
  return normalizeRoutePath(legacyPath || window.location.pathname);
}

export function useRouter() {
  const [path, setPath] = useState(currentBrowserPath);

  useEffect(() => {
    const initialPath = currentBrowserPath();
    if (typeof window !== "undefined" && window.location.pathname !== initialPath) {
      window.history.replaceState({}, "", initialPath);
    }
    setPath(initialPath);

    const handlePopState = () => {
      const nextPath = currentBrowserPath();
      setPath((currentPath) => {
        recordFrontendEvent("ui.navigation", { from: currentPath, to: nextPath, navigation_type: "popstate" });
        return nextPath;
      });
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = useCallback((targetPath) => {
    const nextPath = normalizeRoutePath(targetPath);
    if (nextPath === path) return;
    recordFrontendEvent("ui.navigation", { from: path, to: nextPath, navigation_type: "push" });
    window.history.pushState({}, "", nextPath);
    setPath(nextPath);
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [path]);

  const route = useMemo(() => routeByPath(path), [path]);
  return { navigate, path, route };
}

```

