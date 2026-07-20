# Shared layouts

## `src/main.jsx`

React entry point; installs diagnostics, imports the global stylesheet entry, and mounts providers plus the application.

```jsx
import { createRoot } from "react-dom/client";
import { App } from "./app/App.jsx";
import { AppProviders } from "./app/providers.jsx";
import { installGlobalDiagnostics } from "./diagnostics.js";
import "./styles/index.css";

installGlobalDiagnostics();

createRoot(document.getElementById("root")).render(
  <AppProviders>
    <App />
  </AppProviders>,
);

```

## `src/app/App.jsx`

Authenticated application shell; composes sidebar, top bar, workflow rail, system status, alerts, and the active route page.

```jsx
import { AssetCardsPage } from "../pages/AssetCardsPage.jsx";
import { AssetQueryPage } from "../pages/AssetQueryPage.jsx";
import { AssetsPage } from "../pages/AssetsPage.jsx";
import { ConnectionPage } from "../pages/ConnectionPage.jsx";
import { ExportPage } from "../pages/ExportPage.jsx";
import { PassportsPage } from "../pages/PassportsPage.jsx";
import { OperationsPage } from "../pages/OperationsPage.jsx";
import { AutomationsPage } from "../pages/AutomationsPage.jsx";
import { TasksPage } from "../pages/TasksPage.jsx";
import { VulnerabilitiesPage } from "../pages/VulnerabilitiesPage.jsx";
import { RemediationPage } from "../pages/RemediationPage.jsx";
import { CoveragePage } from "../pages/CoveragePage.jsx";
import {
  AlertStack,
  Sidebar,
  SystemBanner,
  Topbar,
  WorkflowRail,
} from "./layout.jsx";
import { AppDataProvider, useAppDataContext } from "./AppDataContext.jsx";
import { useRouter } from "./router.js";
import { AuthGate } from "../features/auth/AuthGate.jsx";
import { UsersPage } from "../features/auth/UsersPage.jsx";
import { VmManagementPage } from "../pages/VmManagementPage.jsx";

export function App() {
  return <AuthGate>{(auth) => <AuthenticatedApp auth={auth} />}</AuthGate>;
}

function AuthenticatedApp({ auth }) {
  const { navigate, path, route } = useRouter();
  return (
    <AppDataProvider routeId={route?.id}>
      <AppShell navigate={navigate} path={path} route={route} auth={auth} />
    </AppDataProvider>
  );
}

function AppShell({ navigate, path, route, auth }) {
  const appData = useAppDataContext();

  return (
    <div className="app-shell">
      <Sidebar
        session={appData.session}
        systemStatus={appData.systemStatus}
        activeOperations={
          appData.operationSummary?.active ??
          appData.operations.filter((item) =>
            ["queued", "running", "cancelling", "recovering"].includes(
              item.status,
            ),
          ).length
        }
        activePath={path}
        onNavigate={navigate}
        currentUser={auth.user}
      />
      <main className="workspace">
        <Topbar session={appData.session} route={route} onNavigate={navigate} currentUser={auth.user} onLogout={auth.logout} />
        <WorkflowRail activeRouteId={route?.id} onNavigate={navigate} />
        <SystemBanner
          status={appData.systemStatus}
          stale={appData.operationsStale}
          onRetry={appData.refreshSystemStatus}
          onNavigate={navigate}
        />
        <AlertStack alerts={appData.alerts} />
        <ActivePage routeId={route?.id} onNavigate={navigate} currentUser={auth.user} reauthenticate={auth.reauthenticate} {...appData} />
      </main>
    </div>
  );
}

function ActivePage({ routeId, ...props }) {
  if (routeId === "vm") {
    return <VmManagementPage session={props.session} currentUser={props.currentUser} showAlert={props.showAlert} onNavigate={props.onNavigate} />;
  }
  if (routeId === "users") {
    return <UsersPage currentUser={props.currentUser} reauthenticate={props.reauthenticate} showAlert={props.showAlert} />;
  }
  if (routeId === "connection") {
    return (
      <ConnectionPage
        connectionDraft={props.connectionDraft}
        defaults={props.defaults}
        session={props.session}
        setSession={props.setSession}
        lookups={props.lookups}
        setLookups={props.setLookups}
        setConnectionDraft={props.setConnectionDraft}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
        onNavigate={props.onNavigate}
      />
    );
  }
  if (routeId === "tasks") {
    return (
      <TasksPage
        defaults={props.defaults}
        lookups={props.lookups}
        tasks={props.tasks}
        loading={props.tasksLoading}
        error={props.tasksError}
        selectedTask={props.selectedTask}
        selectedTaskId={props.selectedTaskId}
        setSelectedTaskId={props.setSelectedTaskId}
        refreshTasks={props.refreshTasks}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
        session={props.session}
        systemStatus={props.systemStatus}
      />
    );
  }
  if (routeId === "operations") {
    return (
      <OperationsPage
        operations={props.operations}
        total={props.operationsTotal}
        updatedAt={props.operationsUpdatedAt}
        stale={props.operationsStale}
        loading={props.operationsLoading}
        error={props.operationsError}
        summary={props.operationSummary}
        refreshOperations={props.refreshOperations}
        refreshOperationSummary={props.refreshOperationSummary}
        runBusy={props.runBusy}
        busy={props.busy}
        showAlert={props.showAlert}
      />
    );
  }
  if (routeId === "automations") {
    return <AutomationsPage showAlert={props.showAlert} />;
  }
  if (routeId === "vulnerabilities") {
    return <VulnerabilitiesPage />;
  }
  if (routeId === "remediation") {
    return <RemediationPage showAlert={props.showAlert} onNavigate={props.onNavigate} />;
  }
  if (routeId === "coverage") {
    return <CoveragePage showAlert={props.showAlert} onNavigate={props.onNavigate} />;
  }
  if (routeId === "export") {
    return (
      <ExportPage
        defaults={props.defaults}
        busy={props.busy}
        runBusy={props.runBusy}
        refreshAssets={props.refreshAssets}
        showAlert={props.showAlert}
      />
    );
  }
  if (routeId === "asset-cards") {
    return (
      <AssetCardsPage
        defaults={props.defaults}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
      />
    );
  }
  if (routeId === "asset-query") {
    return (
      <AssetQueryPage
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
      />
    );
  }
  if (routeId === "passports") {
    return (
      <PassportsPage
        defaults={props.defaults}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
      />
    );
  }
  if (routeId === "assets") {
    return (
      <AssetsPage
        summary={props.summary}
        rows={props.assetRows}
        total={props.assetTotal}
        loading={props.assetsLoading}
        error={props.assetsError}
        refreshAssets={props.refreshAssets}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
      />
    );
  }
  return (
    <section className="panel">
      <div className="panel__header">
        <div>
          <h2>Раздел не найден</h2>
          <p>Выберите нужный раздел в боковом меню.</p>
        </div>
      </div>
    </section>
  );
}

```

## `src/app/layout.jsx`

Shared shell components used across authenticated routes: Sidebar, Topbar, WorkflowRail, SystemBanner, and AlertStack.

```jsx
import { useEffect, useRef } from "react";
import { navigationGroups, routes, workflowSteps } from "./navigation.js";

function shouldHandleLinkClick(event) {
  return (
    !event.defaultPrevented &&
    event.button === 0 &&
    !event.metaKey &&
    !event.ctrlKey &&
    !event.shiftKey &&
    !event.altKey
  );
}

export function Sidebar({
  session,
  systemStatus,
  activeOperations = 0,
  activePath,
  onNavigate,
  currentUser,
}) {
  const navRef = useRef(null);
  const permissions = new Set(currentUser?.permissions || []);

  useEffect(() => {
    if (
      typeof window === "undefined" ||
      !window.matchMedia?.("(max-width: 760px)").matches
    )
      return;
    const activeLink = navRef.current?.querySelector('a[aria-current="page"]');
    activeLink?.scrollIntoView?.({ block: "nearest", inline: "center" });
  }, [activePath]);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand__mark">MP</div>
        <div>
          <strong>MP VM Client</strong>
          <span>REST API + PostgreSQL</span>
        </div>
      </div>
      <nav ref={navRef} className="nav" aria-label="Основная навигация">
        {navigationGroups.map((group) => {
          const groupRoutes = routes.filter(
            (route) => route.group === group.id &&
              (!route.requiredPermission || permissions.has(route.requiredPermission)) &&
              (!route.requiredAnyPermission || route.requiredAnyPermission.some((item) => permissions.has(item))),
          );
          return (
            <section
              className="nav-group"
              aria-labelledby={`nav-group-${group.id}`}
              key={group.id}
            >
              <h2 id={`nav-group-${group.id}`}>{group.label}</h2>
              <div className="nav-group__items">
                {groupRoutes.map((route) => (
                  <a
                    href={route.path}
                    title={route.label}
                    aria-label={
                      route.id === "operations" && activeOperations
                        ? `Операции — активных: ${activeOperations}`
                        : undefined
                    }
                    className={activePath === route.path ? "is-active" : ""}
                    aria-current={
                      activePath === route.path ? "page" : undefined
                    }
                    onClick={(event) => {
                      if (!shouldHandleLinkClick(event)) return;
                      event.preventDefault();
                      onNavigate(route.path);
                    }}
                    key={route.id}
                  >
                    <span className="nav-icon" aria-hidden="true">
                      {route.icon}
                    </span>
                    <span className="nav-label">{route.label}</span>
                    {route.id === "operations" && activeOperations ? (
                      <em className="nav-badge" aria-hidden="true">
                        {activeOperations}
                      </em>
                    ) : null}
                  </a>
                ))}
              </div>
            </section>
          );
        })}
        <span className="nav-scroll-hint" aria-hidden="true">
          ›
        </span>
      </nav>
      <div className="sidebar-card">
        <span className={session.connected ? "pulse pulse--ok" : "pulse"} />
        <div>
          <strong>
            {session.connected ? "Сессия активна" : "Нет подключения"}
          </strong>
          <p>
            {session.connected
              ? session.api_url
              : "Подключите MP VM, чтобы загрузить справочники."}
          </p>
        </div>
      </div>
      {systemStatus?.components?.database?.state === "down" ? (
        <div className="sidebar-warning">PostgreSQL недоступен</div>
      ) : null}
    </aside>
  );
}

export function SystemBanner({ status, stale, onRetry, onNavigate }) {
  if (!status || (status.state === "ok" && !stale)) return null;
  const components = Object.entries(status.components || {}).filter(
    ([, value]) => value?.state !== "ok",
  );
  const primary = components[0]?.[1];
  const isDown =
    status.state === "down" ||
    components.some(([, value]) => value?.state === "down");
  return (
    <section
      className={`system-banner system-banner--${isDown ? "down" : "degraded"}`}
      role="status"
    >
      <div>
        <strong>
          {isDown
            ? "Часть системы недоступна"
            : "Система работает с ограничениями"}
        </strong>
        <span>
          {primary?.message || "Данные операций могут быть устаревшими."}
        </span>
        {primary?.trace_id ? <code>trace: {primary.trace_id}</code> : null}
      </div>
      <div className="system-banner__actions">
        {components.some(([key]) => key === "mpvm") ? (
          <button type="button" onClick={() => onNavigate("/connection")}>
            Подключение
          </button>
        ) : null}
        {stale ? (
          <button type="button" onClick={() => onNavigate("/operations")}>
            Операции
          </button>
        ) : null}
        <button type="button" onClick={onRetry}>
          Проверить снова
        </button>
      </div>
    </section>
  );
}

const routeNextActions = {
  vm: { label: "Запустить сканирование", path: "/tasks" },
  connection: {
    connectedLabel: "Открыть VM Management",
    label: "Настроить подключение",
    path: "/vm",
  },
  tasks: { label: "Открыть операции", path: "/operations" },
  operations: { label: "Смотреть результаты", path: "/vulnerabilities" },
  vulnerabilities: { label: "Открыть карточки", path: "/asset-cards" },
  "asset-cards": { label: "Сформировать отчёт", path: "/export" },
  assets: { label: "Сформировать отчёт", path: "/export" },
  passports: { label: "Открыть карточки", path: "/asset-cards" },
  "asset-query": { label: "Открыть карточки", path: "/asset-cards" },
  export: { label: "Настроить автоматизацию", path: "/automations" },
  automations: { label: "Открыть операции", path: "/operations" },
};

export function Topbar({ session, route, onNavigate, currentUser, onLogout }) {
  const headingRef = useRef(null);
  useEffect(() => {
    const title = route?.title || "MP VM REST Client";
    if (typeof document !== "undefined")
      document.title = `${title} · MP VM Client`;
    const timer = window.setTimeout(
      () => headingRef.current?.focus({ preventScroll: true }),
      0,
    );
    return () => window.clearTimeout(timer);
  }, [route?.id, route?.title]);
  const action = routeNextActions[route?.id];
  const needsConnection = !session.connected && route?.id !== "connection";
  const actionPath =
    route?.id === "connection" && !session.connected
      ? null
      : needsConnection
        ? "/connection"
        : action?.path;
  const actionLabel = needsConnection
    ? "Настроить подключение"
    : route?.id === "connection" && session.connected
      ? action?.connectedLabel
      : action?.label;
  return (
    <header className="topbar">
      <div className="topbar__copy">
        <span className="topbar__eyebrow">MP VM · рабочее пространство</span>
        <h1 ref={headingRef} tabIndex={-1}>
          {route?.title || "MP VM REST Client"}
        </h1>
        <p>
          {route?.description ||
            "Единый клиент для задач сканирования, PDQL-экспорта и локального анализа уязвимостей."}
        </p>
      </div>
      <div className="topbar__actions">
        <div className="user-chip" title={currentUser?.username}>
          <strong>{currentUser?.display_name || currentUser?.username}</strong>
          <span>{roleLabel(currentUser?.role)}</span>
        </div>
        <div
          className={
            session.connected ? "status-chip status-chip--ok" : "status-chip"
          }
        >
          <span />
          {session.connected ? "MP VM подключён" : "MP VM не подключён"}
        </div>
        {actionPath && actionLabel ? (
          <button
            type="button"
            className="topbar__next"
            onClick={() => onNavigate(actionPath)}
          >
            <span>{actionLabel}</span>
            <strong aria-hidden="true">→</strong>
          </button>
        ) : null}
        <button type="button" className="logout-button" onClick={onLogout}>Выйти</button>
      </div>
    </header>
  );
}

function roleLabel(role) {
  return { admin: "Администратор", operator: "Оператор", viewer: "Наблюдатель" }[role] || role || "";
}

export function WorkflowRail({ activeRouteId, onNavigate }) {
  const activeIndex = Math.max(
    0,
    workflowSteps.findIndex((step) => step.routes.includes(activeRouteId)),
  );
  return (
    <nav className="workflow-rail" aria-label="Этапы рабочего процесса">
      {workflowSteps.map((step, index) => {
        const state =
          index < activeIndex
            ? "complete"
            : index === activeIndex
              ? "active"
              : "upcoming";
        return (
          <button
            type="button"
            className={`workflow-step workflow-step--${state}`}
            onClick={() => onNavigate(step.path)}
            key={step.id}
          >
            <span className="workflow-step__number">
              {index < activeIndex ? "✓" : index + 1}
            </span>
            <span className="workflow-step__copy">
              <strong>{step.label}</strong>
              <small>{step.hint}</small>
            </span>
          </button>
        );
      })}
    </nav>
  );
}

export function AlertStack({ alerts }) {
  if (!alerts.length) return null;
  return (
    <div className="alerts" aria-live="polite" aria-relevant="additions text">
      {alerts.map((alert) => (
        <div
          className={"alert alert--" + alert.type}
          role={alert.type === "error" ? "alert" : "status"}
          key={alert.id}
        >
          {alert.message}
        </div>
      ))}
    </div>
  );
}

```

## `src/app/navigation.js`

Navigation groups, workflow steps, route metadata, labels, icons, and path normalization.

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

Lightweight History API router used by the shell.

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

## `src/app/providers.jsx`

Global TanStack Query provider.

```jsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export function AppProviders({ children }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

```

## `src/app/AppDataContext.jsx`

Shared application-data context wrapped around route pages.

```jsx
import { createContext, useContext } from "react";
import { useAppData } from "./useAppData.js";

const AppDataContext = createContext(null);

export function AppDataProvider({ routeId, children }) {
  const value = useAppData(routeId);
  return (
    <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>
  );
}

export function useAppDataContext() {
  const value = useContext(AppDataContext);
  if (!value)
    throw new Error("useAppDataContext must be used inside AppDataProvider");
  return value;
}

```

## `src/features/auth/AuthGate.jsx`

Authentication boundary and login screen shown before the application shell.

```jsx
import { useEffect, useState } from "react";
import { api } from "../../api/client.js";

export function AuthGate({ children }) {
  const [state, setState] = useState({ loading: true, user: null, error: null, configured: true });

  useEffect(() => {
    let active = true;
    api("/api/auth/me")
      .then((result) => active && setState({ loading: false, user: result.user, error: null, configured: true }))
      .catch(async (error) => {
        let configured = true;
        try {
          configured = (await api("/api/auth/bootstrap-status")).configured;
        } catch {
          // The login form will show the original availability error.
        }
        if (active) setState({ loading: false, user: null, error: error.status === 401 ? null : error, configured });
      });
    return () => { active = false; };
  }, []);

  const login = async (credentials) => {
    const result = await api("/api/auth/login", { method: "POST", body: JSON.stringify(credentials) });
    setState({ loading: false, user: result.user, error: null, configured: true });
  };
  const logout = async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } finally {
      setState({ loading: false, user: null, error: null, configured: true });
    }
  };
  const reauthenticate = async (password) => {
    const result = await api("/api/auth/reauth", { method: "POST", body: JSON.stringify({ password }) });
    const me = await api("/api/auth/me");
    setState({ loading: false, user: me.user, error: null, configured: true });
    return result;
  };

  if (state.loading) return <div className="auth-screen"><div className="auth-card"><p>Проверяем доступ…</p></div></div>;
  if (!state.user) return <LoginForm onLogin={login} error={state.error} configured={state.configured} />;
  return children({ user: state.user, logout, reauthenticate });
}

function LoginForm({ onLogin, error, configured }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState(error?.operatorMessage || error?.message || "");

  const submit = async (event) => {
    event.preventDefault();
    setPending(true);
    setMessage("");
    try { await onLogin({ username, password }); }
    catch (nextError) { setMessage(nextError.operatorMessage || nextError.message); }
    finally { setPending(false); }
  };

  return (
    <main className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">MP</div>
        <span>MP VM Client</span>
        <h1>Вход в приложение</h1>
        <p>Используйте локальную учётную запись. Подключение к MP VM настраивается отдельно.</p>
        {!configured ? <div className="auth-warning">Первый администратор ещё не создан. Задайте MPVM_BOOTSTRAP_ADMIN_PASSWORD и перезапустите приложение.</div> : null}
        <label><span>Имя пользователя</span><input autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
        <label><span>Пароль</span><input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
        {message ? <div className="auth-error" role="alert">{message}</div> : null}
        <button type="submit" disabled={pending || !configured}>{pending ? "Входим…" : "Войти"}</button>
      </form>
    </main>
  );
}

```

