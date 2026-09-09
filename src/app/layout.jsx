import { useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import { ActionMenu } from "../shared/ui.jsx";
import { routes, workflowSteps } from "./navigation.js";

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
  systemStatus,
  activeOperations = 0,
  activePath,
  onNavigate,
  currentUser,
}) {
  const navRef = useRef(null);
  const permissions = new Set(currentUser?.permissions || []);
  const visibleRoutes = routes.filter(
    (route) =>
      (!route.requiredPermission ||
        permissions.has(route.requiredPermission)) &&
      (!route.requiredAnyPermission ||
        route.requiredAnyPermission.some((item) => permissions.has(item))),
  );
  const primaryRoutes = visibleRoutes.filter(
    (route) => route.group === "primary",
  );
  const secondaryRoutes = visibleRoutes.filter(
    (route) => route.group !== "primary",
  );
  const secondaryActive = secondaryRoutes.some(
    (route) => route.path === activePath,
  );

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
        <strong>VM Client</strong>
      </div>
      <nav ref={navRef} className="nav" aria-label="Основная навигация">
        <div className="nav-group__items">
          {primaryRoutes.map((route) => (
            <NavLink
              route={route}
              activePath={activePath}
              activeOperations={activeOperations}
              onNavigate={onNavigate}
              key={route.id}
            />
          ))}
        </div>
        {secondaryRoutes.length ? (
          <details className="nav-more" open={secondaryActive}>
            <summary>Ещё</summary>
            <div className="nav-group__items">
              {secondaryRoutes.map((route) => (
                <NavLink
                  route={route}
                  activePath={activePath}
                  activeOperations={activeOperations}
                  onNavigate={onNavigate}
                  key={route.id}
                />
              ))}
            </div>
          </details>
        ) : null}
        <span className="nav-scroll-hint" aria-hidden="true">
          ›
        </span>
      </nav>
      {systemStatus?.components?.database?.state === "down" ? (
        <div className="sidebar-warning">PostgreSQL недоступен</div>
      ) : null}
    </aside>
  );
}

function NavLink({ route, activePath, activeOperations, onNavigate }) {
  return (
    <a
      href={route.path}
      title={route.label}
      aria-label={
        route.id === "operations" && activeOperations
          ? `Операции — активных: ${activeOperations}`
          : undefined
      }
      className={`nav-link${activePath === route.path ? " is-active" : ""}`}
      data-route-id={route.id}
      data-active={activePath === route.path ? "true" : undefined}
      aria-current={activePath === route.path ? "page" : undefined}
      onClick={(event) => {
        if (!shouldHandleLinkClick(event)) return;
        event.preventDefault();
        onNavigate(route.path);
      }}
    >
      <span className="nav-label">{route.label}</span>
      {route.id === "operations" && activeOperations ? (
        <em className="nav-badge" aria-hidden="true">
          {activeOperations}
        </em>
      ) : null}
    </a>
  );
}

export function SystemBanner({
  status,
  stale,
  onRetry,
  onNavigate,
  currentUser,
}) {
  if (!status || (status.state === "ok" && !stale)) return null;
  const permissions = new Set(currentUser?.permissions || []);
  const canOpenConnectionSettings = permissions.has("connection.manage");
  const components = Object.entries(status.components || {}).filter(
    ([, value]) => value?.state !== "ok",
  );
  const primary = components[0]?.[1];
  const isDown =
    status.state === "down" ||
    components.some(([, value]) => value?.state === "down");
  const showContextActions =
    stale ||
    (canOpenConnectionSettings && components.some(([key]) => key === "mpvm"));
  return (
    <section
      className={`system-banner system-banner--${isDown ? "down" : "degraded"}`}
      role="status"
      aria-live="polite"
      data-state={isDown ? "down" : "degraded"}
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
        <button type="button" onClick={onRetry}>
          Проверить
        </button>
        {showContextActions ? (
          <ActionMenu label="Подробнее">
            {components.some(([key]) => key === "mpvm") &&
            canOpenConnectionSettings ? (
              <button type="button" onClick={() => onNavigate("/connection")}>
                Подключение
              </button>
            ) : null}
            {stale ? (
              <button type="button" onClick={() => onNavigate("/operations")}>
                Операции
              </button>
            ) : null}
          </ActionMenu>
        ) : null}
      </div>
    </section>
  );
}

const routeNextActions = {
  vm: { label: "Сканировать", path: "/tasks" },
  connection: {
    connectedLabel: "К обзору",
    label: "Подключиться",
    path: "/vm",
  },
  tasks: { label: "Операции", path: "/operations" },
  operations: { label: "Результаты", path: "/vulnerabilities" },
  vulnerabilities: { label: "Карточки", path: "/asset-cards" },
  "asset-cards": { label: "Отчёт", path: "/export" },
  assets: { label: "Отчёт", path: "/export" },
  passports: { label: "Карточки", path: "/asset-cards" },
  "asset-query": { label: "Карточки", path: "/asset-cards" },
  export: { label: "Автоматизация", path: "/automations" },
  automations: { label: "Операции", path: "/operations" },
};

export function Topbar({ session, route, onNavigate, currentUser, onLogout }) {
  const headingRef = useRef(null);
  const permissions = new Set(currentUser?.permissions || []);
  const canReadConnection =
    permissions.has("connection.read") || permissions.has("connection.manage");
  const canManageConnection = permissions.has("connection.manage");
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
  const needsConnection =
    canManageConnection && !session.connected && route?.id !== "connection";
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
    <header className="topbar" aria-labelledby="workspace-title">
      <div className="topbar__copy">
        <span className="topbar__eyebrow">MP VM Client</span>
        <h1 id="workspace-title" ref={headingRef} tabIndex={-1}>
          {route?.title || "MP VM REST Client"}
        </h1>
        {route?.description ? (
          <p className="topbar__description">{route.description}</p>
        ) : null}
      </div>
      <div className="topbar__actions">
        <GlobalSearch onNavigate={onNavigate} />
        {canReadConnection ? (
          <div
            className={
              session.connected ? "status-chip status-chip--ok" : "status-chip"
            }
            role="status"
            aria-label={session.connected ? "Подключено" : "Нет подключения"}
          >
            <span aria-hidden="true" />
            {session.connected ? "Подключено" : "Нет подключения"}
          </div>
        ) : null}
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
        <ActionMenu
          className="account-menu"
          label={
            currentUser?.display_name || currentUser?.username || "Аккаунт"
          }
        >
          {currentUser?.username ? <span>{currentUser.username}</span> : null}
          <button type="button" onClick={onLogout}>
            Выйти
          </button>
        </ActionMenu>
      </div>
    </header>
  );
}

function GlobalSearch({ onNavigate }) {
  const enabled =
    import.meta.env.VITE_MPVM_ATTENTION_SEARCH_ENABLED !== "false";
  const [value, setValue] = useState("");
  const [focused, setFocused] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [results, setResults] = useState([]);
  const inputRef = useRef(null);
  const requestRef = useRef(0);

  useEffect(() => {
    if (!enabled) return undefined;
    const query = value.trim();
    if (query.length < 2) {
      setResults([]);
      setLoading(false);
      setError(null);
      return undefined;
    }
    const requestId = ++requestRef.current;
    setLoading(true);
    setError(null);
    const timer = window.setTimeout(async () => {
      try {
        const params = new URLSearchParams({ q: query, limit: "20" });
        const data = await api(`/api/search?${params}`);
        if (requestId === requestRef.current) setResults(data?.items || []);
      } catch (cause) {
        if (requestId === requestRef.current) {
          setResults([]);
          setError(
            cause.operatorMessage ||
              cause.message ||
              "Не удалось выполнить поиск",
          );
        }
      } finally {
        if (requestId === requestRef.current) setLoading(false);
      }
    }, 250);
    return () => window.clearTimeout(timer);
  }, [value, enabled]);

  if (!enabled) return null;
  const open = focused && value.trim().length >= 2;
  const handleKeyDown = (event) => {
    if (event.key === "Escape") {
      setFocused(false);
      inputRef.current?.blur();
    }
    if (event.key === "Enter" && results[0]?.href) {
      event.preventDefault();
      const href = results[0].href;
      navigateSearchResult(href, onNavigate);
      setFocused(false);
    }
  };
  return (
    <div className="global-search">
      <label className="global-search__label" htmlFor="global-search-input">
        Поиск
      </label>
      <input
        id="global-search-input"
        ref={inputRef}
        type="search"
        value={value}
        placeholder="Поиск по активам, CVE, операциям"
        aria-label="Глобальный поиск"
        aria-controls="global-search-results"
        aria-expanded={open}
        onFocus={() => setFocused(true)}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={handleKeyDown}
      />
      {open ? (
        <div
          id="global-search-results"
          className="global-search__results"
          role="listbox"
          aria-live="polite"
        >
          {loading ? <div className="global-search__status">Ищу…</div> : null}
          {error ? (
            <div
              className="global-search__status global-search__status--error"
              role="alert"
            >
              {error}
            </div>
          ) : null}
          {!loading && !error && !results.length ? (
            <div className="global-search__status">Ничего не найдено</div>
          ) : null}
          {!loading && !error
            ? results.map((item) => {
                const href = normalizeSearchHref(item);
                return (
                  <a
                    role="option"
                    className="global-search__item"
                    href={href}
                    key={`${item.type}:${item.id}`}
                    onClick={(event) => {
                      if (
                        !event.metaKey &&
                        !event.ctrlKey &&
                        !event.shiftKey &&
                        !event.altKey
                      ) {
                        event.preventDefault();
                        navigateSearchResult(href, onNavigate);
                      }
                      setFocused(false);
                    }}
                  >
                    <span className="global-search__item-type">
                      {item.type}
                    </span>
                    <span>
                      <strong>{item.title}</strong>
                      {item.subtitle ? <small>{item.subtitle}</small> : null}
                    </span>
                  </a>
                );
              })
            : null}
        </div>
      ) : null}
    </div>
  );
}

function normalizeSearchHref(item) {
  if (
    item.type === "asset" &&
    String(item.href || "").startsWith("/asset-cards/")
  ) {
    return `/asset-cards?asset_id=${encodeURIComponent(item.id)}`;
  }
  if (
    item.type === "task" &&
    String(item.href || "").startsWith("/scanner-tasks")
  ) {
    return String(item.href).replace(/^\/scanner-tasks/, "/tasks");
  }
  if (
    item.type === "automation" &&
    String(item.href || "").startsWith("/automations/runs")
  ) {
    return `/automations?run=${encodeURIComponent(item.id)}`;
  }
  return item.href || "/vm";
}

function navigateSearchResult(href, onNavigate) {
  if (/[?#]/.test(href) && typeof window !== "undefined") {
    window.history.pushState({}, "", href);
    window.dispatchEvent(new PopStateEvent("popstate"));
  } else onNavigate?.(href);
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
            aria-label={`${step.label}: ${step.hint}`}
            aria-current={state === "active" ? "step" : undefined}
            data-step-id={step.id}
            data-state={state}
            title={step.hint}
            onClick={() => onNavigate(step.path)}
            key={step.id}
          >
            <span className="workflow-step__number">
              {index < activeIndex ? "✓" : index + 1}
            </span>
            <span className="workflow-step__copy">
              <strong>{step.label}</strong>
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
