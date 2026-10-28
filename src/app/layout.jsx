import { useEffect, useRef, useState } from "react";
import { api } from "../api/client.js";
import { searchTypeLabel } from "../shared/labels.js";
import { ActionMenu } from "../shared/ui.jsx";
import { navigationGroups, routes } from "./navigation.js";

function getAccountLabel(user) {
  const displayName = String(user?.display_name || "").trim();
  const username = String(user?.username || "").trim();
  if (!displayName || displayName.toLowerCase() === username.toLowerCase()) {
    return "Аккаунт";
  }

  const usernameSuffix = ` ${username}`;
  if (
    username &&
    displayName.toLowerCase().endsWith(usernameSuffix.toLowerCase())
  ) {
    return displayName.slice(0, -usernameSuffix.length).trimEnd() || "Аккаунт";
  }

  return displayName;
}

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
            {navigationGroups
              .filter((group) => group.id !== "primary")
              .map((group) => {
                const items = secondaryRoutes.filter(
                  (route) => route.group === group.id,
                );
                if (!items.length) return null;
                return (
                  <div
                    className="nav-group"
                    role="group"
                    aria-labelledby={`nav-group-${group.id}`}
                    key={group.id}
                  >
                    <span
                      className="nav-group__label"
                      id={`nav-group-${group.id}`}
                    >
                      {group.label}
                    </span>
                    <div className="nav-group__items">
                      {items.map((route) => (
                        <NavLink
                          route={route}
                          activePath={activePath}
                          activeOperations={activeOperations}
                          onNavigate={onNavigate}
                          key={route.id}
                        />
                      ))}
                    </div>
                  </div>
                );
              })}
          </details>
        ) : null}
        <span className="nav-scroll-hint" aria-hidden="true">
          ›
        </span>
      </nav>
      {systemStatus?.components?.database?.state === "down" ? (
        <div className="sidebar-warning">База данных недоступна</div>
      ) : null}
    </aside>
  );
}

function NavLink({ route, activePath, activeOperations, onNavigate }) {
  const showOperationsBadge =
    route.id === "operations" &&
    activeOperations > 0 &&
    activePath !== route.path;
  return (
    <a
      href={route.path}
      aria-label={
        showOperationsBadge
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
      {showOperationsBadge ? (
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
  const components = Object.entries(status?.components || {}).filter(
    ([key, value]) =>
      value?.state !== "ok" && !(key === "mpvm" && value?.state === "degraded"),
  );
  if (!status || (!components.length && !stale)) return null;
  const permissions = new Set(currentUser?.permissions || []);
  const canOpenConnectionSettings = permissions.has("connection.manage");
  const primary = components[0]?.[1];
  const isDown =
    status.state === "down" ||
    components.some(([, value]) => value?.state === "down");
  const showContextActions =
    stale ||
    Boolean(primary?.trace_id) ||
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
            {primary?.trace_id ? (
              <code className="system-banner__trace">
                trace: {primary.trace_id}
              </code>
            ) : null}
          </ActionMenu>
        ) : null}
      </div>
    </section>
  );
}

export function Topbar({
  session,
  route,
  onNavigate,
  theme = "light",
  onToggleTheme,
  currentUser,
  onLogout,
}) {
  const headingRef = useRef(null);
  const permissions = new Set(currentUser?.permissions || []);
  const canReadConnection =
    permissions.has("connection.read") || permissions.has("connection.manage");
  const canManageConnection = permissions.has("connection.manage");
  useEffect(() => {
    const title = route?.title || "MP VM Client";
    if (typeof document !== "undefined")
      document.title = `${title} · MP VM Client`;
    const timer = window.setTimeout(
      () => headingRef.current?.focus({ preventScroll: true }),
      0,
    );
    return () => window.clearTimeout(timer);
  }, [route?.id, route?.title]);
  return (
    <header className="topbar" aria-labelledby="workspace-title">
      <div className="topbar__copy">
        <h1 id="workspace-title" ref={headingRef} tabIndex={-1}>
          {route?.title || "MP VM Client"}
        </h1>
      </div>
      <div className="topbar__actions">
        <GlobalSearch onNavigate={onNavigate} />
        <button
          type="button"
          className="theme-toggle"
          aria-label={`Переключить на ${theme === "dark" ? "светлую" : "тёмную"} тему`}
          aria-pressed={theme === "dark"}
          title={`Переключить на ${theme === "dark" ? "светлую" : "тёмную"} тему`}
          onClick={onToggleTheme}
        >
          <svg
            aria-hidden="true"
            viewBox="0 0 24 24"
            width="18"
            height="18"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            {theme === "dark" ? (
              <>
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
              </>
            ) : (
              <path d="M20.5 13a8.5 8.5 0 0 1-9.5-9.5A8.5 8.5 0 1 0 20.5 13Z" />
            )}
          </svg>
        </button>
        {canReadConnection ? (
          <ConnectionChip
            connected={session.connected}
            canManage={canManageConnection && route?.id !== "connection"}
            onNavigate={onNavigate}
          />
        ) : null}
        <ActionMenu
          className="account-menu"
          label={getAccountLabel(currentUser)}
        >
          <button type="button" onClick={onLogout}>
            Выйти
          </button>
        </ActionMenu>
      </div>
    </header>
  );
}

function ConnectionChip({ connected, canManage, onNavigate }) {
  const label = connected ? "Подключено" : "Нет подключения";
  const className = connected ? "status-chip status-chip--ok" : "status-chip";
  if (canManage && !connected) {
    return (
      <a
        href="/connection"
        className={`${className} status-chip--link`}
        onClick={(event) => {
          if (!shouldHandleLinkClick(event)) return;
          event.preventDefault();
          onNavigate("/connection");
        }}
      >
        <span aria-hidden="true" />
        {label}
      </a>
    );
  }
  return (
    <div className={className} role="status" aria-label={label}>
      <span aria-hidden="true" />
      {label}
    </div>
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
                      {searchTypeLabel(item.type)}
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

export function AlertStack({ alerts, onDismiss }) {
  if (!alerts.length) return null;
  return (
    <div className="alerts" aria-live="polite" aria-relevant="additions text">
      {alerts.map((alert) => (
        <div
          className={"alert alert--" + alert.type}
          role={alert.type === "error" ? "alert" : "status"}
          key={alert.id}
        >
          <span>{alert.message}</span>
          {onDismiss ? (
            <button
              type="button"
              className="alert-dismiss"
              aria-label="Закрыть"
              onClick={() => onDismiss(alert.id)}
            >
              ×
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}
