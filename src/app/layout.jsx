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
}) {
  const navRef = useRef(null);

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
            (route) => route.group === group.id,
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
  connection: {
    connectedLabel: "Перейти к задачам",
    label: "Настроить подключение",
    path: "/tasks",
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

export function Topbar({ session, route, onNavigate }) {
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
      </div>
    </header>
  );
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
