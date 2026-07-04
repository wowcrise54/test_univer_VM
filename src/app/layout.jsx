import { routes } from "./navigation.js";

export function Sidebar({ session, systemStatus, activeOperations = 0, activePath, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand__mark">MP</div>
        <div>
          <strong>MP VM Client</strong>
          <span>REST API + PostgreSQL</span>
        </div>
      </div>
      <nav className="nav" aria-label="Основная навигация">
        {routes.map((route) => (
          <a
            href={route.path}
            className={activePath === route.path ? "is-active" : ""}
            aria-current={activePath === route.path ? "page" : undefined}
            onClick={(event) => {
              event.preventDefault();
              onNavigate(route.path);
            }}
            key={route.id}
          >
            <span>{route.label}</span>
            {route.id === "operations" && activeOperations ? <em className="nav-badge">{activeOperations}</em> : null}
          </a>
        ))}
      </nav>
      <div className="sidebar-card">
        <span className={session.connected ? "pulse pulse--ok" : "pulse"} />
        <div>
          <strong>{session.connected ? "Сессия активна" : "Нет подключения"}</strong>
          <p>{session.connected ? session.api_url : "Подключите MP VM, чтобы загрузить справочники."}</p>
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
  const components = Object.entries(status.components || {}).filter(([, value]) => value?.state !== "ok");
  const primary = components[0]?.[1];
  const isDown = status.state === "down" || components.some(([, value]) => value?.state === "down");
  return (
    <section className={`system-banner system-banner--${isDown ? "down" : "degraded"}`} role="status">
      <div>
        <strong>{isDown ? "Часть системы недоступна" : "Система работает с ограничениями"}</strong>
        <span>{primary?.message || "Данные операций могут быть устаревшими."}</span>
        {primary?.trace_id ? <code>trace: {primary.trace_id}</code> : null}
      </div>
      <div className="system-banner__actions">
        {components.some(([key]) => key === "mpvm") ? <button onClick={() => onNavigate("/connection")}>Подключение</button> : null}
        {stale ? <button onClick={() => onNavigate("/operations")}>Операции</button> : null}
        <button onClick={onRetry}>Проверить снова</button>
      </div>
    </section>
  );
}

export function Topbar({ session, route }) {
  return (
    <header className="topbar">
      <div>
        <h1>{route?.title || "MP VM REST Client"}</h1>
        <p>{route?.description || "Единый клиент для задач сканирования, PDQL-экспорта и локального анализа уязвимостей."}</p>
      </div>
      <div className={session.connected ? "status-chip status-chip--ok" : "status-chip"}>
        <span />
        {session.connected ? "Подключено" : "Не подключено"}
      </div>
    </header>
  );
}

export function AlertStack({ alerts }) {
  if (!alerts.length) return null;
  return (
    <div className="alerts">
      {alerts.map((alert) => (
        <div className={"alert alert--" + alert.type} key={alert.id}>
          {alert.message}
        </div>
      ))}
    </div>
  );
}
