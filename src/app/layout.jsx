import { routes } from "./navigation.js";

export function Sidebar({ session, activePath, onNavigate }) {
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
            {route.label}
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
    </aside>
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
