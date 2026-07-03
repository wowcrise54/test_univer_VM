import { lazy, Suspense } from "react";
import { AlertStack, Sidebar, Topbar } from "./layout.jsx";
import { useRouter } from "./router.js";
import { useAppData } from "./useAppData.js";

const AssetCardsPage = lazy(() => import("../pages/AssetCardsPage.jsx").then((module) => ({ default: module.AssetCardsPage })));
const AssetsPage = lazy(() => import("../pages/AssetsPage.jsx").then((module) => ({ default: module.AssetsPage })));
const ConnectionPage = lazy(() => import("../pages/ConnectionPage.jsx").then((module) => ({ default: module.ConnectionPage })));
const ExportPage = lazy(() => import("../pages/ExportPage.jsx").then((module) => ({ default: module.ExportPage })));
const PassportsPage = lazy(() => import("../pages/PassportsPage.jsx").then((module) => ({ default: module.PassportsPage })));
const TasksPage = lazy(() => import("../pages/TasksPage.jsx").then((module) => ({ default: module.TasksPage })));

export function App() {
  const { navigate, path, route } = useRouter();
  const appData = useAppData(route?.id);

  return (
    <div className="app-shell">
      <Sidebar session={appData.session} activePath={path} onNavigate={navigate} />
      <main className="workspace">
        <Topbar session={appData.session} route={route} />
        <AlertStack alerts={appData.alerts} />
        <Suspense fallback={<div className="route-loading">Загрузка раздела…</div>}>
          <ActivePage
            routeId={route?.id}
            {...appData}
          />
        </Suspense>
      </main>
    </div>
  );
}

function ActivePage({ routeId, ...props }) {
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
      />
    );
  }
  if (routeId === "tasks") {
    return (
      <TasksPage
        defaults={props.defaults}
        lookups={props.lookups}
        tasks={props.tasks}
        selectedTask={props.selectedTask}
        selectedTaskId={props.selectedTaskId}
        setSelectedTaskId={props.setSelectedTaskId}
        refreshTasks={props.refreshTasks}
        busy={props.busy}
        runBusy={props.runBusy}
        showAlert={props.showAlert}
      />
    );
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
    return <AssetCardsPage defaults={props.defaults} busy={props.busy} runBusy={props.runBusy} showAlert={props.showAlert} />;
  }
  if (routeId === "passports") {
    return <PassportsPage defaults={props.defaults} busy={props.busy} runBusy={props.runBusy} showAlert={props.showAlert} />;
  }
  if (routeId === "assets") {
    return (
      <AssetsPage
        summary={props.summary}
        rows={props.assetRows}
        total={props.assetTotal}
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
