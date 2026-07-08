import { AssetCardsPage } from "../pages/AssetCardsPage.jsx";
import { AssetQueryPage } from "../pages/AssetQueryPage.jsx";
import { AssetsPage } from "../pages/AssetsPage.jsx";
import { ConnectionPage } from "../pages/ConnectionPage.jsx";
import { ExportPage } from "../pages/ExportPage.jsx";
import { PassportsPage } from "../pages/PassportsPage.jsx";
import { OperationsPage } from "../pages/OperationsPage.jsx";
import { TasksPage } from "../pages/TasksPage.jsx";
import { AlertStack, Sidebar, SystemBanner, Topbar } from "./layout.jsx";
import { AppDataProvider, useAppDataContext } from "./AppDataContext.jsx";
import { useRouter } from "./router.js";

export function App() {
  const { navigate, path, route } = useRouter();
  return (
    <AppDataProvider routeId={route?.id}>
      <AppShell navigate={navigate} path={path} route={route} />
    </AppDataProvider>
  );
}

function AppShell({ navigate, path, route }) {
  const appData = useAppDataContext();

  return (
    <div className="app-shell">
      <Sidebar
        session={appData.session}
        systemStatus={appData.systemStatus}
        activeOperations={
          appData.operations.filter((item) =>
            ["queued", "running", "cancelling", "recovering"].includes(
              item.status,
            ),
          ).length
        }
        activePath={path}
        onNavigate={navigate}
      />
      <main className="workspace">
        <Topbar session={appData.session} route={route} />
        <SystemBanner
          status={appData.systemStatus}
          stale={appData.operationsStale}
          onRetry={appData.refreshSystemStatus}
          onNavigate={navigate}
        />
        <AlertStack alerts={appData.alerts} />
        <ActivePage routeId={route?.id} {...appData} />
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
        refreshOperations={props.refreshOperations}
        runBusy={props.runBusy}
        busy={props.busy}
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
