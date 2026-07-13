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
