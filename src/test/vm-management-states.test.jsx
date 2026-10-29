import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { VmManagementPage } from "../pages/VmManagementPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn(), createIdempotencyKey: () => "key-1" }));

const PERMISSIONS = [
  "operations.read",
  "tasks.read",
  "tasks.execute",
  "remediation.read",
  "remediation.manage",
  "risk.manage",
];

function renderPage(currentUser = { username: "e2e", permissions: PERMISSIONS }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VmManagementPage
        session={{ connected: true }}
        currentUser={currentUser}
        showAlert={vi.fn()}
        onNavigate={vi.fn()}
      />
    </QueryClientProvider>,
  );
}

describe("VmManagementPage critical states", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation((path) => {
      if (path === "/api/vm/overview") {
        return Promise.resolve({
          active_workflows: 0,
          active_operations: 0,
          open_cases: 0,
          overdue_cases: 0,
          awaiting_verification: 0,
          asset_count: 0,
          attention: [],
          recent_workflows: [],
        });
      }
      if (path === "/api/scanner-tasks") return Promise.resolve([]);
      if (path === "/api/remediation/campaigns") return Promise.resolve({ rows: [], total: 0 });
      if (path === "/api/attention?limit=100") return Promise.resolve({ items: [] });
      return Promise.reject(new Error(path));
    });
  });

  it("shows an inline error when the overview query fails", async () => {
    const failure = new Error("MP VM недоступен");
    failure.operatorMessage = "MP VM недоступен";
    api.mockImplementation((path) => {
      if (path === "/api/vm/overview") return Promise.reject(failure);
      if (path === "/api/scanner-tasks") return Promise.resolve([]);
      if (path === "/api/remediation/campaigns") return Promise.resolve({ rows: [], total: 0 });
      if (path === "/api/attention?limit=100") return Promise.resolve({ items: [] });
      return Promise.reject(new Error(path));
    });
    renderPage();

    const alert = await screen.findByText("MP VM недоступен");
    expect(alert.closest('[role="alert"]')).toBeInTheDocument();
    expect(screen.getByText("Активные процессы")).toBeInTheDocument();
  });

  it("renders zero KPIs and empty queues while connected with no data", async () => {
    renderPage();

    expect(await screen.findByText("Активные процессы")).toBeInTheDocument();
    const kpis = screen.getAllByRole("article");
    expect(kpis).toHaveLength(4);
    for (const kpi of kpis) {
      expect(kpi.querySelector("strong")?.textContent).toBe("0");
    }
    expect(screen.queryByText(/Нет подключения к MP VM/)).not.toBeInTheDocument();
    expect(await screen.findByText("Нет задач, требующих действия.")).toBeInTheDocument();
    expect(screen.getByText("Процессов пока нет.")).toBeInTheDocument();
    // One refresh button serves the whole page.
    expect(screen.getAllByRole("button", { name: "Обновить" })).toHaveLength(1);
  });

  it("prompts to configure the connection when MP VM is not connected", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const onNavigate = vi.fn();
    render(
      <QueryClientProvider client={client}>
        <VmManagementPage
          session={{ connected: false }}
          currentUser={{ username: "e2e", permissions: PERMISSIONS }}
          showAlert={vi.fn()}
          onNavigate={onNavigate}
        />
      </QueryClientProvider>,
    );

    expect(await screen.findByText(/Нет подключения к MP VM/)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Задача MP VM" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Проверить перед запуском" })).toBeDisabled();
  });
});
