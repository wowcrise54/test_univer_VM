import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { VmManagementPage } from "../pages/VmManagementPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn(), createIdempotencyKey: () => "key-1" }));

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><VmManagementPage
    session={{ connected: true }} currentUser={{ permissions: ["operations.read", "tasks.read", "tasks.execute", "remediation.read", "remediation.manage", "risk.manage"] }}
    showAlert={vi.fn()} onNavigate={vi.fn()} /></QueryClientProvider>);
}

beforeEach(() => {
  api.mockReset();
  api.mockImplementation((path, options) => {
    if (path === "/api/vm/overview") return Promise.resolve({ active_workflows: 1, open_cases: 4, overdue_cases: 2, awaiting_verification: 1, asset_count: 10, attention: [], recent_workflows: [] });
    if (path === "/api/scanner-tasks") return Promise.resolve([{ mp_task_id: "task-1", payload: { name: "Production" } }]);
    if (path === "/api/remediation/campaigns") return Promise.resolve({ rows: [], total: 0 });
    if (path === "/api/vm/workflows/scan" && options?.method === "POST") return Promise.resolve({ workflow_id: "wf-1", status: "queued" });
    if (path === "/api/vm/workflows/wf-1") return Promise.resolve({ workflow_id: "wf-1", kind: "scan", status: "queued", progress_percent: 0, steps: [] });
    return Promise.reject(new Error(path));
  });
});

describe("VM Management", () => {
  it("shows the cross-domain overview and starts a durable workflow", async () => {
    renderPage();
    expect(await screen.findByText("Оперативная сводка")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Просрочено").previousSibling).toHaveTextContent("2"));
    await screen.findByRole("option", { name: "Production" });
    fireEvent.click(screen.getByRole("button", { name: "Запустить конвейер" }));
    await waitFor(() => expect(api).toHaveBeenCalledWith("/api/vm/workflows/scan", expect.objectContaining({ method: "POST" })));
    expect(await screen.findByRole("dialog", { name: "Полное сканирование" })).toBeInTheDocument();
  });
});
