import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { OperationsPage } from "../pages/OperationsPage.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: () => "test-key",
}));

const OPERATION = {
  operation_id: "operation-001",
  kind: "asset_card_build",
  status: "running",
  stage: "tree",
  progress_percent: 42,
  subject: { id: "host-1", label: "host-1" },
  message: "Сбор дерева актива",
  can_cancel: true,
  can_retry: false,
  created_at: "2026-07-04T10:00:00Z",
  updated_at: "2026-07-04T10:02:00Z",
  request: {},
  result: null,
  error: null,
  events: [
    {
      id: "event-1",
      status: "running",
      stage: "tree",
      message: "Начали сбор дерева",
      created_at: "2026-07-04T10:01:00Z",
    },
  ],
};

function renderOperations(overrides = {}) {
  const props = {
    operations: [OPERATION],
    total: 1,
    updatedAt: "2026-07-04T10:03:00Z",
    stale: false,
    loading: false,
    error: null,
    summary: null,
    refreshOperations: vi.fn(() => Promise.resolve({ rows: [OPERATION], total: 1 })),
    refreshOperationSummary: vi.fn(() => Promise.resolve({ total: 1, active: 1 })),
    runBusy: (_key, action) => action(),
    busy: {},
    showAlert: vi.fn(),
    ...overrides,
  };
  return render(<OperationsPage {...props} />);
}

describe("OperationsPage critical states", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockResolvedValue({ rows: [], total: 0 });
  });

  it("shows a loading state while the list is being fetched", () => {
    renderOperations({ operations: [], total: 0, loading: true });

    expect(screen.getByText("Загрузка операций…")).toBeInTheDocument();
  });

  it("shows a retryable error state when loading fails", async () => {
    const refreshOperations = vi.fn(() => Promise.resolve({ rows: [OPERATION], total: 1 }));
    renderOperations({
      operations: [],
      total: 0,
      error: new Error("backend down"),
      refreshOperations,
    });

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Не удалось загрузить операции: backend down");
    fireEvent.click(screen.getByRole("button", { name: "Повторить" }));
    await waitFor(() => expect(refreshOperations).toHaveBeenCalled());
  });

  it("shows the empty state when no operations match", () => {
    renderOperations({ operations: [], total: 0 });

    expect(screen.getByText("Операции с такими фильтрами не найдены.")).toBeInTheDocument();
    expect(screen.getByText("Нет операций")).toBeInTheDocument();
  });

  it("marks the summary stale when data may be outdated", () => {
    renderOperations({ stale: true });

    expect(screen.getByText("Устарели")).toBeInTheDocument();
    expect(screen.queryByText("Актуальны")).not.toBeInTheDocument();
  });

  it("opens the operation drawer and closes it with the close button", async () => {
    api.mockImplementation((path) =>
      path === "/api/operations/operation-001"
        ? Promise.resolve(OPERATION)
        : Promise.resolve({ rows: [], total: 0 }),
    );
    renderOperations();

    fireEvent.click(screen.getByRole("button", { name: "Открыть" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByText("Сбор дерева актива")).toBeInTheDocument();
    expect(within(dialog).getByText("42%")).toBeInTheDocument();
    expect(within(dialog).getByText("Прогресс")).toBeInTheDocument();
    expect(
      within(dialog).getByRole("link", { name: "Диагностика" }),
    ).toHaveAttribute("href", "/api/operations/operation-001/diagnostics");

    fireEvent.click(screen.getByRole("button", { name: "Закрыть" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("asks for cancellation from the drawer and keeps the returned operation", async () => {
    let latestDetail = OPERATION;
    const cancelled = { ...OPERATION, status: "cancelling", can_cancel: false };
    api.mockImplementation((path, options) => {
      if (path === "/api/operations/operation-001") return Promise.resolve(latestDetail);
      if (path === "/api/operations/operation-001/cancel") {
        expect(options.method).toBe("POST");
        latestDetail = cancelled;
        return Promise.resolve(cancelled);
      }
      return Promise.resolve({ rows: [], total: 0 });
    });
    const showAlert = vi.fn();
    renderOperations({ showAlert });

    fireEvent.click(screen.getByRole("button", { name: "Открыть" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Остановить" }));

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/operations/operation-001/cancel",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    await waitFor(() =>
      expect(within(dialog).getByText("Останавливается")).toBeInTheDocument(),
    );
    expect(showAlert).toHaveBeenCalledWith("Запрос на остановку операции принят.", "info");
  });

  it("retries a failed operation with an idempotency key", async () => {
    let latestDetail = { ...OPERATION, status: "failed", can_cancel: false, can_retry: true, stage: "failed" };
    const retried = { ...latestDetail, status: "queued", can_retry: false };
    api.mockImplementation((path, options) => {
      if (path === "/api/operations/operation-001") return Promise.resolve(latestDetail);
      if (path === "/api/operations/operation-001/retry") {
        expect(options.method).toBe("POST");
        expect(options.headers["X-Idempotency-Key"]).toBe("test-key");
        latestDetail = retried;
        return Promise.resolve({ operation: retried });
      }
      return Promise.resolve({ rows: [], total: 0 });
    });
    const showAlert = vi.fn();
    renderOperations({ operations: [latestDetail], showAlert });

    fireEvent.click(screen.getByRole("button", { name: "Открыть" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Повторить" }));

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/operations/operation-001/retry",
        expect.objectContaining({
          method: "POST",
          headers: { "X-Idempotency-Key": "test-key" },
        }),
      ),
    );
    await waitFor(() =>
      expect(within(dialog).getByText("В очереди")).toBeInTheDocument(),
    );
    expect(showAlert).toHaveBeenCalledWith("Повтор операции поставлен в очередь.", "success");
  });

  it("saves the current filter view through /api/saved-views", async () => {
    api.mockImplementation((path, options) => {
      if (path === "/api/saved-views?route=operations") return Promise.resolve({ rows: [], total: 0 });
      if (path === "/api/saved-views" && options.method === "POST") {
        expect(JSON.parse(options.body)).toEqual({
          route: "operations",
          name: "Критичные сбои",
          filters: expect.objectContaining({
            q: "",
            status: "failed",
            kind: "",
            sort: expect.objectContaining({ key: "created_at" }),
          }),
        });
        return Promise.resolve({ id: "view-1", route: "operations", name: "Критичные сбои" });
      }
      return Promise.resolve({ rows: [], total: 0 });
    });
    const showAlert = vi.fn();
    renderOperations({ showAlert });

    fireEvent.click(screen.getByText("Фильтры и представления"));
    fireEvent.change(screen.getByLabelText("Статус операции"), { target: { value: "failed" } });
    fireEvent.change(screen.getByLabelText("Название представления"), {
      target: { value: "Критичные сбои" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/saved-views",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    expect(showAlert).toHaveBeenCalledWith("Представление «Критичные сбои» сохранено.", "success");
  });

  it("debounces the search query before requesting the list", async () => {
    const refreshOperations = vi.fn(() => Promise.resolve({ rows: [OPERATION], total: 1 }));
    renderOperations({ refreshOperations });
    const callsAtMount = refreshOperations.mock.calls.length;
    expect(callsAtMount).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText("Поиск операций"), { target: { value: "host" } });
    expect(refreshOperations).toHaveBeenCalledTimes(callsAtMount);
    await vi.waitFor(() =>
      expect(refreshOperations).toHaveBeenLastCalledWith(
        expect.objectContaining({ q: "host", limit: 50, offset: 0 }),
      ),
    );
  });
});
