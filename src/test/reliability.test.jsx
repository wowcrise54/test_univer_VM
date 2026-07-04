import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SystemBanner } from "../app/layout.jsx";
import { normalizeApiError } from "../api/client.js";
import { ConfirmDialog } from "../shared/ui.jsx";
import { OperationsPage } from "../pages/OperationsPage.jsx";

vi.mock("../api/client.js", async (importOriginal) => {
  const original = await importOriginal();
  return { ...original, api: vi.fn(() => Promise.resolve({ rows: [] })) };
});

describe("reliability UI", () => {
  it("normalizes a network failure into an operator-facing error", () => {
    const error = normalizeApiError(new TypeError("fetch failed"), { path: "/api/system/status", requestId: "request-1" });
    expect(error.code).toBe("NETWORK_UNAVAILABLE");
    expect(error.retryable).toBe(true);
    expect(error.context.path).toBe("/api/system/status");
  });

  it("renders one persistent degraded-state banner", () => {
    render(<SystemBanner status={{ state: "degraded", components: { database: { state: "down", message: "PostgreSQL недоступен.", trace_id: "trace-1" } } }} stale onRetry={vi.fn()} onNavigate={vi.fn()} />);
    expect(screen.getByText("Часть системы недоступна")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL недоступен.")).toBeInTheDocument();
    expect(screen.getByText("trace: trace-1")).toBeInTheDocument();
  });

  it("requires the remote object id before destructive confirmation", () => {
    const confirm = vi.fn();
    render(<ConfirmDialog open title="Удалить задачу?" description="Изменение MP VM" requireText="task-42" onConfirm={confirm} onClose={vi.fn()} />);
    const button = screen.getByRole("button", { name: "Подтвердить" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "task-42" } });
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(confirm).toHaveBeenCalledOnce();
  });

  it("shows normalized operations and attention count", () => {
    const operations = [
      { operation_id: "one", kind: "asset_card_build", status: "running", stage: "tree", progress_percent: 42, subject: { label: "host-1" }, updated_at: "2026-07-04T10:00:00Z" },
      { operation_id: "two", kind: "passport_detail_sync", status: "failed", stage: "failed", progress_percent: 73, subject: { label: "Passports" }, updated_at: "2026-07-04T10:01:00Z", can_retry: true },
    ];
    render(<OperationsPage operations={operations} total={2} updatedAt="2026-07-04T10:02:00Z" stale={false} refreshOperations={vi.fn()} runBusy={(_key, fn) => fn()} busy={{}} showAlert={vi.fn()} />);
    expect(screen.getByText("host-1")).toBeInTheDocument();
    expect(screen.getByText("Passports")).toBeInTheDocument();
    expect(screen.getByText("требуют внимания").previousSibling).toHaveTextContent("1");
  });
});
