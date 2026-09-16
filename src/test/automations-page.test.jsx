import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { AutomationsPage } from "../pages/AutomationsPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

function renderPage(showAlert = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <AutomationsPage showAlert={showAlert} />
    </QueryClientProvider>,
  );
  return showAlert;
}

describe("AutomationsPage", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation((path, options) => {
      if (path === "/api/scanner-tasks") {
        return Promise.resolve([
          { mp_task_id: "task-1", name: "Периметр" },
        ]);
      }
      if (path === "/api/notifications") {
        return Promise.resolve({ rows: [], unread: 0 });
      }
      if (path === "/api/automations/runbooks" && options?.method === "POST") {
        return Promise.resolve({ runbook_id: "runbook-1" });
      }
      return Promise.resolve({ rows: [] });
    });
  });

  it("replaces the runbook constructor with a direct scanner schedule form", async () => {
    renderPage();

    expect(
      await screen.findByRole("heading", { name: "Автоматизация сканирования" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Сценарии" })).not.toBeInTheDocument();
    expect(
      screen.getByLabelText("Задача сканирования MP VM"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Cron")).toHaveValue("0 2 * * *");
  });

  it("creates and publishes a scan runbook before attaching the cron schedule", async () => {
    const showAlert = renderPage();

    expect(
      await screen.findByRole("option", { name: "Периметр" }),
    ).toBeInTheDocument();
    fireEvent.change(
      screen.getByLabelText("Задача сканирования MP VM"),
      { target: { value: "task-1" } },
    );
    fireEvent.change(screen.getByLabelText("Название расписания"), {
      target: { value: "Ночное сканирование" },
    });
    fireEvent.change(screen.getByLabelText("Cron"), {
      target: { value: "30 1 * * *" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Создать расписание" }));

    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/automations/runbooks",
        expect.objectContaining({
          method: "POST",
          body: expect.stringContaining('"type":"scanner_task_start"'),
        }),
      ),
    );
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/automations/runbooks/runbook-1/publish",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/automations/schedules",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            runbook_id: "runbook-1",
            name: "Ночное сканирование",
            cron_expression: "30 1 * * *",
            timezone: "Asia/Yekaterinburg",
            enabled: true,
          }),
        }),
      ),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Расписание для задачи «Периметр» создано.",
        "success",
      ),
    );
  });
});
