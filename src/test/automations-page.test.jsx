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
        return Promise.resolve([{ mp_task_id: "task-1", name: "Периметр" }]);
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
      await screen.findByRole("heading", {
        name: "Автоматизация сканирования",
      }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: "Сценарии" }),
    ).not.toBeInTheDocument();
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
    fireEvent.change(screen.getByLabelText("Задача сканирования MP VM"), {
      target: { value: "task-1" },
    });
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

describe("Notification reading modes", () => {
  it("hides a notification after marking it read and keeps it in history", async () => {
    let isRead = false;
    api.mockImplementation((path) => {
      if (path === "/api/notifications/notice-1/read") {
        isRead = true;
        return Promise.resolve({ is_read: true });
      }
      if (path.startsWith("/api/notifications"))
        return Promise.resolve({
          unread: isRead ? 0 : 1,
          rows: [
            {
              notification_id: "notice-1",
              title: "Сканирование завершено",
              message: "Обработано",
              event_type: "scan.completed",
              level: "info",
              is_read: isRead,
              created_at: "2026-09-30T00:00:00Z",
            },
          ],
        });
      return Promise.resolve({ rows: [] });
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: /Уведомления/ }));
    expect(
      await screen.findByText("Сканирование завершено"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Прочитано" }));
    await waitFor(() =>
      expect(
        screen.queryByText("Сканирование завершено"),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "История" }));
    expect(
      await screen.findByText("Сканирование завершено"),
    ).toBeInTheDocument();
  });
});

describe("Notification read acknowledgement", () => {
  it("keeps a successful read hidden while the subsequent list refresh stalls", async () => {
    let acknowledged = false;
    api.mockImplementation((path) => {
      if (path === "/api/notifications/stable-notice/read") {
        acknowledged = true;
        return Promise.resolve({ is_read: true });
      }
      if (path.startsWith("/api/notifications")) {
        if (acknowledged && path.includes("unread_only=true"))
          return new Promise(() => {});
        return Promise.resolve({
          unread: 1,
          rows: [
            {
              notification_id: "stable-notice",
              title: "Прочитанная операция",
              message: "Готово",
              event_type: "completed",
              level: "info",
              is_read: false,
            },
          ],
        });
      }
      return Promise.resolve({ rows: [] });
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: /Уведомления/ }));
    await screen.findByText("Прочитанная операция");
    fireEvent.click(screen.getByRole("button", { name: "Прочитано" }));
    await waitFor(() =>
      expect(
        screen.queryByText("Прочитанная операция"),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "История" }));
    expect(await screen.findByText("Прочитанная операция")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Прочитано" }),
    ).not.toBeInTheDocument();
  });
});

describe("Notification server selection", () => {
  beforeEach(() => api.mockReset());
  it("loads unread notifications beyond the history limit and separates the mode caches", async () => {
    const history = Array.from({ length: 100 }, (_, index) => ({
      notification_id: "read-" + index,
      title: "История " + index,
      is_read: true,
      message: "Готово",
      event_type: "completed",
      level: "info",
    }));
    const olderUnread = {
      notification_id: "older-unread",
      title: "Давнее непрочитанное",
      is_read: false,
      message: "Внимание",
      event_type: "failed",
      level: "error",
    };
    let read = false;
    api.mockImplementation((path) => {
      if (path === "/api/notifications/older-unread/read") {
        read = true;
        return Promise.resolve({ is_read: true });
      }
      if (path === "/api/notifications?unread_only=true")
        return Promise.resolve({
          rows: read ? [] : [olderUnread],
          unread: read ? 0 : 1,
        });
      if (path === "/api/notifications")
        return Promise.resolve({ rows: history, unread: read ? 0 : 1 });
      return Promise.resolve({ rows: [] });
    });
    renderPage();
    fireEvent.click(screen.getByRole("tab", { name: /Уведомления/ }));
    expect(await screen.findByText("Давнее непрочитанное")).toBeInTheDocument();
    expect(screen.queryByText("История 0")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "История" }));
    expect(await screen.findByText("История 0")).toBeInTheDocument();
    expect(screen.queryByText("Давнее непрочитанное")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Непрочитанные" }));
    await screen.findByText("Давнее непрочитанное");
    fireEvent.click(screen.getByRole("button", { name: "Прочитано" }));
    await waitFor(() =>
      expect(
        screen.queryByText("Давнее непрочитанное"),
      ).not.toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "История" }));
    await screen.findByText("История 0");
    expect(
      api.mock.calls.filter(([path]) => path === "/api/notifications"),
    ).toHaveLength(2);
  });
});
