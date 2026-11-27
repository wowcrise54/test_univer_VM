import { useState } from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { TasksPage } from "../pages/TasksPage.jsx";
import { recordFrontendEvent } from "../diagnostics.js";

vi.mock("../diagnostics.js", async (importOriginal) => ({
  ...(await importOriginal()),
  recordFrontendEvent: vi.fn(),
}));

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "task-action-key"),
  downloadApiFile: vi.fn(),
}));

const tasks = [
  {
    mp_task_id: "task-1",
    name: "Night audit",
    status: "finished",
    created_at: "2026-10-01T10:00:00Z",
    include_targets: ["10.0.0.1"],
    payload: {
      profile: "profile-1",
      include: { targets: ["10.0.0.1"] },
      triggerParameters: { isEnabled: false },
    },
  },
  {
    mp_task_id: "task-2",
    name: "Domain audit",
    status: "running",
    include_targets: ["example.test"],
    payload: { profile: "profile-2", include: { targets: ["example.test"] } },
  },
];

function renderTasks(
  permissions = ["tasks.read", "tasks.manage", "tasks.execute"],
  taskRows = tasks,
) {
  function Harness() {
    const [selectedTaskId, setSelectedTaskId] = useState(null);
    return (
      <TasksPage
        busy={{}}
        defaults={{ utc_offset: "+05:00" }}
        lookups={{ scopes: [], scanner_profiles: [], credentials: [] }}
        refreshTasks={vi.fn()}
        runBusy={(_key, action) => action()}
        selectedTask={null}
        selectedTaskId={selectedTaskId}
        setSelectedTaskId={setSelectedTaskId}
        showAlert={vi.fn()}
        currentUser={{ permissions }}
        session={{ connected: true }}
        systemStatus={{ components: { database: { state: "ok" } } }}
        tasks={taskRows}
      />
    );
  }
  return render(<Harness />);
}

describe("task workspace", () => {
  beforeEach(() => {
    recordFrontendEvent.mockClear();
    api.mockReset();
    api.mockImplementation(async (path) => {
      if (path === "/api/scanner-task-folders") return { rows: [] };
      if (path.includes("/runs?"))
        return {
          items: [
            {
              id: "run-1",
              status: "finished",
              startedAt: "2026-10-02T08:00:00Z",
            },
          ],
        };
      if (path.endsWith("/runs/run-1/jobs"))
        return {
          items: [
            {
              id: "job-1",
              status: "finished",
              errorStatus: "success",
              targets: ["10.0.0.1"],
              profile: { name: "Windows Audit" },
              connectionCheckResults: [
                {
                  transport: "RPC",
                  status: "fail",
                  errors: ["connection refused"],
                },
              ],
            },
          ],
        };
      return {};
    });
  });

  it("selects a row without loading task results or opening its editor", async () => {
    renderTasks();
    await screen.findByRole("button", { name: /Все задачи/ });
    const row = screen.getByText("Night audit").closest("tr");
    fireEvent.click(row);
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(
      screen.getByRole("heading", { name: "Night audit" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Название задачи")).not.toBeInTheDocument();
    expect(api.mock.calls.map(([path]) => path)).toEqual([
      "/api/scanner-task-folders",
    ]);
  });

  it("opens run history on double click and fetches jobs for the selected run", async () => {
    renderTasks();
    await screen.findByText("Night audit");
    fireEvent.doubleClick(screen.getByText("Night audit").closest("tr"));
    expect(
      await screen.findByRole("heading", { name: "Запуски" }),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Задания запуска" }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/RPC:/)).toBeInTheDocument();
    expect(document.querySelector(".task-connection-checks")).toHaveTextContent(
      "connection refused",
    );
    expect(api).toHaveBeenCalledWith(
      "/api/scanner-tasks/task-1/runs?offset=0&limit=50",
    );
    expect(api).toHaveBeenCalledWith(
      "/api/scanner-tasks/task-1/runs/run-1/jobs",
    );
    expect(api).not.toHaveBeenCalledWith("/api/scanner-tasks/task-1/results");
  });

  it("keeps task details visible when MP VM returns null connection-check entries", async () => {
    api.mockImplementation(async (path) => {
      if (path === "/api/scanner-task-folders") return { rows: [] };
      if (path.includes("/runs?")) {
        return {
          items: [{ id: "run-1", status: "finished" }],
          has_more: false,
        };
      }
      if (path.endsWith("/runs/run-1/jobs")) {
        return {
          items: [
            {
              id: "job-1",
              status: "finished",
              targets: ["10.0.0.1"],
              connectionCheckResults: [
                null,
                { status: "failed", errors: null },
              ],
            },
          ],
        };
      }
      return {};
    });

    renderTasks();
    await screen.findByText("Night audit");
    fireEvent.doubleClick(screen.getByText("Night audit").closest("tr"));

    expect(
      await screen.findByRole("heading", { name: "Задания запуска" }),
    ).toBeInTheDocument();
    expect(await screen.findAllByText("10.0.0.1")).toHaveLength(2);
  });

  it.each([
    {
      startedBy: {
        id: "user-1",
        login: "Administrator",
        firstName: null,
        lastName: null,
      },
    },
    { initiator: { name: "Administrator" } },
    { startedBy: "Administrator" },
  ])(
    "renders the run initiator without removing task details: %j",
    async (initiator) => {
      api.mockImplementation(async (path) => {
        if (path === "/api/scanner-task-folders") return { rows: [] };
        if (path.includes("/runs?")) {
          return {
            items: [{ id: "run-1", status: "finished", ...initiator }],
          };
        }
        return { items: [] };
      });

      renderTasks();
      await screen.findByText("Night audit");
      fireEvent.doubleClick(screen.getByText("Night audit").closest("tr"));
      expect(await screen.findByText("Administrator")).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "← К задачам" }),
      ).toBeInTheDocument();
    },
  );

  it("keeps unexpected rendering failures recoverable and reports the task ID", async () => {
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    try {
      renderTasks(
        ["tasks.read"],
        [
          { ...tasks[0], payload: { description: { unexpected: true } } },
          tasks[1],
        ],
      );
      await screen.findByText("Night audit");
      fireEvent.doubleClick(screen.getByText("Night audit").closest("tr"));

      expect(await screen.findByRole("alert")).toHaveTextContent(
        "Не удалось отобразить задачу",
      );
      expect(recordFrontendEvent).toHaveBeenCalledWith(
        "ui.task_workspace.render_error",
        expect.objectContaining({ task_id: "task-1" }),
        expect.objectContaining({ level: "error" }),
      );
      fireEvent.click(screen.getByRole("button", { name: "К списку задач" }));
      expect(await screen.findByText("Night audit")).toBeInTheDocument();
      fireEvent.doubleClick(screen.getByText("Domain audit").closest("tr"));
      expect(
        await screen.findByRole("heading", { name: "Запуски" }),
      ).toBeInTheDocument();
    } finally {
      consoleError.mockRestore();
    }
  });

  it.each([
    { targets: "10.0.0.1" },
    { targets: ["10.0.0.1"] },
    { targets: [null, "10.0.0.1"] },
  ])("renders job targets supplied as %j", async ({ targets }) => {
    api.mockImplementation(async (path) => {
      if (path === "/api/scanner-task-folders") return { rows: [] };
      if (path.includes("/runs?")) return { items: [{ id: "run-1" }] };
      return { items: [{ id: "job-1", targets }] };
    });
    renderTasks();
    await screen.findByText("Night audit");
    fireEvent.doubleClick(screen.getByText("Night audit").closest("tr"));
    expect(
      await screen.findByRole("cell", { name: "10.0.0.1" }),
    ).toBeInTheDocument();
  });

  it("searches by task name or ID and exposes no extra filters", async () => {
    renderTasks();
    await screen.findByText("Night audit");
    fireEvent.change(
      screen.getByRole("searchbox", { name: "Поиск по задачам" }),
      { target: { value: "task-2" } },
    );
    expect(screen.getByText("Domain audit")).toBeInTheDocument();
    expect(screen.queryByText("Night audit")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Фильтр по статусу"),
    ).not.toBeInTheDocument();
  });

  it("keeps management controls out of the viewer workspace", async () => {
    renderTasks(["tasks.read"]);
    await screen.findByText("Night audit");
    expect(
      screen.queryByRole("button", { name: "Создать папку" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "+ Создать задачу" }),
    ).not.toBeInTheDocument();
  });
});
