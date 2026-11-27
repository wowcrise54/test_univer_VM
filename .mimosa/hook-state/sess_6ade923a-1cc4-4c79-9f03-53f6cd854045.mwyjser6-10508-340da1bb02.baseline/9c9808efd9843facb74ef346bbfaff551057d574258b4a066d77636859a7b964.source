import { useState } from "react";
import { JSDOM } from "jsdom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { TasksPage } from "../pages/TasksPage.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
  downloadApiFile: vi.fn(),
}));

const draftKey = "mpvm.task-draft.v1";
const auditTask = {
  mp_task_id: "task-1",
  name: "Audit task",
  status: "finished",
  credential_id: "credential-1",
  include_targets: ["10.0.0.1"],
  payload: {
    name: "Audit task",
    description: "Existing audit",
    scope: "scope-1",
    profile: "profile-1",
    include: { targets: ["10.0.0.1"] },
    exclude: { targets: ["10.0.0.2"] },
    agents: { agentIds: ["agent-1"] },
    hostDiscovery: { enabled: true, profile: "profile-1" },
    triggerParameters: { timeZone: "+03:00" },
  },
};
const secondTask = {
  ...auditTask,
  mp_task_id: "task-2",
  name: "Second task",
  payload: { ...auditTask.payload, name: "Second task" },
};
const pageProps = {
  currentUser: { permissions: ["tasks.read", "tasks.manage", "tasks.execute"] },
  defaults: { utc_offset: "+05:00" },
  lookups: {
    scopes: [{ id: "scope-1", name: "Scope" }],
    scanner_profiles: [{ id: "profile-1", name: "Windows Audit" }],
    credentials: [{ id: "credential-1", name: "Credential" }],
  },
  busy: {},
  refreshTasks: vi.fn(),
  runBusy: (_key, action) => action(),
  showAlert: vi.fn(),
  session: { connected: true },
  systemStatus: { components: { database: { state: "ok" } } },
};

function Harness({
  tasks = [auditTask, secondTask],
  initialSelectedId = null,
}) {
  const [selectedTaskId, setSelectedTaskId] = useState(initialSelectedId);
  return (
    <TasksPage
      {...pageProps}
      tasks={tasks}
      selectedTaskId={selectedTaskId}
      selectedTask={
        tasks.find((task) => task.mp_task_id === selectedTaskId) || null
      }
      setSelectedTaskId={setSelectedTaskId}
    />
  );
}

function changeName(value) {
  fireEvent.change(screen.getByLabelText("Название задачи"), {
    target: { value },
  });
}

function selectTask(name = "Audit task") {
  fireEvent.click(screen.getByText(name, { selector: "td strong" }));
}

function openNewTask() {
  fireEvent.click(screen.getByRole("button", { name: /Создать задачу/ }));
}

function openTaskEditor(name = "Audit task") {
  selectTask(name);
  fireEvent.click(screen.getByRole("button", { name: "Изменить" }));
}

describe("task builder drafts", () => {
  beforeEach(() => {
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: new JSDOM("", { url: "https://mpvm.test" }).window.localStorage,
    });
    api.mockReset();
    api.mockResolvedValue({ total: 0, items: [] });
  });

  it("starts an independent clean new task after editing an existing task", () => {
    render(<Harness initialSelectedId="task-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Изменить" }));
    changeName("Unsaved audit edit");
    fireEvent.change(screen.getByLabelText("Таймаут задачи, минут"), {
      target: { value: "45" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openNewTask();

    expect(screen.getByLabelText("Название задачи")).toHaveValue("");
    expect(screen.getByLabelText("Цели сканирования")).toHaveValue("");
    expect(screen.getByLabelText("Инфраструктура / scope")).toHaveValue(
      "scope-1",
    );
    expect(
      screen.getByLabelText("Поиск профиля по имени или ID: выбор"),
    ).toHaveValue("");
    expect(screen.getByLabelText("Учётная запись")).toHaveValue("");
    expect(screen.getByLabelText("Исключить цели")).toHaveValue("");
    expect(screen.getByLabelText("Коллекторы / agents")).toHaveValue("");
    expect(screen.getByLabelText("Часовой пояс")).toHaveValue("+05:00");
    expect(screen.getByLabelText("Таймаут задачи, минут")).toHaveValue(120);
    expect(screen.getByLabelText("Включить hostDiscovery")).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Создать задачу" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Запустить сканирование" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("never replaces the persisted new-task draft with existing-task edits", async () => {
    const view = render(<Harness />);
    openNewTask();
    changeName("New task draft");
    fireEvent.change(screen.getByLabelText("Цели сканирования"), {
      target: { value: "192.0.2.10" },
    });
    await waitFor(() =>
      expect(JSON.parse(window.localStorage.getItem(draftKey))?.form.name).toBe(
        "New task draft",
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openTaskEditor();
    changeName("Existing task edit");
    await new Promise((resolve) => window.setTimeout(resolve, 450));
    view.unmount();
    render(<Harness />);
    openNewTask();
    expect(screen.getByLabelText("Название задачи")).toHaveValue(
      "New task draft",
    );
    expect(screen.getByLabelText("Цели сканирования")).toHaveValue(
      "192.0.2.10",
    );
  });

  it("restores the new draft even when the page initially opens an existing task", async () => {
    window.localStorage.setItem(
      draftKey,
      JSON.stringify({
        version: 1,
        form: { name: "Saved new draft", include_targets: "192.0.2.20" },
      }),
    );
    const view = render(<Harness initialSelectedId="task-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Изменить" }));
    changeName("Existing task edit");
    await new Promise((resolve) => window.setTimeout(resolve, 450));
    view.unmount();
    render(<Harness />);
    openNewTask();
    expect(screen.getByLabelText("Название задачи")).toHaveValue(
      "Saved new draft",
    );
    expect(screen.getByLabelText("Цели сканирования")).toHaveValue(
      "192.0.2.20",
    );
  });

  it("keeps unsaved edits when refresh replaces the selected task object", () => {
    const view = render(<Harness initialSelectedId="task-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Изменить" }));
    changeName("Unsaved edit");
    fireEvent.change(screen.getByLabelText("Цели сканирования"), {
      target: { value: "192.0.2.30" },
    });
    view.rerender(
      <Harness
        initialSelectedId="task-1"
        tasks={[
          {
            ...auditTask,
            status: "running",
            payload: { ...auditTask.payload, name: "Server name" },
          },
          secondTask,
        ]}
      />,
    );
    expect(screen.getByLabelText("Название задачи")).toHaveValue(
      "Unsaved edit",
    );
    expect(screen.getByLabelText("Цели сканирования")).toHaveValue(
      "192.0.2.30",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps separate unsaved edits when switching between existing tasks", () => {
    render(<Harness initialSelectedId="task-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Изменить" }));
    changeName("First edit");
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openTaskEditor("Second task");
    expect(screen.getByLabelText("Название задачи")).toHaveValue("Second task");
    changeName("Second edit");
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openTaskEditor();
    expect(screen.getByLabelText("Название задачи")).toHaveValue("First edit");
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openTaskEditor("Second task");
    expect(screen.getByLabelText("Название задачи")).toHaveValue("Second edit");
  });

  it("persists the explicit clean reset and creates with only the new form parameters", async () => {
    api.mockResolvedValue({ mp_task_id: "new-task" });
    const view = render(<Harness />);
    openNewTask();
    changeName("Old new draft");
    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    openNewTask();
    await waitFor(() =>
      expect(JSON.parse(window.localStorage.getItem(draftKey))?.form.name).toBe(
        "",
      ),
    );
    view.unmount();
    render(<Harness />);
    openNewTask();
    expect(screen.getByLabelText("Название задачи")).toHaveValue("");
    changeName("Independent new task");
    fireEvent.change(screen.getByLabelText("Цели сканирования"), {
      target: { value: "192.0.2.40" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Создать задачу" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/scanner-tasks", {
        method: "POST",
        body: JSON.stringify({
          name: "Independent new task",
          description: "Windows audit vulnerability collection",
          scope_id: "scope-1",
          profile_id: "",
          credential_id: null,
          credential_transport: "windows",
          host_discovery_profile_id: null,
          include_targets: ["192.0.2.40"],
          exclude_targets: [],
          agent_ids: [],
          host_discovery_enabled: false,
          is_fqdn_priority: true,
          time_zone: "+05:00",
          trigger_parameters: null,
          denied_scan_settings: null,
        }),
      }),
    );
  });

  it("serializes the weekly schedule and denied scanning periods", async () => {
    api.mockResolvedValue({ mp_task_id: "scheduled-task" });
    render(<Harness />);
    openNewTask();
    fireEvent.click(screen.getAllByLabelText("Включить")[0]);
    fireEvent.change(screen.getByLabelText("Тип расписания"), {
      target: { value: "Weekly" },
    });
    fireEvent.change(screen.getByLabelText("Время запуска"), {
      target: { value: "01:30" },
    });
    fireEvent.click(screen.getAllByLabelText("Включить")[1]);
    fireEvent.click(screen.getByRole("button", { name: "Создать задачу" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/scanner-tasks",
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const body = JSON.parse(
      api.mock.calls.find(([path]) => path === "/api/scanner-tasks")[1].body,
    );
    expect(body.trigger_parameters).toMatchObject({
      isEnabled: true,
      type: "Weekly",
      atTime: "01:30:00",
      daysOfWeek: expect.arrayContaining(["monday"]),
    });
    expect(body.denied_scan_settings).toMatchObject({
      isEnabled: true,
      periods: [
        {
          daysOfWeek: expect.arrayContaining(["saturday", "sunday"]),
          isAllDay: false,
        },
      ],
    });
  });
});
