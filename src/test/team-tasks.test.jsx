import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { landingPathForUser, routeByPath } from "../app/navigation.js";
import { Sidebar } from "../app/layout.jsx";
import {
  TeamTasksPage,
  isTeamTaskRunning,
  parseTargets,
  teamTaskStatus,
} from "../features/team-tasks/TeamTasksPage.jsx";
import { TaskPresetsPage } from "../features/task-presets/TaskPresetsPage.jsx";
import {
  emptyPresetForm,
  formToPayload,
  presetFormProblems,
  presetToForm,
  templateDraftToForm,
} from "../features/task-presets/presetForm.js";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "key-1"),
  downloadApiFile: vi.fn(),
}));

const PRESET = {
  preset_id: "preset-1",
  name: "Windows audit",
  description: "Аудит серверов Windows",
  os_family: "windows",
  max_groups_per_task: 2,
  trigger_parameters: null,
  allowed_asset_groups: [
    { id: "g-1", name: "Servers", path: "Root / Servers" },
    { id: "g-2", name: "DC", path: "Root / DC" },
    { id: "g-3", name: "Branch", path: "Root / Branch" },
  ],
  role_ids: [10],
  version: 2,
  is_active: true,
  max_active_tasks: 3,
};

const TASK = {
  mp_task_id: "task-1",
  name: "[WIN] Servers",
  preset_name: "Windows audit",
  preset_is_active: true,
  os_family: "windows",
  status: "started",
  created_by: "win.eng",
  updated_at: "2026-10-20T10:00:00Z",
  preset_asset_groups: [{ id: "g-1", name: "Servers", path: "Root / Servers" }],
  postprocess: { status: "monitoring" },
};

function renderWithClient(ui) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>{ui}</QueryClientProvider>,
  );
}

describe("engineer scans page", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation(async (path, options = {}) => {
      if (path === "/api/task-presets") return { rows: [PRESET] };
      if (path === "/api/team-tasks" && !options.method)
        return { rows: [TASK] };
      if (path === "/api/team-tasks" && options.method === "POST")
        return {
          task: { ...TASK, mp_task_id: "task-2", name: "[WIN] DC" },
          start: { status: "started" },
        };
      if (path.endsWith("/runs?limit=10"))
        return { items: [{ id: "run-1", status: "finished" }] };
      if (path.endsWith("/stop")) return {};
      throw new Error(`unexpected ${path}`);
    });
  });

  it("creates and starts a task with only the selected groups", async () => {
    const showAlert = vi.fn();
    renderWithClient(
      <TeamTasksPage
        currentUser={{ permissions: ["tasks.team"] }}
        showAlert={showAlert}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Создать задачу" }),
    );
    const dialog = screen.getByRole("dialog", { name: "Windows audit" });
    const create = within(dialog).getByRole("button", {
      name: "Создать и запустить",
    });
    expect(create).toBeDisabled();

    fireEvent.click(within(dialog).getByLabelText("Root / Servers"));
    fireEvent.click(within(dialog).getByLabelText("Root / DC"));
    fireEvent.click(within(dialog).getByLabelText("Root / Branch"));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("не больше 2");
    expect(create).toBeDisabled();
    fireEvent.click(within(dialog).getByLabelText("Root / Branch"));

    fireEvent.change(
      within(dialog).getByLabelText("Название (необязательно)"),
      {
        target: { value: "Night" },
      },
    );
    fireEvent.click(create);

    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Задача «[WIN] DC» создана и запущена.",
        "success",
      ),
    );
    const [, request] = api.mock.calls.find(
      ([path, options]) => path === "/api/team-tasks" && options?.method,
    );
    expect(JSON.parse(request.body)).toEqual({
      preset_id: "preset-1",
      asset_group_ids: ["g-1", "g-2"],
      targets: [],
      name: "Night",
      description: null,
      start_now: true,
    });
    expect(request.headers["X-Idempotency-Key"]).toBe("key-1:run");
  });

  it("creates a task for IP addresses, subnets and FQDNs typed by the engineer", async () => {
    const showAlert = vi.fn();
    renderWithClient(
      <TeamTasksPage
        currentUser={{ permissions: ["tasks.team"] }}
        showAlert={showAlert}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Создать задачу" }),
    );
    const dialog = screen.getByRole("dialog", { name: "Windows audit" });
    const create = within(dialog).getByRole("button", { name: "Создать" });
    expect(create).toBeDisabled();
    fireEvent.change(
      within(dialog).getByLabelText(
        "IP-адреса, подсети и FQDN для сканирования",
      ),
      { target: { value: "192.168.5.0/24, srv01.corp.local\n10.0.0.15" } },
    );
    expect(within(dialog).getByText(/указано 3/)).toBeInTheDocument();
    expect(create).toBeEnabled();
    fireEvent.click(create);

    await waitFor(() => expect(showAlert).toHaveBeenCalled());
    const [, request] = api.mock.calls.find(
      ([path, options]) => path === "/api/team-tasks" && options?.method,
    );
    expect(JSON.parse(request.body)).toMatchObject({
      asset_group_ids: [],
      targets: ["192.168.5.0/24", "srv01.corp.local", "10.0.0.15"],
      start_now: false,
    });
  });

  it("splits typed targets and drops duplicates", () => {
    expect(
      parseTargets(" 10.0.0.1, srv.corp.local;10.0.1.0/24\n\n10.0.0.1 "),
    ).toEqual(["10.0.0.1", "srv.corp.local", "10.0.1.0/24"]);
    expect(parseTargets("")).toEqual([]);
  });

  it("shows team tasks with status, stop and history", async () => {
    renderWithClient(
      <TeamTasksPage
        currentUser={{ permissions: ["tasks.team"] }}
        showAlert={vi.fn()}
      />,
    );

    expect(await screen.findByText("[WIN] Servers")).toBeInTheDocument();
    expect(screen.getByText("Сканирование идёт")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Удалить" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "История" }));
    expect(await screen.findByText("finished")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Остановить" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/team-tasks/task-1/stop",
        expect.objectContaining({ method: "POST" }),
      ),
    );
  });

  it("explains an empty preset list by role", async () => {
    api.mockImplementation(async () => ({ rows: [] }));
    renderWithClient(
      <TeamTasksPage
        currentUser={{ permissions: ["tasks.team"] }}
        showAlert={vi.fn()}
      />,
    );
    expect(
      await screen.findByText(/Для вашей роли пока нет пресетов/),
    ).toBeInTheDocument();
  });

  it("labels task states", () => {
    expect(teamTaskStatus({ status: "precheck_failed" })).toBe(
      "Хосты недоступны",
    );
    expect(
      teamTaskStatus({
        status: "started",
        postprocess: { status: "completed" },
      }),
    ).toBe("Завершено");
    expect(teamTaskStatus({ status: "custom" })).toBe("custom");
    expect(isTeamTaskRunning({ postprocess: { status: "processing" } })).toBe(
      true,
    );
    expect(isTeamTaskRunning({ status: "started" })).toBe(false);
  });
});

describe("navigation for engineers", () => {
  it("lands engineers on the scans page and hides the operator workspace", () => {
    const engineer = {
      permissions: ["tasks.team", "task_presets.read", "operations.read"],
    };
    expect(landingPathForUser(engineer)).toBe("/scans");
    expect(
      landingPathForUser({ permissions: ["tasks.read", "tasks.team"] }),
    ).toBe("/vm");
    expect(routeByPath("/scans")?.requiredPermission).toBe("tasks.team");
    expect(routeByPath("/task-presets")?.requiredPermission).toBe(
      "task_presets.manage",
    );

    render(
      <Sidebar
        activePath="/scans"
        onNavigate={vi.fn()}
        currentUser={engineer}
      />,
    );
    expect(screen.getByRole("link", { name: "Сканирование" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(
      screen.queryByRole("link", { name: "Задачи" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Пресеты задач" }),
    ).not.toBeInTheDocument();
  });
});

describe("preset form helpers", () => {
  it("maps a preset to the form and back to the API payload", () => {
    const form = presetToForm({
      ...PRESET,
      scope_id: "scope-1",
      profile_id: "profile-1",
      credential_id: "cred-1",
      os_family: "linux",
      start_options: { precheck_enabled: true, precheck_profile_id: "p-2" },
      host_discovery_enabled: false,
      host_discovery_profile_id: "hd-1",
      time_zone: "+03:00",
      name_prefix: "[LNX]",
    });
    const payload = formToPayload({ ...form, max_active_tasks: "" });
    expect(payload).toMatchObject({
      os_family: "linux",
      credential_transport: "ssh",
      host_discovery_profile_id: null,
      start_options: { precheck_enabled: true, precheck_profile_id: "p-2" },
      allowed_asset_groups: [{ id: "g-1" }, { id: "g-2" }, { id: "g-3" }],
      max_active_tasks: null,
      expected_version: 2,
      role_ids: [10],
    });
    expect(formToPayload(emptyPresetForm())).not.toHaveProperty(
      "expected_version",
    );
  });

  it("lists missing required fields", () => {
    expect(presetFormProblems(emptyPresetForm())).toHaveLength(5);
    expect(
      presetFormProblems({ ...emptyPresetForm(), time_zone: "MSK" }),
    ).toContain("Часовой пояс задаётся в формате +05:00.");
    expect(
      presetFormProblems({ ...emptyPresetForm(), host_discovery_enabled: true }),
    ).toContain("Выберите профиль HostDiscovery.");
  });

  it("turns a template draft into a new preset form", () => {
    const form = templateDraftToForm({
      draft: {
        template_id: "linux-safe-pentest",
        name: "Linux. Безопасный пентест",
        os_family: "linux",
        start_options: { precheck_enabled: false, precheck_profile_id: null },
        max_active_tasks: 1,
        role_ids: [11],
      },
      warnings: ["Профиль не найден."],
    });
    expect(form).toMatchObject({
      preset_id: null,
      template_id: "linux-safe-pentest",
      template_warnings: ["Профиль не найден."],
      os_family: "linux",
      precheck_enabled: false,
      max_active_tasks: 1,
      role_ids: [11],
    });
    expect(formToPayload(form)).not.toHaveProperty("template_id");
    expect(templateDraftToForm({})).toMatchObject({
      template_id: null,
      template_warnings: [],
    });
  });
});

const TEMPLATES = {
  rows: [
    {
      template_id: "linux-audit",
      os_family: "linux",
      name: "Linux. Полный аудит",
      purpose: "Полная конфигурация ОС семейства Unix.",
      module: "Audit",
      profile_names: ["Unix SSH Audit"],
      credential: "required",
      credential_hint: "SSH-учётная запись с sudo.",
      precheck_enabled: true,
      max_groups_per_task: 3,
      max_active_tasks: 2,
      notes: ["До 5 минут на актив."],
    },
    {
      template_id: "windows-safe-pentest",
      os_family: "windows",
      name: "Windows. Безопасный пентест",
      purpose: "Уязвимости сетевых служб без учётной записи.",
      module: "Pentest",
      profile_names: ["Safe PenTest"],
      credential: "none",
      credential_hint: "Не нужна.",
      precheck_enabled: false,
      max_groups_per_task: 3,
      max_active_tasks: null,
      notes: [],
    },
  ],
  avoid: [{ profile: "Unsafe PenTest", reason: "DoS-проверки." }],
  docs_url:
    "https://help.ptsecurity.com/ru-RU/projects/vm/28.0/help/7723547531",
};

function templateDraft(templateId) {
  const template = TEMPLATES.rows.find(
    (item) => item.template_id === templateId,
  );
  return {
    draft: {
      template_id: templateId,
      name: template.name,
      os_family: template.os_family,
      scope_id: "scope-1",
      profile_id: "profile-1",
      start_options: {
        precheck_enabled: template.precheck_enabled,
        precheck_profile_id: null,
      },
      allowed_asset_groups: [],
      max_groups_per_task: template.max_groups_per_task,
      max_active_tasks: template.max_active_tasks,
      name_prefix: "[Audit][LNX]",
      role_ids: [10],
    },
    warnings:
      templateId === "linux-audit"
        ? ["Роль «Инженер Linux» не найдена. Отметьте роли вручную."]
        : [],
  };
}

describe("preset administration", () => {
  beforeEach(() => {
    api.mockReset();
    window.history.replaceState({}, "", "/task-presets");
    api.mockImplementation(async (path, options = {}) => {
      if (path === "/api/task-presets" && options.method === "POST")
        return { ...PRESET, name: "New" };
      if (path === "/api/task-presets") return { rows: [PRESET] };
      if (path === "/api/auth/roles")
        return { rows: [{ id: 10, name: "Инженер Windows" }] };
      if (path === "/api/task-presets/lookups")
        return {
          scopes: [{ id: "scope-1", name: "Main" }],
          scanner_profiles: [{ id: "profile-1", name: "Audit" }],
          credentials: [{ id: "cred-1", name: "domain-audit" }],
          agents: [],
        };
      if (path === "/api/task-presets/asset-groups")
        return { rows: PRESET.allowed_asset_groups };
      if (path === "/api/task-presets/templates") return TEMPLATES;
      if (path.startsWith("/api/task-presets/from-template/"))
        return templateDraft(path.split("/").pop());
      if (path.startsWith("/api/task-presets/from-task/"))
        return {
          draft: {
            name: "From task",
            os_family: "windows",
            scope_id: "scope-1",
            profile_id: "profile-1",
            allowed_asset_groups: [{ id: "g-1" }],
          },
        };
      if (path.endsWith("/archive")) return { ...PRESET, is_active: false };
      throw new Error(`unexpected ${path}`);
    });
  });

  it("creates a preset from the form", async () => {
    const showAlert = vi.fn();
    renderWithClient(<TaskPresetsPage showAlert={showAlert} />);
    expect(await screen.findByText("Windows audit")).toBeInTheDocument();
    expect(await screen.findByText("Инженер Windows")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "+ Новый пресет" }));
    const save = screen.getByRole("button", { name: "Сохранить пресет" });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Название"), {
      target: { value: "New" },
    });
    await screen.findByRole("option", { name: "Main" });
    fireEvent.change(screen.getByLabelText("Область (scope)"), {
      target: { value: "scope-1" },
    });
    fireEvent.change(screen.getByLabelText("Профиль сканирования"), {
      target: { value: "profile-1" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: "Инженер Windows" }));
    fireEvent.click(await screen.findByRole("checkbox", { name: "Root / DC" }));
    expect(save).toBeEnabled();
    fireEvent.click(save);

    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Пресет «New» сохранён.",
        "success",
      ),
    );
    const [, request] = api.mock.calls.find(
      ([path, options]) => path === "/api/task-presets" && options?.method,
    );
    expect(JSON.parse(request.body)).toMatchObject({
      name: "New",
      scope_id: "scope-1",
      profile_id: "profile-1",
      role_ids: [10],
      allowed_asset_groups: [{ id: "g-2" }],
      credential_transport: "windows",
    });
  });

  it("fills the editor from a recommended template", async () => {
    const showAlert = vi.fn();
    renderWithClient(<TaskPresetsPage showAlert={showAlert} />);
    expect(await screen.findByText("Linux. Полный аудит")).toBeInTheDocument();
    expect(screen.getByText("Unsafe PenTest")).toBeInTheDocument();
    expect(
      screen.getByRole("link", {
        name: "Рекомендации PT по использованию профилей",
      }),
    ).toHaveAttribute("href", TEMPLATES.docs_url);
    expect(screen.getByText("без лимита")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("ОС"), {
      target: { value: "linux" },
    });
    expect(
      screen.queryByText("Windows. Безопасный пентест"),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Создать пресет по шаблону «Linux. Полный аудит»",
      }),
    );

    expect(
      await screen.findByDisplayValue("Linux. Полный аудит"),
    ).toHaveFocus();
    expect(api).toHaveBeenCalledWith(
      "/api/task-presets/from-template/linux-audit",
      { method: "POST" },
    );
    const hint = screen.getByRole("note", { name: "Рекомендации шаблона" });
    expect(
      within(hint).getByText("Учётная запись: SSH-учётная запись с sudo."),
    ).toBeInTheDocument();
    expect(
      within(hint).getByText(
        "Роль «Инженер Linux» не найдена. Отметьте роли вручную.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByDisplayValue("Linux (SSH)")).toBeInTheDocument();
    expect(screen.getByDisplayValue("[Audit][LNX]")).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: "Проверять доступность хостов (precheck) перед сканированием",
      }),
    ).toBeChecked();
    expect(showAlert).toHaveBeenCalledWith(
      "Черновик заполнен по шаблону. Проверьте предупреждения в форме.",
      "warning",
    );
    expect(
      screen.queryByRole("button", { name: /по шаблону/ }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Отмена" }));
    fireEvent.change(screen.getByLabelText("ОС"), { target: { value: "" } });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Создать пресет по шаблону «Windows. Безопасный пентест»",
      }),
    );
    expect(
      await screen.findByDisplayValue("Windows. Безопасный пентест"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", {
        name: "Проверять доступность хостов (precheck) перед сканированием",
      }),
    ).not.toBeChecked();
    expect(showAlert).toHaveBeenLastCalledWith(
      "Черновик заполнен по шаблону. Проверьте параметры и выберите разрешённые группы.",
      "info",
    );
  });

  it("reports template failures", async () => {
    const showAlert = vi.fn();
    const fallback = api.getMockImplementation();
    api.mockImplementation(async (path, options) => {
      if (path.startsWith("/api/task-presets/from-template/"))
        throw new Error("MP VM не подключён");
      return fallback(path, options);
    });
    const { unmount } = renderWithClient(
      <TaskPresetsPage showAlert={showAlert} />,
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Создать пресет по шаблону «Linux. Полный аудит»",
      }),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith("MP VM не подключён", "error"),
    );
    expect(screen.queryByLabelText("Название")).not.toBeInTheDocument();
    unmount();

    api.mockImplementation(async (path, options) => {
      if (path === "/api/task-presets/templates")
        throw new Error("Каталог недоступен");
      return fallback(path, options);
    });
    renderWithClient(<TaskPresetsPage showAlert={showAlert} />);
    expect(
      await screen.findByText(
        "Не удалось загрузить шаблоны: Каталог недоступен",
      ),
    ).toBeInTheDocument();
  });

  it("prefills the editor from an existing task and archives presets", async () => {
    window.history.replaceState({}, "", "/task-presets?from_task=task-9");
    const showAlert = vi.fn();
    renderWithClient(<TaskPresetsPage showAlert={showAlert} />);
    expect(await screen.findByDisplayValue("From task")).toBeInTheDocument();
    expect(window.location.search).toBe("");
    expect(api).toHaveBeenCalledWith("/api/task-presets/from-task/task-9", {
      method: "POST",
    });

    fireEvent.click(screen.getByRole("button", { name: "В архив" }));
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "В архив",
      }),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Пресет перенесён в архив.",
        "success",
      ),
    );
  });
});
