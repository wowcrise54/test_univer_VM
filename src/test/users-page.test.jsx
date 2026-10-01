import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { UsersPage } from "../features/auth/UsersPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));
const actions = {
  click: (element) => fireEvent.click(element),
  clear: (element) => fireEvent.change(element, { target: { value: "" } }),
  type: (element, value) => fireEvent.change(element, { target: { value } }),
  selectOptions: (element, values) => {
    const selected = new Set(Array.isArray(values) ? values : [values]);
    for (const option of element.options)
      option.selected = selected.has(option.value);
    fireEvent.change(element);
  },
};
const READ = [
  "security.users.read",
  "security.roles.read",
  "security.audit.read",
];
const MANAGE = [...READ, "security.users.manage", "security.roles.manage"];
let data;
let showAlert;
const groupBy = Object.getOwnPropertyDescriptor(Object, "groupBy");
beforeEach(() => {
  showAlert = vi.fn();
  data = {
    "/api/auth/users": {
      rows: [
        {
          id: 1,
          username: "admin",
          display_name: "Current administrator",
          is_active: true,
          roles: [{ id: 10 }],
          last_login_at: "2026-09-30T10:00:00Z",
        },
        {
          id: 2,
          username: "operator",
          display_name: "Other operator",
          is_active: false,
        },
      ],
    },
    "/api/auth/roles": {
      rows: [
        {
          id: 10,
          name: "System admin",
          description: "Built in",
          permission_keys: ["assets.read"],
          is_system: true,
          user_count: 1,
        },
        {
          id: 11,
          name: "Custom reader",
          description: "Custom role",
          permission_keys: ["assets.read"],
          is_system: false,
          user_count: 0,
        },
      ],
    },
    "/api/auth/permissions": {
      rows: [
        { key: "assets.read", description: "Read assets", domain: "assets" },
        { key: "assets.manage", description: "Edit assets", domain: "assets" },
        { key: "tasks.read", description: "Read tasks", domain: "tasks" },
      ],
    },
    "/api/auth/audit?limit=200": {
      rows: [
        {
          id: 1,
          created_at: "2026-09-30T10:00:00Z",
          actor_username: "operator",
          event_type: "role_updated",
          decision: "allow",
          permission_key: "security.roles.manage",
          target_id: "11",
        },
        {
          id: 2,
          created_at: "2026-09-30T10:00:00Z",
          event_type: "access_denied",
          decision: "deny",
        },
      ],
    },
  };
  api.mockReset().mockImplementation(async (path, options) => {
    if (options?.method) return { ok: true };
    if (data[path] instanceof Error) throw data[path];
    if (data[path]) return data[path];
    throw new Error(`Unexpected request: ${path}`);
  });
});
afterEach(() => {
  if (groupBy) Object.defineProperty(Object, "groupBy", groupBy);
  else delete Object.groupBy;
});
function page(permissions = MANAGE) {
  return render(
    <UsersPage currentUser={{ id: 1, permissions }} showAlert={showAlert} />,
  );
}
function rowFor(name) {
  return screen.getByText(name).closest("tr");
}
async function roles() {
  await actions.click(
    screen.getByRole("button", { name: "Роли", exact: true }),
  );
  await screen.findByDisplayValue("System admin");
}
async function customRole() {
  await roles();
  await actions.click(screen.getByRole("button", { name: /Custom reader/ }));
  await screen.findByDisplayValue("Custom reader");
}
function mutation(path, method) {
  return api.mock.calls.find(
    ([url, options]) => url === path && options?.method === method,
  )?.[1];
}

describe("user access management", () => {
  it("shows insufficient access without requesting protected data", async () => {
    page([]);
    expect(screen.getByText("Недостаточно прав.")).toBeInTheDocument();
    await waitFor(() => expect(api).not.toHaveBeenCalled());
  });

  it("allows reading users without exposing mutation controls or requesting role data", async () => {
    page(["security.users.read"]);
    await screen.findByText("Other operator");
    expect(screen.queryByText("Новый пользователь")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Отключить" }),
    ).not.toBeInTheDocument();
    expect(
      within(rowFor("Other operator")).getByRole("listbox"),
    ).toBeDisabled();
    expect(api).toHaveBeenCalledTimes(1);
    expect(api).toHaveBeenCalledWith("/api/auth/users");
  });

  it("protects the current account and updates another user's roles and active state", async () => {
    page();
    await screen.findByText("Other operator");
    const current = within(rowFor("Current administrator"));
    expect(current.getByRole("listbox")).toBeDisabled();
    expect(current.getByRole("button", { name: "Отключить" })).toBeDisabled();
    const other = within(rowFor("Other operator"));
    await actions.selectOptions(other.getByRole("listbox"), ["10", "11"]);
    await waitFor(() =>
      expect(mutation("/api/auth/users/2", "PATCH")).toBeDefined(),
    );
    expect(JSON.parse(mutation("/api/auth/users/2", "PATCH").body)).toEqual({
      role_ids: [10, 11],
    });
    api.mockClear();
    await actions.click(other.getByRole("button", { name: "Включить" }));
    await waitFor(() =>
      expect(JSON.parse(mutation("/api/auth/users/2", "PATCH").body)).toEqual({
        is_active: true,
      }),
    );
    expect(showAlert).not.toHaveBeenCalled();
  });

  it("creates a user with numeric role IDs and resets the form after submission", async () => {
    page();
    await screen.findByText("Other operator");
    await actions.click(screen.getByText("Новый пользователь"));
    expect(screen.getByRole("button", { name: "Создать" })).toBeDisabled();
    await actions.type(screen.getByLabelText("Логин"), "new-operator");
    await actions.type(
      screen.getByLabelText("Имя", { exact: true }),
      "New Operator",
    );
    await actions.type(screen.getByLabelText("Пароль"), "fixture-password");
    await actions.selectOptions(
      screen.getByLabelText("Роли", { exact: true }),
      "11",
    );
    await actions.click(screen.getByRole("button", { name: "Создать" }));
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith("Пользователь создан.", "success"),
    );
    expect(JSON.parse(mutation("/api/auth/users", "POST").body)).toEqual({
      username: "new-operator",
      display_name: "New Operator",
      password: "fixture-password",
      role_ids: [11],
    });
    expect(screen.getByLabelText("Логин")).toHaveValue("");
    expect(screen.getByLabelText("Пароль")).toHaveValue("");
  });

  it.each([true, false])(
    "reports load failure using operator detail when available (%s)",
    async (operatorDetail) => {
      const error = new Error("Request failed");
      if (operatorDetail)
        error.operatorMessage = "Users temporarily unavailable";
      data["/api/auth/users"] = error;
      page();
      await waitFor(() =>
        expect(showAlert).toHaveBeenCalledWith(
          operatorDetail ? "Users temporarily unavailable" : "Request failed",
          "error",
        ),
      );
    },
  );

  it("reports a mutation failure and does not announce success", async () => {
    const original = api.getMockImplementation();
    api.mockImplementation((path, options) =>
      options?.method
        ? Promise.reject(
            Object.assign(new Error("Conflict"), {
              operatorMessage: "Account changed by another operator",
            }),
          )
        : original(path, options),
    );
    page();
    await screen.findByText("Other operator");
    await actions.click(
      within(rowFor("Other operator")).getByRole("button", {
        name: "Включить",
      }),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith(
        "Account changed by another operator",
        "error",
      ),
    );
    expect(showAlert).toHaveBeenCalledTimes(1);
  });
});

describe("role editing and cloning", () => {
  it("starts on roles when users cannot be read and keeps system roles immutable", async () => {
    page(["security.roles.read", "security.roles.manage"]);
    await screen.findByDisplayValue("System admin");
    expect(screen.getByLabelText("Название")).toBeDisabled();
    expect(screen.getByLabelText("Описание")).toBeDisabled();
    screen
      .getAllByRole("checkbox")
      .forEach((input) => expect(input).toBeDisabled());
    expect(
      screen.queryByRole("button", { name: "Сохранить" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Системная роль неизменяема/)).toBeInTheDocument();
    expect(api).not.toHaveBeenCalledWith("/api/auth/users");
  });

  it("keeps custom roles read only without management permission", async () => {
    page(READ);
    await customRole();
    expect(screen.getByLabelText("Название")).toBeDisabled();
    expect(screen.queryByText("Клонировать роль")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Сохранить" }),
    ).not.toBeInTheDocument();
  });

  it.each([true, false])(
    "saves role details and both added and removed permissions with groupBy available=%s",
    async (available) => {
      if (available)
        Object.defineProperty(Object, "groupBy", {
          configurable: true,
          value: (items, key) =>
            items.reduce((all, item) => {
              (all[key(item)] ||= []).push(item);
              return all;
            }, {}),
        });
      else
        Object.defineProperty(Object, "groupBy", {
          configurable: true,
          value: undefined,
        });
      page();
      await customRole();
      await actions.clear(screen.getByLabelText("Название"));
      await actions.type(screen.getByLabelText("Название"), "Limited operator");
      await actions.clear(screen.getByLabelText("Описание"));
      await actions.type(screen.getByLabelText("Описание"), "Only task access");
      await actions.click(
        screen.getByRole("checkbox", { name: /assets.read/ }),
      );
      await actions.click(screen.getByRole("checkbox", { name: /tasks.read/ }));
      await actions.click(screen.getByRole("button", { name: "Сохранить" }));
      await waitFor(() =>
        expect(showAlert).toHaveBeenCalledWith("Роль сохранена.", "success"),
      );
      expect(JSON.parse(mutation("/api/auth/roles/11", "PATCH").body)).toEqual({
        name: "Limited operator",
        description: "Only task access",
        permission_keys: ["tasks.read"],
      });
      expect(screen.getByRole("group", { name: "assets" })).toBeInTheDocument();
      expect(screen.getByRole("group", { name: "tasks" })).toBeInTheDocument();
    },
  );

  it("clones a system role with a numeric source ID and resets the clone draft", async () => {
    page();
    await roles();
    await actions.click(screen.getByText("Клонировать роль"));
    const cloneForm = screen
      .getByRole("button", { name: "Клонировать", exact: true })
      .closest("form");
    await actions.selectOptions(within(cloneForm).getByRole("combobox"), "10");
    await actions.type(
      screen.getByPlaceholderText("Название новой роли"),
      "Scoped admin",
    );
    await actions.click(
      within(cloneForm).getByRole("button", {
        name: "Клонировать",
        exact: true,
      }),
    );
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith("Роль создана.", "success"),
    );
    expect(JSON.parse(mutation("/api/auth/roles/clone", "POST").body)).toEqual({
      source_role_id: 10,
      name: "Scoped admin",
      description: "",
    });
    expect(screen.getByPlaceholderText("Название новой роли")).toHaveValue("");
  });

  it("requires the role name for deletion and closes the dialog after the request", async () => {
    page();
    await customRole();
    await actions.click(screen.getByText("Ещё", { exact: true }));
    await actions.click(screen.getByRole("button", { name: "Удалить роль" }));
    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByRole("button", { name: "Удалить роль" })).toBeDisabled();
    fireEvent.change(dialog.getByRole("textbox"), {
      target: { value: "Custom reader" },
    });
    await actions.click(dialog.getByRole("button", { name: "Удалить роль" }));
    await waitFor(() =>
      expect(showAlert).toHaveBeenCalledWith("Роль удалена.", "success"),
    );
    expect(mutation("/api/auth/roles/11", "DELETE")).toEqual({
      method: "DELETE",
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("can cancel a role deletion without sending a request", async () => {
    page();
    await customRole();
    await actions.click(screen.getByText("Ещё", { exact: true }));
    await actions.click(screen.getByRole("button", { name: "Удалить роль" }));
    await actions.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Отмена",
      }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(mutation("/api/auth/roles/11", "DELETE")).toBeUndefined();
  });

  it("handles an empty role and permission response", async () => {
    data["/api/auth/roles"] = {};
    data["/api/auth/permissions"] = {};
    page(["security.roles.read"]);
    expect(await screen.findByText("Роли не найдены.")).toBeInTheDocument();
  });
});

describe("security audit view", () => {
  it("starts on audit when that is the only readable resource", async () => {
    page(["security.audit.read"]);
    await screen.findByText("role_updated");
    expect(screen.getByText("Разрешено")).toBeInTheDocument();
    expect(screen.getByText("Отклонено")).toBeInTheDocument();
    expect(screen.getByText("security.roles.manage")).toBeInTheDocument();
    expect(api).toHaveBeenCalledTimes(1);
  });

  it.each([true, false])(
    "reports audit failure using operator detail when available (%s)",
    async (operatorDetail) => {
      const error = new Error("Audit request failed");
      if (operatorDetail) error.operatorMessage = "Audit unavailable";
      data["/api/auth/audit?limit=200"] = error;
      page();
      await actions.click(
        screen.getByRole("button", { name: "Аудит", exact: true }),
      );
      await waitFor(() =>
        expect(showAlert).toHaveBeenCalledWith(
          operatorDetail ? "Audit unavailable" : "Audit request failed",
          "error",
        ),
      );
    },
  );

  it("handles audit and user responses without rows", async () => {
    data["/api/auth/users"] = {};
    data["/api/auth/audit?limit=200"] = {};
    page();
    await actions.click(
      screen.getByRole("button", { name: "Аудит", exact: true }),
    );
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/auth/audit?limit=200"),
    );
    expect(screen.getAllByRole("row")).toHaveLength(1);
  });
});

it("returns from audit to the users tab and reports plain mutation errors", async () => {
  const original = api.getMockImplementation();
  api.mockImplementation((path, options) =>
    options?.method
      ? Promise.reject(new Error("Account update failed"))
      : original(path, options),
  );
  page();
  await screen.findByText("Other operator");
  fireEvent.click(screen.getByRole("button", { name: "Аудит", exact: true }));
  await screen.findByText("role_updated");
  fireEvent.click(
    screen.getByRole("button", { name: "Пользователи", exact: true }),
  );
  fireEvent.click(
    within(rowFor("Other operator")).getByRole("button", { name: "Включить" }),
  );
  await waitFor(() =>
    expect(showAlert).toHaveBeenCalledWith("Account update failed", "error"),
  );
});
