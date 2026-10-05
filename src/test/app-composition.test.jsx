import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { AppProviders } from "../app/providers.jsx";
import {
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { App } from "../app/App.jsx";
import { useAppDataContext } from "../app/AppDataContext.jsx";
import { routes } from "../app/navigation.js";

vi.mock("../api/client.js", async (original) => ({
  ...(await original()),
  api: vi.fn(),
}));
let identity, clients;
beforeEach(() => {
  clients = [];
  identity = {
    id: 1,
    username: "reader",
    display_name: "Read only operator",
    permissions: [
      ...new Set(
        routes
          .flatMap((route) => [
            route.requiredPermission,
            ...(route.requiredAnyPermission || []),
          ])
          .filter(Boolean),
      ),
      "notifications.read",
      "saved_views.read",
    ],
  };
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  const storage = new Map();
  vi.stubGlobal("localStorage", {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  });
  api.mockReset().mockImplementation(async (path) => {
    const endpoint = new URL(path, "http://localhost").pathname;
    if (endpoint === "/api/auth/me") {
      if (!identity)
        throw Object.assign(new Error("Unauthorized"), { status: 401 });
      return { user: identity };
    }
    if (endpoint === "/api/auth/bootstrap-status") return { configured: true };
    if (endpoint === "/api/session")
      return {
        connected: true,
        api_url: "https://vm.example",
        verify_tls: true,
      };
    if (endpoint === "/api/defaults")
      return { client_id: "mpx", utc_offset: "+05:00", scope: "" };
    if (endpoint === "/api/system/status")
      return {
        state: "ok",
        components: Object.fromEntries(
          ["application", "database", "mpvm", "background_workers"].map(
            (key) => [key, { state: "ok" }],
          ),
        ),
      };
    if (endpoint === "/api/scanner-tasks") return [];
    if (endpoint === "/api/operations/summary")
      return { total: 0, active: 0, by_status: {}, by_kind: {} };
    if (endpoint === "/api/vm/overview")
      return { attention: [], recent_workflows: [], active_workflows: 0 };
    if (endpoint === "/api/vulnerabilities/summary")
      return {
        totals: {},
        coverage: { complete: true },
        by_severity: [],
        top_vulnerabilities: [],
        top_hosts: [],
      };
    if (endpoint === "/api/vulnerabilities/trends")
      return {
        rows: [],
        scope: "all_saved_asset_cards",
        bucket: "day",
        retention_days: 90,
      };
    if (endpoint === "/api/remediation/policy")
      return {
        critical_days: 7,
        high_days: 30,
        medium_days: 90,
        low_days: 180,
        near_due_days: 7,
      };
    if (endpoint === "/api/notifications") return { rows: [], unread: 0 };
    if (endpoint.endsWith("/active")) return { job: null };
    return { rows: [], total: 0 };
  });
});
afterEach(() => {
  clients.forEach((client) => client.clear());
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});
function page(path) {
  window.history.replaceState({}, "", path);
  return render(
    <AppProviders>
      <ObservedApp />
    </AppProviders>,
  );
}
function ObservedApp() {
  const client = useQueryClient();
  useEffect(() => {
    clients.push(client);
  }, [client]);
  return <App />;
}
describe("complete application composition", () => {
  it.each(routes.map((route) => [route.path, route.title]))(
    "opens %s with real page components and no runtime errors",
    async (path, title) => {
      page(path);
      await screen.findByRole("heading", { level: 1, name: title });
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      await waitFor(() =>
        expect(api).toHaveBeenCalledWith("/api/system/status"),
      );
      await waitFor(() =>
        expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
      );
      expect(window.location.pathname).toBe(path);
      expect(
        screen.queryByRole("heading", { name: "Раздел не найден" }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("heading", { name: "Раздел недоступен" }),
      ).not.toBeInTheDocument();
    },
  );

  it("does not load workspace data before login", async () => {
    identity = null;
    page("/tasks");
    await screen.findByRole("heading", { name: "Вход в приложение" });
    expect(api.mock.calls.map(([path]) => path)).toEqual([
      "/api/auth/me",
      "/api/auth/bootstrap-status",
    ]);
  });

  it.each(["/tasks", "/users"])(
    "blocks direct navigation to %s without the relevant permissions",
    async (path) => {
      identity.permissions = [];
      page(path);
      await screen.findByRole("heading", { name: "Раздел недоступен" });
      expect(
        screen.getByRole("heading", { level: 1, name: "Нет доступа" }),
      ).toBeInTheDocument();
      expect(api).not.toHaveBeenCalledWith("/api/scanner-tasks");
      expect(api).not.toHaveBeenCalledWith("/api/auth/users");
    },
  );

  it("allows the access section with audit permission alone", async () => {
    identity.permissions = ["security.audit.read"];
    page("/users");
    await screen.findByRole("heading", {
      level: 1,
      name: "Пользователи и роли",
    });
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/auth/audit?limit=200"),
    );
    expect(api).not.toHaveBeenCalledWith("/api/auth/users");
    expect(api).not.toHaveBeenCalledWith("/api/auth/roles");
  });

  it("handles an unknown URL with a recovery navigation", async () => {
    page("/unknown-section");
    await screen.findByRole("heading", { name: "Раздел не найден" });
    fireEvent.click(
      screen.getByRole("link", { name: "Уязвимости", exact: true }),
    );
    await screen.findByRole("heading", { level: 1, name: "Уязвимости" });
    expect(window.location.pathname).toBe("/vulnerabilities");
    expect(
      screen.queryByRole("heading", { name: "Раздел не найден" }),
    ).not.toBeInTheDocument();
  });

  it("logs out through the actual shell and returns to the login form", async () => {
    page("/users");
    await screen.findByRole("heading", {
      level: 1,
      name: "Пользователи и роли",
    });
    fireEvent.click(screen.getByRole("button", { name: "Выйти" }));
    await screen.findByRole("heading", { name: "Вход в приложение" });
    expect(api).toHaveBeenCalledWith("/api/auth/logout", { method: "POST" });
  });

  it("fails explicitly when a consumer is mounted outside its data provider", () => {
    expect(() => renderHook(() => useAppDataContext())).toThrow(
      "useAppDataContext must be used inside AppDataProvider",
    );
  });
});

it("derives the active operation badge from rows when the summary has no active count", async () => {
  const original = api.getMockImplementation();
  api.mockImplementation((path, options) => {
    const endpoint = new URL(path, "http://localhost").pathname;
    if (endpoint === "/api/operations/summary") return Promise.resolve({});
    if (endpoint === "/api/operations")
      return Promise.resolve({
        total: 5,
        rows: [
          "queued",
          "running",
          "cancelling",
          "recovering",
          "completed",
        ].map((status) => ({
          operation_id: `op-${status}`,
          status,
          kind: "scan",
          created_at: "2026-09-30T12:00:00Z",
        })),
      });
    return original(path, options);
  });
  page("/operations");
  await screen.findByTitle("op-completed");
  expect(screen.getByRole("link", { name: "Операции" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  fireEvent.click(screen.getByRole("link", { name: "Задачи" }));
  expect(
    await screen.findByRole("link", { name: "Операции — активных: 4" }),
  ).toHaveAttribute("href", "/operations");
});

it("denies a protected route when the authenticated identity has no permissions field", async () => {
  delete identity.permissions;
  page("/tasks");
  await screen.findByRole("heading", { name: "Нет доступа", level: 1 });
  expect(api).not.toHaveBeenCalledWith("/api/scanner-tasks");
});
