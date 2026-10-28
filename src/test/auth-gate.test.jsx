import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ACCESS_CHANGED_EVENT } from "../api/accessEvents.js";
import { api } from "../api/client.js";
import {
  AuthGate,
  USER_REFRESH_INTERVAL_MS,
  USER_REFRESH_MIN_GAP_MS,
} from "../features/auth/AuthGate.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const USER = {
  id: 1,
  username: "operator",
  display_name: "Operator",
  role: "admin",
  permissions: ["system.read", "operations.read"],
};

function renderGate() {
  return render(<AuthGate>{(auth) => <div>Рабочее пространство · {auth.user.username}</div>}</AuthGate>);
}

describe("AuthGate", () => {
  beforeEach(() => {
    api.mockReset();
  });

  it("renders the workspace with the session user after /api/auth/me succeeds", async () => {
    api.mockImplementation((path) =>
      path === "/api/auth/me"
        ? Promise.resolve({ user: USER })
        : Promise.reject(new Error(path)),
    );
    renderGate();

    expect(await screen.findByText("Рабочее пространство · operator")).toBeInTheDocument();
    expect(api).toHaveBeenCalledWith("/api/auth/me");
  });

  it("shows the login form without an error on 401", async () => {
    const unauthorized = new Error("unauthorized");
    unauthorized.status = 401;
    unauthorized.operatorMessage = "unauthorized";
    api.mockImplementation((path) => {
      if (path === "/api/auth/me") return Promise.reject(unauthorized);
      if (path === "/api/auth/bootstrap-status") return Promise.resolve({ configured: true });
      return Promise.reject(new Error(path));
    });
    renderGate();

    expect(await screen.findByRole("heading", { name: "Вход в приложение" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await waitFor(() => expect(api).toHaveBeenCalledTimes(2));
    expect(api).toHaveBeenCalledWith("/api/auth/bootstrap-status");
  });

  it("keeps the original availability error when bootstrap status is unreachable", async () => {
    const failure = new Error("Сервис приложения недоступен");
    failure.status = 503;
    failure.operatorMessage = "Backend недоступен. Проверьте, что сервис запущен.";
    api.mockImplementation((path) => {
      if (path === "/api/auth/me") return Promise.reject(failure);
      if (path === "/api/auth/bootstrap-status") return Promise.reject(new Error("down"));
      return Promise.reject(new Error(path));
    });
    renderGate();

    expect(await screen.findByRole("heading", { name: "Вход в приложение" })).toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Backend недоступен. Проверьте, что сервис запущен.",
    );
    expect(screen.queryByText(/Первый администратор ещё не создан/)).not.toBeInTheDocument();
    await waitFor(() => expect(api).toHaveBeenCalledTimes(2));
  });

  it("surfaces the operator message for non-401 failures and still offers login", async () => {
    const failure = new Error("Сервис приложения недоступен");
    failure.status = 503;
    failure.operatorMessage = "Backend недоступен. Проверьте, что сервис запущен.";
    api.mockImplementation((path) => {
      if (path === "/api/auth/me") return Promise.reject(failure);
      if (path === "/api/auth/bootstrap-status") return Promise.resolve({ configured: true });
      return Promise.reject(new Error(path));
    });
    renderGate();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Backend недоступен. Проверьте, что сервис запущен.",
    );
  });

  it("blocks login and warns while the bootstrap admin is not configured", async () => {
    const failure = new Error("Сервис приложения недоступен");
    failure.status = 503;
    failure.operatorMessage = "Backend недоступен.";
    api.mockImplementation((path) => {
      if (path === "/api/auth/me") return Promise.reject(failure);
      if (path === "/api/auth/bootstrap-status") return Promise.resolve({ configured: false });
      return Promise.reject(new Error(path));
    });
    renderGate();

    expect(
      await screen.findByText(/Первый администратор ещё не создан/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Войти" })).toBeDisabled();
  });

  it("posts local credentials to /api/auth/login and enters the workspace", async () => {
    api.mockImplementation((path, options) => {
      if (path === "/api/auth/me") {
        const unauthorized = new Error("unauthorized");
        unauthorized.status = 401;
        return Promise.reject(unauthorized);
      }
      if (path === "/api/auth/login") {
        expect(options.method).toBe("POST");
        return Promise.resolve({ user: USER });
      }
      return Promise.reject(new Error(path));
    });
    renderGate();

    await screen.findByRole("heading", { name: "Вход в приложение" });
    fireEvent.change(screen.getByLabelText("Логин"), {
      target: { value: "operator" },
    });
    fireEvent.change(screen.getByLabelText("Пароль"), {
      target: { value: "secret" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(await screen.findByText("Рабочее пространство · operator")).toBeInTheDocument();
    expect(api).toHaveBeenCalledWith(
      "/api/auth/login",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ username: "operator", password: "secret", auth_type: "local" }),
      }),
    );
  });

  it("switches the form copy and payload for LDAP logins", async () => {
    api.mockImplementation((path, options) => {
      if (path === "/api/auth/me") {
        const unauthorized = new Error("unauthorized");
        unauthorized.status = 401;
        return Promise.reject(unauthorized);
      }
      if (path === "/api/auth/login") {
        expect(options.body).toContain('"auth_type":"ldap"');
        return Promise.resolve({ user: USER });
      }
      return Promise.reject(new Error(path));
    });
    renderGate();

    await screen.findByRole("heading", { name: "Вход в приложение" });
    fireEvent.click(screen.getByRole("button", { name: "LDAP" }));
    expect(screen.getByRole("button", { name: "LDAP" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Локально" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.queryByText(/Используйте/)).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Логин"), { target: { value: "CORP\\operator" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "secret" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти через LDAP" }));

    expect(await screen.findByText("Рабочее пространство · operator")).toBeInTheDocument();
  });

  it("shows a failed login error without leaving the form", async () => {
    const rejected = new Error("Неверное имя пользователя или пароль");
    rejected.status = 401;
    rejected.operatorMessage = "Неверное имя пользователя или пароль";
    api.mockImplementation((path) => {
      if (path === "/api/auth/me") return Promise.reject(rejected);
      if (path === "/api/auth/bootstrap-status") return Promise.resolve({ configured: true });
      if (path === "/api/auth/login") return Promise.reject(rejected);
      return Promise.reject(new Error(path));
    });
    renderGate();

    const heading = await screen.findByRole("heading", { name: "Вход в приложение" });
    expect(heading).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Логин"), {
      target: { value: "wrong" },
    });
    fireEvent.change(screen.getByLabelText("Пароль"), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "Неверное имя пользователя или пароль",
      ),
    );
    expect(screen.getByRole("heading", { name: "Вход в приложение" })).toBeInTheDocument();
  });

  it("returns to the login form after logout", async () => {
    api.mockImplementation((path, options) => {
      if (path === "/api/auth/me") return Promise.resolve({ user: USER });
      if (path === "/api/auth/logout") {
        expect(options?.method).toBe("POST");
        return Promise.resolve({ ok: true });
      }
      return Promise.reject(new Error(path));
    });
    let logoutFn = null;
    render(
      <AuthGate>
        {(auth) => {
          logoutFn = auth.logout;
          return <div>Рабочее пространство</div>;
        }}
      </AuthGate>,
    );

    await screen.findByText("Рабочее пространство");
    logoutFn();
    await screen.findByRole("heading", { name: "Вход в приложение" });
    expect(api).toHaveBeenCalledWith("/api/auth/logout", expect.objectContaining({ method: "POST" }));
  });
});

describe("AuthGate keeps the current user's access fresh", () => {
  const ENGINEER = {
    ...USER,
    username: "engineer",
    roles: [{ id: 67, name: "Инженер Windows" }],
    permissions: ["operations.read", "tasks.team"],
  };
  const WIDENED = {
    ...ENGINEER,
    roles: [...ENGINEER.roles, { id: 90, name: "VM-linux" }],
    permissions: ["assets.read", "operations.read", "tasks.team"],
  };
  let responses;
  let renders;

  const meCalls = () => api.mock.calls.filter(([path]) => path === "/api/auth/me").length;
  const advance = (ms) => act(() => vi.advanceTimersByTime(ms));
  const setVisibility = (value) =>
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => value });

  function renderWorkspace() {
    return render(
      <AuthGate>
        {(auth) => {
          renders.push(auth.user);
          return <div>Права: {auth.user.permissions.join(", ")}</div>;
        }}
      </AuthGate>,
    );
  }

  beforeEach(async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    setVisibility("visible");
    renders = [];
    responses = [{ user: ENGINEER }];
    api.mockReset().mockImplementation((path) => {
      if (path !== "/api/auth/me") return Promise.reject(new Error(path));
      const next = responses.length > 1 ? responses.shift() : responses[0];
      return next instanceof Error ? Promise.reject(next) : Promise.resolve(next);
    });
    renderWorkspace();
    await screen.findByText("Права: operations.read, tasks.team");
  });

  afterEach(() => {
    vi.useRealTimers();
    delete document.visibilityState;
  });

  it("re-reads the user after a permission denial and shows the widened access", async () => {
    responses = [{ user: WIDENED }];
    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));

    expect(await screen.findByText("Права: assets.read, operations.read, tasks.team")).toBeInTheDocument();
    expect(meCalls()).toBe(2);
  });

  it("re-reads the user when the browser tab becomes visible or focused again", async () => {
    responses = [{ user: WIDENED }];
    await advance(USER_REFRESH_MIN_GAP_MS);
    setVisibility("hidden");
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(meCalls()).toBe(1);

    setVisibility("visible");
    act(() => document.dispatchEvent(new Event("visibilitychange")));
    expect(await screen.findByText(/assets\.read/)).toBeInTheDocument();
    expect(meCalls()).toBe(2);

    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new Event("focus")));
    await waitFor(() => expect(meCalls()).toBe(3));
  });

  it("polls periodically only while the tab is visible", async () => {
    setVisibility("hidden");
    await advance(USER_REFRESH_INTERVAL_MS);
    expect(meCalls()).toBe(1);

    setVisibility("visible");
    responses = [{ user: WIDENED }];
    await advance(USER_REFRESH_INTERVAL_MS);
    expect(await screen.findByText(/assets\.read/)).toBeInTheDocument();
    expect(meCalls()).toBe(2);
  });

  it("collapses bursts of triggers into one request per minimum gap", async () => {
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));
    expect(meCalls()).toBe(1);

    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => {
      window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT));
      window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT));
      window.dispatchEvent(new Event("focus"));
    });
    await waitFor(() => expect(meCalls()).toBe(2));
  });

  it("keeps the same user object when access is unchanged", async () => {
    const before = renders.at(-1);
    responses = [{ user: { ...ENGINEER, permissions: [...ENGINEER.permissions].reverse() } }];
    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));
    await waitFor(() => expect(meCalls()).toBe(2));

    expect(renders.at(-1)).toBe(before);
  });

  it("returns to the login form with an explanation when the session was revoked", async () => {
    responses = [Object.assign(new Error("unauthorized"), { status: 401 })];
    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));

    expect(await screen.findByRole("heading", { name: "Вход в приложение" })).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Сеанс завершён");
  });

  it("keeps the workspace when the refresh fails for a non-session reason", async () => {
    responses = [Object.assign(new Error("down"), { status: 503 })];
    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));
    await waitFor(() => expect(meCalls()).toBe(2));

    expect(screen.getByText("Права: operations.read, tasks.team")).toBeInTheDocument();
  });

  it("stops refreshing once the session has ended", async () => {
    responses = [Object.assign(new Error("unauthorized"), { status: 401 })];
    await advance(USER_REFRESH_MIN_GAP_MS);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));
    await screen.findByRole("heading", { name: "Вход в приложение" });
    const calls = meCalls();

    await advance(USER_REFRESH_INTERVAL_MS * 2);
    act(() => window.dispatchEvent(new CustomEvent(ACCESS_CHANGED_EVENT)));
    expect(meCalls()).toBe(calls);
  });
});
