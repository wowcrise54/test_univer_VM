import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { AuthGate } from "../features/auth/AuthGate.jsx";

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
    fireEvent.change(screen.getByLabelText("Имя пользователя"), {
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
    expect(screen.getByText("Используйте доменную учётную запись LDAP.")).toBeInTheDocument();
    expect(screen.getByLabelText("LDAP-логин")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("LDAP-логин"), { target: { value: "CORP\\operator" } });
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
    fireEvent.change(screen.getByLabelText("Имя пользователя"), {
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
