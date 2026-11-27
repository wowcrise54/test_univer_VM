import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { McpTokensTab } from "../features/auth/McpTokensTab.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const SCOPES = [
  { key: "vulnerabilities:read", label: "Уязвимости, хосты и паспорта" },
  { key: "risk:read", label: "Приоритеты риска" },
];
const TOKEN = {
  id: 7,
  token_id: "mpvm_mcp_aaaaaaaaaaaa",
  name: "claude-code",
  owner: { id: 1, username: "root", display_name: "Root" },
  scopes: ["vulnerabilities:read"],
  status: "active",
  expires_at: "2026-12-01T00:00:00+00:00",
  last_used_at: null,
  last_used_ip: null,
};
const admin = {
  id: 1,
  username: "root",
  permissions: ["security.mcp_tokens.read", "security.mcp_tokens.manage"],
};
let rows;
let showAlert;

beforeEach(() => {
  rows = [TOKEN];
  showAlert = vi.fn();
  api.mockReset();
  api.mockImplementation(async (path, options = {}) => {
    if (path === "/api/auth/mcp-tokens" && !options.method)
      return { rows, scopes: SCOPES };
    if (path === "/api/auth/mcp-tokens" && options.method === "POST") {
      const body = JSON.parse(options.body);
      return { ...TOKEN, id: 8, name: body.name, token: "mpvm_mcp_bbbbbbbbbbbb_secret" };
    }
    if (path.endsWith("/revoke")) {
      rows = [{ ...TOKEN, status: "revoked" }];
      return rows[0];
    }
    if (path.endsWith("/rotate"))
      return { ...TOKEN, id: 9, token: "mpvm_mcp_cccccccccccc_secret" };
    throw new Error(`unexpected ${path}`);
  });
});

const renderTab = (user = admin) =>
  render(<McpTokensTab currentUser={user} users={[]} showAlert={showAlert} />);

describe("McpTokensTab", () => {
  it("lists tokens without any secret and shows scopes by their labels", async () => {
    renderTab();
    expect(await screen.findByText("claude-code")).toBeInTheDocument();
    expect(screen.getByText("mpvm_mcp_aaaaaaaaaaaa")).toBeInTheDocument();
    expect(
      within(screen.getByRole("table")).getByText("Уязвимости, хосты и паспорта"),
    ).toBeInTheDocument();
    expect(screen.getByText("Действует")).toBeInTheDocument();
    expect(screen.getByText("Не использовался")).toBeInTheDocument();
  });

  it("issues a token with the chosen scopes and shows the secret once", async () => {
    renderTab();
    await screen.findByText("claude-code");
    fireEvent.click(screen.getByText("Новый токен"));
    const submit = screen.getByRole("button", { name: "Выпустить" });
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Название клиента"), {
      target: { value: "cursor" },
    });
    expect(submit).toBeDisabled(); // a token needs at least one scope
    fireEvent.click(screen.getByLabelText("Приоритеты риска"));
    fireEvent.change(screen.getByLabelText("Разрешённые адреса (необязательно)"), {
      target: { value: "10.0.0.0/24, 192.168.1.5" },
    });
    fireEvent.click(submit);

    expect(await screen.findByTestId("issued-token")).toHaveTextContent(
      "mpvm_mcp_bbbbbbbbbbbb_secret",
    );
    const post = api.mock.calls.find(([, options]) => options?.method === "POST");
    expect(JSON.parse(post[1].body)).toEqual({
      name: "cursor",
      scopes: ["risk:read"],
      expires_in_days: 90,
      ip_allowlist: ["10.0.0.0/24", "192.168.1.5"],
    });
    expect(showAlert).toHaveBeenCalledWith("Токен выпущен.", "success");
    fireEvent.click(screen.getByRole("button", { name: "Я сохранил токен" }));
    expect(screen.queryByTestId("issued-token")).not.toBeInTheDocument();
  });

  it("revokes a token only after confirmation", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: "Отозвать токен: claude-code" }));
    const dialog = await screen.findByRole("dialog");
    expect(api.mock.calls.some(([path]) => path.endsWith("/revoke"))).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Отозвать" }));
    await waitFor(() => expect(screen.getByText("Отозван")).toBeInTheDocument());
    expect(api).toHaveBeenCalledWith("/api/auth/mcp-tokens/7/revoke", { method: "POST" });
    expect(screen.queryByRole("button", { name: /Отозвать токен/ })).not.toBeInTheDocument();
  });

  it("rotates a token and shows the replacement secret", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: "Заменить токен: claude-code" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Заменить" }));
    expect(await screen.findByTestId("issued-token")).toHaveTextContent("cccccccccccc");
    expect(api).toHaveBeenCalledWith("/api/auth/mcp-tokens/7/rotate", {
      method: "POST",
      body: JSON.stringify({ grace_hours: 24 }),
    });
  });

  it("is read-only without the manage permission", async () => {
    renderTab({ ...admin, permissions: ["security.mcp_tokens.read"] });
    await screen.findByText("claude-code");
    expect(screen.queryByText("Новый токен")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Отозвать токен/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Заменить токен/ })).not.toBeInTheDocument();
  });

  it("reports a failed request instead of dropping it", async () => {
    api.mockRejectedValueOnce(Object.assign(new Error("boom"), { operatorMessage: "Нет связи." }));
    renderTab();
    await waitFor(() => expect(showAlert).toHaveBeenCalledWith("Нет связи.", "error"));
  });
});
