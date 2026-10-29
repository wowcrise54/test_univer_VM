import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { ConnectionPanel } from "../features/connection/index.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const lookups = {
  credentials: [],
  scopes: [],
  scanner_profiles: [],
  agents: [],
};
const draft = {
  api_url: "https://vm.example",
  token_url: "",
  username: "",
  password: "",
  client_id: "mpx",
  client_secret: "",
  scope: "",
  access_token: "",
  verify_tls: true,
};

function renderPanel(session, extra = {}) {
  const props = {
    refreshLookups: vi.fn(async () => lookups),
    showAlert: vi.fn(),
    runBusy: vi.fn(async (_key, action) => action()),
    ...extra,
  };
  render(
    <ConnectionPanel
      connectionDraft={draft}
      setConnectionDraft={vi.fn()}
      session={session}
      setSession={vi.fn()}
      lookups={lookups}
      setLookups={vi.fn()}
      busy={{}}
      onNavigate={vi.fn()}
      {...props}
    />,
  );
  return props;
}

describe("ConnectionPanel env auto-connect state", () => {
  it("explains why the .env auto-connect failed", () => {
    renderPanel({
      connected: false,
      env_connect_error: "Missing authentication fields: username",
    });
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Автоподключение не выполнено: Missing authentication fields: username",
    );
  });

  it("hides the failure once the session is connected", () => {
    renderPanel({
      connected: true,
      api_url: "https://vm.example",
      env_connect_error: "stale",
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("https://vm.example")).toBeInTheDocument();
  });
});

describe("ConnectionPanel lookups", () => {
  const connected = { connected: true, api_url: "https://vm.example" };

  it("shows when lookups were refreshed automatically", () => {
    renderPanel(connected, { lookupsUpdatedAt: "2026-10-26T10:15:00.000Z" });
    expect(screen.getByText(/Справочники обновлены/)).toBeInTheDocument();
  });

  it("reports a failed background refresh", () => {
    renderPanel(connected, { lookupsError: new Error("MP VM timeout") });
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Не удалось обновить справочники: MP VM timeout",
    );
  });

  it("refreshes through the shared lookups query on demand", async () => {
    const props = renderPanel(connected);
    fireEvent.click(
      screen.getByRole("button", { name: "Обновить справочники" }),
    );
    await waitFor(() => expect(props.refreshLookups).toHaveBeenCalledTimes(1));
    expect(props.showAlert).toHaveBeenCalledWith(
      expect.stringContaining("Справочники обновлены"),
      "success",
    );
    expect(api).not.toHaveBeenCalledWith("/api/mpvm/lookups");
  });

  it("does not issue a separate lookups request after a manual connect", async () => {
    api
      .mockReset()
      .mockResolvedValue({ connected: true, api_url: "https://vm.example" });
    const props = renderPanel({ connected: false });
    fireEvent.click(screen.getByRole("button", { name: "Подключиться" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/session/connect",
        expect.any(Object),
      ),
    );
    expect(api).toHaveBeenCalledTimes(1);
    expect(props.refreshLookups).not.toHaveBeenCalled();
  });
});
