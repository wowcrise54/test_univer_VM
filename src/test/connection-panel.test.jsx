import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConnectionPanel } from "../features/connection/index.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const lookups = { credentials: [], scopes: [], scanner_profiles: [], agents: [] };
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

function renderPanel(session) {
  render(
    <ConnectionPanel
      connectionDraft={draft}
      setConnectionDraft={vi.fn()}
      session={session}
      setSession={vi.fn()}
      lookups={lookups}
      setLookups={vi.fn()}
      busy={{}}
      runBusy={vi.fn()}
      showAlert={vi.fn()}
      onNavigate={vi.fn()}
    />,
  );
}

describe("ConnectionPanel env auto-connect state", () => {
  it("explains why the .env auto-connect failed", () => {
    renderPanel({
      connected: false,
      env_connect_error: "Missing authentication fields: username",
    });
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Автоподключение из .env не выполнено: Missing authentication fields: username",
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
