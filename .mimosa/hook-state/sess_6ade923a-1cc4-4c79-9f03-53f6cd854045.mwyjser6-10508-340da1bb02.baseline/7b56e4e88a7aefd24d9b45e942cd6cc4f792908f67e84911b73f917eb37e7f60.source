import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { VulnerabilitiesDashboard } from "../features/vulnerabilities/index.jsx";
import { routeByPath } from "../app/navigation.js";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));
const finding = {
  selector: "id:one",
  name: "Уязвимость выборки",
  severity: "high",
  affected_hosts: 1,
  findings: 2,
  sources: ["os"],
};
function renderView(mode = "vulnerabilities", onNavigate = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <VulnerabilitiesDashboard
        mode={mode}
        onNavigate={onNavigate}
        currentUser={{ permissions: ["assets.read", "remediation.read"] }}
      />
    </QueryClientProvider>,
  );
}
function callsFor(path) {
  return api.mock.calls
    .map(([value]) => new URL(value, "http://localhost"))
    .filter((url) => url.pathname === path);
}
async function apply() {
  fireEvent.click(
    await screen.findByRole("button", { name: "Применить фильтры" }),
  );
}
describe("applied vulnerability selection", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/vulnerabilities");
    api.mockReset();
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities/summary")
        return Promise.resolve({
          totals: { unique_vulnerabilities: 75 },
          coverage: { complete: true },
          by_severity: [{ severity: "high", findings: 2 }],
          top_vulnerabilities: [finding],
          top_hosts: [
            { asset_id: "asset-a", display_name: "host-a", findings: 2 },
          ],
        });
      if (url.pathname === "/api/vulnerabilities")
        return Promise.resolve({ rows: [finding], total: 75 });
      if (url.pathname === "/api/vulnerabilities/hosts")
        return Promise.resolve({
          rows: [
            { asset_id: "asset-a", display_name: "host-a", severity: "high" },
          ],
          total: 1,
        });
      return Promise.resolve({ rows: [] });
    });
  });
  it("does not query results before apply and keeps global analytics out of the selection", async () => {
    renderView();
    await waitFor(() =>
      expect(callsFor("/api/asset-cards/local")).toHaveLength(1),
    );
    expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(0);
    expect(callsFor("/api/vulnerabilities")).toHaveLength(0);
    expect(callsFor("/api/vulnerabilities/trends")).toHaveLength(0);
    expect(callsFor("/api/vulnerabilities/trending")).toHaveLength(0);
    expect(screen.queryByText("История риска")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Контроль и отчёты" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Все уязвимости" }),
    ).not.toBeInTheDocument();
    await apply();
    expect(
      await screen.findByRole("heading", { name: "Все уязвимости" }),
    ).toBeInTheDocument();
    expect(callsFor("/api/vulnerabilities")).toHaveLength(1);
    expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(1);
    expect(callsFor("/api/vulnerabilities/trends")).toHaveLength(0);
    expect(callsFor("/api/vulnerabilities/trending")).toHaveLength(0);
  });
  it("preserves the asset across summary list hosts and pagination while draft edits stay unapplied", async () => {
    renderView();
    fireEvent.change(screen.getByLabelText("Актив", { exact: true }), {
      target: { value: "asset-a" },
    });
    await apply();
    const buttons = await screen.findAllByRole("button", {
      name: "Показать хосты с уязвимостью Уязвимость выборки",
    });
    expect(
      callsFor("/api/vulnerabilities/summary")[0].searchParams.get("asset_id"),
    ).toBe("asset-a");
    expect(
      callsFor("/api/vulnerabilities")[0].searchParams.get("asset_id"),
    ).toBe("asset-a");
    fireEvent.change(screen.getByLabelText("Актив", { exact: true }), {
      target: { value: "asset-b" },
    });
    fireEvent.click(buttons.at(-1));
    await screen.findByRole("heading", {
      name: "Хосты с уязвимостью «Уязвимость выборки»",
    });
    await waitFor(() =>
      expect(
        callsFor("/api/vulnerabilities/hosts")[0].searchParams.get("asset_id"),
      ).toBe("asset-a"),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Уязвимости: следующая страница" }),
    );
    await waitFor(() =>
      expect(
        callsFor("/api/vulnerabilities").at(-1).searchParams.get("offset"),
      ).toBe("50"),
    );
    expect(
      callsFor("/api/vulnerabilities").at(-1).searchParams.get("asset_id"),
    ).toBe("asset-a");
    expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(1);
    expect(callsFor("/api/vulnerabilities/trends")).toHaveLength(0);
    expect(callsFor("/api/vulnerabilities/trending")).toHaveLength(0);
  });
  it("refreshes an identical applied selection and resets pagination", async () => {
    renderView();
    await apply();
    await screen.findByRole("heading", { name: "Все уязвимости" });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Применить фильтры" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Уязвимости: следующая страница" }),
    );
    await waitFor(() =>
      expect(
        callsFor("/api/vulnerabilities").at(-1).searchParams.get("offset"),
      ).toBe("50"),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Применить фильтры" }),
      ).toBeEnabled(),
    );
    const summaryCalls = callsFor("/api/vulnerabilities/summary").length;
    await apply();
    await waitFor(() =>
      expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(
        summaryCalls + 1,
      ),
    );
    expect(
      callsFor("/api/vulnerabilities").at(-1).searchParams.get("offset"),
    ).toBe("0");
  });
  it("keeps dashboards global and navigates to an editable working selection", async () => {
    const onNavigate = vi.fn();
    renderView("dashboards", onNavigate);
    await screen.findByText("Хосты с уязвимостями");
    expect(callsFor("/api/vulnerabilities/trends")).toHaveLength(1);
    expect(callsFor("/api/vulnerabilities/trending")).toHaveLength(1);
    expect(callsFor("/api/vulnerabilities")).toHaveLength(0);
    expect(
      screen.queryByRole("combobox", { name: "Актив" }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Показать хосты с уязвимостью Уязвимость выборки",
      }),
    );
    expect(onNavigate).toHaveBeenCalledWith(
      "/vulnerabilities?q=%D0%A3%D1%8F%D0%B7%D0%B2%D0%B8%D0%BC%D0%BE%D1%81%D1%82%D1%8C+%D0%B2%D1%8B%D0%B1%D0%BE%D1%80%D0%BA%D0%B8",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Показать уязвимости актива host-a" }),
    );
    expect(onNavigate).toHaveBeenCalledWith(
      "/vulnerabilities?asset_id=asset-a",
    );
    expect(routeByPath("/dashboards").requiredPermission).toBe("assets.read");
  });
  it("resets only the draft and applies changed conditions to a fresh result", async () => {
    renderView();
    fireEvent.change(screen.getByLabelText("Актив", { exact: true }), {
      target: { value: "asset-a" },
    });
    await apply();
    await screen.findByRole("heading", { name: "Все уязвимости" });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Сбросить" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Сбросить" }));
    expect(screen.getByLabelText("Актив", { exact: true })).toHaveValue("");
    expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(1);
    expect(
      screen.getByRole("heading", { name: "Все уязвимости" }),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Актив", { exact: true }), {
      target: { value: "asset-b" },
    });
    await apply();
    await waitFor(() =>
      expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(2),
    );
    expect(
      callsFor("/api/vulnerabilities/summary")
        .at(-1)
        .searchParams.get("asset_id"),
    ).toBe("asset-b");
    const buttons = await screen.findAllByRole("button", {
      name: "Показать хосты с уязвимостью Уязвимость выборки",
    });
    fireEvent.click(buttons.at(-1));
    await waitFor(() =>
      expect(
        callsFor("/api/vulnerabilities/hosts")[0].searchParams.get("asset_id"),
      ).toBe("asset-b"),
    );
  });
  it("prefills deep links without fetching the selection before apply", async () => {
    window.history.replaceState(
      {},
      "",
      "/vulnerabilities?asset_id=asset-a&q=CVE-2026",
    );
    renderView();
    expect(screen.getByLabelText("Актив", { exact: true })).toHaveValue(
      "asset-a",
    );
    expect(screen.getByRole("textbox", { name: "Уязвимость" })).toHaveValue(
      "CVE-2026",
    );
    await waitFor(() =>
      expect(callsFor("/api/asset-cards/local")).toHaveLength(1),
    );
    expect(callsFor("/api/vulnerabilities/summary")).toHaveLength(0);
    await apply();
    await screen.findByRole("heading", { name: "Все уязвимости" });
    expect(
      callsFor("/api/vulnerabilities/summary")[0].searchParams.get("q"),
    ).toBe("CVE-2026");
  });
});
