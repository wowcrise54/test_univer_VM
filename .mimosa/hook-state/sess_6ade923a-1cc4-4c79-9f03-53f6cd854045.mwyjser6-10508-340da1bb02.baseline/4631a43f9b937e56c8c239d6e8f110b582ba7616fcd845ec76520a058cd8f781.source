import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { RemediationPage } from "../pages/RemediationPage.jsx";
import { VmManagementPage } from "../pages/VmManagementPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn(), createIdempotencyKey: () => "key" }));
const conflict = Object.assign(new Error("stale"), { code: "VERSION_CONFLICT", status: 409 });
beforeEach(() => { api.mockReset(); window.history.replaceState({}, "", "/"); });

it("sends the selected asset context snapshot and blocks overwrite until explicit reread", async () => {
  const writes = [];
  let version = 4;
  api.mockImplementation((path, options) => {
    if (path === "/api/assets/context") { writes.push(JSON.parse(options.body)); version = 5; return Promise.reject(conflict); }
    if (path.startsWith("/api/risk/queue")) return Promise.resolve({ rows: [{ case_id: "c1", asset_id: "a1", cve: "CVE-risk", context_version: version, risk_score: 70, risk_level: "high" }], total: 1 });
    return Promise.resolve({ rows: [], total: 0 });
  });
  render(<RemediationPage showAlert={vi.fn()} />);
  fireEvent.click(screen.getByText("Приоритизация и кампании"));
  fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать CVE-risk" }));
  fireEvent.click(screen.getByRole("button", { name: /Применить к активам/ }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0].expected_versions).toEqual({ a1: 4 });
  expect(await screen.findByRole("button", { name: "Перечитать контекст" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Применить к активам/ })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Перечитать контекст" }));
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Выбрать CVE-risk" })).not.toBeChecked());
  expect(writes).toHaveLength(1);
});

it("campaign preserves its draft after conflict and rereads only on operator request", async () => {
  const writes = [];
  let reads = 0;
  const campaign = { campaign_id: "campaign-1", name: "Campaign", version: 3, status: "draft", cases: [], events: [] };
  api.mockImplementation((path, options) => {
    if (path === "/api/remediation/campaigns/campaign-1") {
      if (options?.method === "PATCH") { writes.push(JSON.parse(options.body)); return Promise.reject(conflict); }
      reads += 1; return Promise.resolve({ ...campaign, name: reads > 1 ? "Other operator" : "Campaign", version: reads > 1 ? 4 : 3 });
    }
    if (path === "/api/remediation/campaigns") return Promise.resolve({ rows: [campaign], total: 1 });
    if (path === "/api/scanner-tasks") return Promise.resolve([]);
    return Promise.resolve({});
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><VmManagementPage session={{ connected: false }} currentUser={{ permissions: ["remediation.read", "risk.manage"] }} showAlert={vi.fn()} /></QueryClientProvider>);
  fireEvent.click(await screen.findByRole("button", { name: /Campaign/ }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.change(await within(dialog).findByLabelText("Название"), { target: { value: "My draft" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0].expected_version).toBe(3);
  expect(within(dialog).getByLabelText("Название")).toHaveValue("My draft");
  expect(await within(dialog).findByRole("button", { name: "Перечитать кампанию" })).toBeInTheDocument();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeDisabled();
  expect(reads).toBe(1);
  fireEvent.click(within(dialog).getByRole("button", { name: "Перечитать кампанию" }));
  await waitFor(() => expect(within(dialog).getByLabelText("Название")).toHaveValue("Other operator"));
  expect(writes).toHaveLength(1);
});

it("successful context saving clears the old selection before another edit", async () => {
  api.mockImplementation((path) => {
    if (path.startsWith("/api/risk/queue")) return Promise.resolve({ rows: [{ case_id: "c1", asset_id: "a1", cve: "CVE-risk", context_version: 4 }], total: 1 });
    return Promise.resolve({ rows: [], total: 0 });
  });
  render(<RemediationPage showAlert={vi.fn()} />);
  fireEvent.click(screen.getByText("Приоритизация и кампании"));
  fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать CVE-risk" }));
  fireEvent.click(screen.getByRole("button", { name: /Применить к активам/ }));
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Выбрать CVE-risk" })).not.toBeChecked());
});

it("selecting another case of the same asset keeps its first context snapshot", async () => {
  const writes = [];
  let version = 4;
  api.mockImplementation((path, options) => {
    if (path === "/api/assets/context") { writes.push(JSON.parse(options.body)); return Promise.resolve({}); }
    if (path.startsWith("/api/risk/queue")) return Promise.resolve({ rows: ["one", "two"].map((cve) => ({ case_id: cve, asset_id: "a1", cve, context_version: version, risk_score: version })), total: 2 });
    return Promise.resolve({ rows: [], total: 0 });
  });
  render(<RemediationPage showAlert={vi.fn()} />);
  fireEvent.click(screen.getByText("Приоритизация и кампании"));
  fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать one" }));
  version = 5;
  fireEvent.change(screen.getByRole("combobox", { name: "Уровень риска" }), { target: { value: "high" } });
  await screen.findAllByText("5");
  fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать two" }));
  fireEvent.click(screen.getByRole("button", { name: /Применить к активам/ }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0].expected_versions).toEqual({ a1: 4 });
});
