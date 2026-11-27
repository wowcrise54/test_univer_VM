import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AssetGroupsPage } from "../pages/AssetGroupsPage.jsx";

function renderPage(permissions = ["asset_groups.read", "asset_groups.manage"], showAlert = vi.fn()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><AssetGroupsPage currentUser={{ permissions }} showAlert={showAlert} /></QueryClientProvider>);
}

function response(payload) {
  return Promise.resolve(new Response(JSON.stringify(payload), { status: 200, headers: { "Content-Type": "application/json" } }));
}

afterEach(() => vi.restoreAllMocks());

describe("local asset groups management", () => {
  it("renders and filters the calculated hierarchy", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) {
        return response({ runs: 0, success: 0, false: 0, unknown: 0 });
      }
      if (url.includes("/precheck-runs")) return response({ rows: [] });
      if (url.includes("/fields")) return response({ rows: [] });
      return response({ rows: [{ group_id: "root-1", name: "Infrastructure", status: "ready", member_count: 12, children: [
        { group_id: "group-1", name: "Production Linux", status: "ready", member_count: 4, children: [] },
      ] }] });
    });

    renderPage();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/asset-groups/tree",
      expect.any(Object),
    ));
    expect(await screen.findByRole("button", { name: /Infrastructure/ })).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Поиск групп" }), { target: { value: "Linux" } });
    expect(screen.getByRole("button", { name: /Production Linux/ })).toBeInTheDocument();
  });

  it("hides mutation controls from read-only users", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(() => response({ rows: [] }));

    renderPage(["asset_groups.read"]);
    await waitFor(() => expect(screen.getByText("Групп пока нет.")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Новая динамическая группа" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Создать группу" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Пересчитать выбранные" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Архивировать выбранные" })).not.toBeInTheDocument();
  });

  it("selects groups for a bulk recalculation and shows precheck statistics", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, options) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) return response({ runs: 4, success: 9, false: 3, unknown: 1 });
      if (url.includes("/precheck-runs")) return response({ rows: [] });
      if (url.includes("/fields")) return response({ rows: [] });
      if (url.endsWith("/bulk-action") && options?.method === "POST") {
        return response({ processed: 1, succeeded: 1, failed: 0, results: [] });
      }
      return response({ rows: [{ group_id: "group-1", name: "Production", status: "ready", member_count: 4, children: [] }] });
    });

    const showAlert = vi.fn();
    renderPage(undefined, showAlert);
    expect(screen.getByText("Доступны")).toBeInTheDocument();
    expect(await screen.findByText("9")).toBeInTheDocument();
    expect(screen.getByText("Недоступны: 3")).toBeInTheDocument();
    expect(screen.getByText("Без данных")).toBeInTheDocument();
    // Bulk actions appear only once something is selected.
    expect(screen.queryByRole("button", { name: "Пересчитать выбранные" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Архивировать выбранные" })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать группу Production" }));
    expect(screen.getByText("Выбрано: 1")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Пересчитать выбранные" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/asset-groups/bulk-action"),
      expect.objectContaining({ method: "POST", body: JSON.stringify({ group_ids: ["group-1"], action: "evaluate" }) }),
    ));
    await waitFor(() => expect(showAlert).toHaveBeenCalledWith("Обработано: 1; ошибок: 0.", "success"));
    expect(screen.getByRole("checkbox", { name: "Выбрать группу Production" })).not.toBeChecked();
  });

  it("shows false targets and retries only the selected precheck run", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, options) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) return response({ runs: 1, success: 1, false: 1, unknown: 0 });
      if (url.includes("/precheck-runs")) return response({ rows: [{ mp_task_id: "precheck-1", name: "Precheck", false_targets: ["10.0.0.2"], false_target_count: 1, retryable: true }] });
      if (url.includes("/retry-false") && options?.method === "POST") return response({ requested_target_count: 1, false_target_count: 0 });
      if (url.includes("/fields")) return response({ rows: [] });
      return response({ rows: [] });
    });
    const showAlert = vi.fn();

    renderPage(["asset_groups.read", "tasks.execute"], showAlert);
    fireEvent.click(await screen.findByText("Недоступные хосты · 1"));
    expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Повторить недоступные" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/scanner-tasks/precheck-1/retry-false"),
      expect.objectContaining({ method: "POST" }),
    ));
    await waitFor(() => expect(showAlert).toHaveBeenCalledWith("Повторено: 1; недоступны: 0.", "success"));
  });

  it("starts group scan and remediation verification for executable users", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, options) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) return response({ runs: 0, success: 0, false: 0, unknown: 0 });
      if (url.includes("/precheck-runs")) return response({ rows: [] });
      if (url.includes("/fields")) return response({ rows: [] });
      if (url.includes("/members")) return response({ rows: [], total: 2 });
      if (url.endsWith("/scan") && options?.method === "POST") return response({ workflow_id: "wf-scan", asset_count: 2 });
      if (url.endsWith("/verify") && options?.method === "POST") return response({ workflow_id: "wf-verify", asset_count: 2 });
      return response({ rows: [{ group_id: "group-1", name: "Production", status: "ready", member_count: 2, children: [] }] });
    });
    const showAlert = vi.fn();

    renderPage(["asset_groups.read", "tasks.execute"], showAlert);
    fireEvent.click(await screen.findByRole("button", { name: /Production/ }));
    fireEvent.click(screen.getByRole("button", { name: "Сканировать группу" }));
    fireEvent.click(screen.getByRole("button", { name: "Проверить устранение" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/asset-groups/group-1/scan"),
      expect.objectContaining({ method: "POST" }),
    ));
    await waitFor(() => expect(showAlert).toHaveBeenCalledWith("Сканирование запущено: 2 активов.", "success"));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/asset-groups/group-1/verify"),
      expect.objectContaining({ method: "POST" }),
    ));
    expect(showAlert).toHaveBeenCalledWith("Проверка запущена: 2 активов.", "success");
  });

  it.each([
    { status: "stale", member_count: 2, description: "stale groups" },
    { status: "ready", member_count: 0, description: "empty groups" },
  ])(
    "blocks remote group workflows for $description",
    async ({ status, member_count }) => {
      const fetchMock = vi
        .spyOn(globalThis, "fetch")
        .mockImplementation((input) => {
          const url = String(input);
          if (url.includes("/precheck-stats"))
            return response({ runs: 0, success: 0, false: 0, unknown: 0 });
          if (url.includes("/precheck-runs")) return response({ rows: [] });
          if (url.includes("/fields")) return response({ rows: [] });
          if (url.includes("/members"))
            return response({ rows: [], total: member_count });
          return response({
            rows: [
              {
                group_id: "group-1",
                name: "Production",
                status,
                member_count,
                children: [],
              },
            ],
          });
        });

      renderPage(["asset_groups.read", "tasks.execute"]);
      fireEvent.click(
        await screen.findByRole("button", { name: /Production/ }),
      );

      const scanButton = await screen.findByRole("button", {
        name: "Сканировать группу",
      });
      const verifyButton = screen.getByRole("button", {
        name: "Проверить устранение",
      });
      expect(scanButton).toBeDisabled();
      expect(verifyButton).toBeDisabled();
      fireEvent.click(scanButton);
      fireEvent.click(verifyButton);
      expect(
        fetchMock.mock.calls.some(([input]) =>
          /\/api\/asset-groups\/group-1\/(scan|verify)$/.test(String(input)),
        ),
      ).toBe(false);
    },
  );
});

describe("asset group safeguards", () => {
  afterEach(() => vi.restoreAllMocks());

  it("asks before archiving several groups at once", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, options) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) return response({ runs: 0, success: 0, false: 0, unknown: 0 });
      if (url.includes("/precheck-runs") || url.includes("/fields")) return response({ rows: [] });
      if (url.endsWith("/bulk-action") && options?.method === "POST") return response({ processed: 1, failed: 0 });
      return response({ rows: [{ group_id: "group-1", name: "Production", status: "ready", member_count: 4, children: [] }] });
    });
    renderPage();
    fireEvent.click(await screen.findByRole("checkbox", { name: "Выбрать группу Production" }));
    fireEvent.click(screen.getByRole("button", { name: "Архивировать выбранные" }));

    const dialog = screen.getByRole("dialog", { name: "Архивировать выбранные группы (1)?" });
    expect(fetchMock).not.toHaveBeenCalledWith(expect.stringContaining("/bulk-action"), expect.anything());
    fireEvent.click(within(dialog).getByRole("button", { name: "Архивировать" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/api/asset-groups/bulk-action"),
      expect.objectContaining({ body: JSON.stringify({ group_ids: ["group-1"], action: "archive" }) }),
    ));
  });

  it("describes the group rule in words and opens the create form on demand", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
      const url = String(input);
      if (url.includes("/precheck-stats")) return response({ runs: 0, success: 0, false: 0, unknown: 0 });
      if (url.includes("/precheck-runs") || url.includes("/members")) return response({ rows: [], total: 0 });
      if (url.includes("/fields")) return response({ rows: [{ field_path: "asset.ipAddress", field_name: "IP-адрес" }] });
      return response({ rows: [{ group_id: "group-1", name: "Production", status: "ready", member_count: 0, children: [], query: { combinator: "and", rules: [{ field_path: "asset.ipAddress", operator: "in_cidr", value: "10.0.0.0/8" }] } }] });
    });
    renderPage();
    expect(screen.queryByRole("heading", { name: "Новая динамическая группа" })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: /Production/ }));
    expect(await screen.findByText("IP-адрес входит в подсеть 10.0.0.0/8")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "+ Новая группа" }));
    expect(screen.getByRole("heading", { name: "Новая динамическая группа" })).toBeInTheDocument();
  });
});
