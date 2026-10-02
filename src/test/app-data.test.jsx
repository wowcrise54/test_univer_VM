import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { useAppData } from "../app/useAppData.js";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));
const healthy = { state: "ok", components: { database: { state: "ok" } } };
let responses;
let clients;
beforeEach(() => {
  clients = [];
  responses = {
    "/api/defaults": { api_url: "https://vm.example", scope: "read" },
    "/api/session": {
      connected: true,
      username: "operator",
      verify_tls: false,
    },
    "/api/system/status": healthy,
    "/api/operations/summary": { active: 0 },
    "/api/scanner-tasks": [{ mp_task_id: "task-1", name: "First" }],
    "/api/assets/summary": { total: 1 },
  };
  api.mockReset().mockImplementation(async (path) => {
    const value = responses[path];
    if (value instanceof Error) throw value;
    if (value !== undefined) return value;
    if (path.startsWith("/api/operations?")) return { rows: [], total: 0 };
    if (path.startsWith("/api/assets?"))
      return { rows: [{ asset_id: "a-1" }], total: 1 };
    throw new Error(`Unexpected API request: ${path}`);
  });
});
afterEach(() => {
  clients.forEach((client) => client.clear());
  vi.useRealTimers();
});
function harness(route = "tasks") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  clients.push(client);
  const wrapper = ({ children }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return {
    ...renderHook(({ currentRoute }) => useAppData(currentRoute), {
      wrapper,
      initialProps: { currentRoute: route },
    }),
    client,
  };
}
async function ready(result) {
  await waitFor(() => expect(result.current.systemStatus).not.toBeNull());
  await waitFor(() => expect(result.current.session.connected).toBe(true));
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

describe("application data loading and recovery", () => {
  it("loads connection defaults and session metadata without requiring task selection", async () => {
    const { result } = harness();
    await ready(result);
    await waitFor(() => expect(result.current.tasks).toHaveLength(1));
    expect(result.current.selectedTask).toBeNull();
    expect(result.current.connectionDraft).toMatchObject({
      api_url: "https://vm.example",
      username: "operator",
      client_id: "mpx",
      scope: "read",
      verify_tls: false,
    });
    act(() => result.current.setSelectedTaskId("task-1"));
    expect(result.current.selectedTask.name).toBe("First");
    act(() => result.current.setSelectedTaskId("missing"));
    expect(result.current.selectedTask).toBeNull();
  });

  it("keeps edited credentials when refreshed defaults omit fields", async () => {
    responses["/api/defaults"] = {};
    responses["/api/session"] = {
      connected: true,
      api_url: "https://session.example",
      token_url: "https://session.example/token",
    };
    const { result, client } = harness("forbidden");
    await ready(result);
    act(() =>
      result.current.setConnectionDraft((draft) => ({
        ...draft,
        api_url: "https://edited.example",
        client_id: "custom",
        scope: "custom-scope",
      })),
    );
    act(() =>
      client.setQueryData(["defaults"], {
        api_url: "https://default.example",
        client_id: "other",
        scope: "other",
      }),
    );
    await waitFor(() =>
      expect(result.current.connectionDraft.api_url).toBe(
        "https://edited.example",
      ),
    );
    expect(result.current.connectionDraft).toMatchObject({
      client_id: "custom",
      scope: "custom-scope",
      token_url: "https://session.example/token",
      verify_tls: true,
    });
    expect(api.mock.calls.map(([path]) => path)).not.toContain(
      "/api/scanner-tasks",
    );
  });

  it.each(["operatorMessage", "message", "none"])(
    "represents backend failure using %s and recovers without reloading the page",
    async (field) => {
      const error = new Error(field === "message" ? "Connection refused" : "");
      if (field === "operatorMessage")
        error.operatorMessage = "Backend restarting";
      error.traceId = "trace-recovery";
      responses["/api/system/status"] = error;
      const { result } = harness("tasks");
      await ready(result);
      expect(result.current.systemStatus.state).toBe("down");
      expect(result.current.systemStatus.components.application).toMatchObject({
        retryable: true,
        trace_id: "trace-recovery",
        message:
          field === "operatorMessage"
            ? "Backend restarting"
            : field === "message"
              ? "Connection refused"
              : "Backend недоступен.",
      });
      expect(result.current.operationsStale).toBe(true);
      expect(api.mock.calls.map(([path]) => path)).not.toContain(
        "/api/scanner-tasks",
      );
      responses["/api/system/status"] = healthy;
      await act(async () =>
        expect(await result.current.refreshSystemStatus()).toEqual(healthy),
      );
      await waitFor(() => expect(result.current.tasks).toHaveLength(1));
      expect(result.current.operationsStale).toBe(false);
    },
  );

  it("loads only the active route and retains cached task selection across navigation", async () => {
    const { result, rerender } = harness("tasks");
    await ready(result);
    await waitFor(() => expect(result.current.tasks).toHaveLength(1));
    act(() => result.current.setSelectedTaskId("task-1"));
    expect(
      api.mock.calls.some(([path]) => path.startsWith("/api/assets?")),
    ).toBe(false);
    rerender({ currentRoute: "assets" });
    await waitFor(() => expect(result.current.assetTotal).toBe(1));
    expect(result.current.summary).toEqual({ total: 1 });
    expect(result.current.selectedTask.mp_task_id).toBe("task-1");
    expect(
      api.mock.calls.some(([path]) => path.startsWith("/api/operations?")),
    ).toBe(false);
  });

  it("encodes asset filters and supports empty responses and default refresh", async () => {
    const { result } = harness("assets");
    await ready(result);
    const filters = {
      q: "server & api",
      severity: "critical",
      sort_by: "hostname",
      sort_dir: "asc",
    };
    const path =
      "/api/assets?limit=300&q=server+%26+api&severity=critical&sort_by=hostname&sort_dir=asc";
    responses[path] = {};
    await act(async () =>
      expect(await result.current.refreshAssets(filters)).toEqual({
        summary: { total: 1 },
        rows: [],
        total: 0,
      }),
    );
    expect(api).toHaveBeenCalledWith(path);
    await waitFor(() => expect(result.current.assetRows).toEqual([]));
    await act(async () => result.current.refreshAssets());
    await waitFor(() => expect(result.current.assetTotal).toBe(1));
  });

  it("exposes task and asset request errors while allowing explicit retry", async () => {
    const failure = new Error("Task list failed");
    responses["/api/scanner-tasks"] = failure;
    const { result, rerender } = harness("tasks");
    await ready(result);
    await waitFor(() => expect(result.current.tasksError).toBe(failure));
    responses["/api/scanner-tasks"] = [{ mp_task_id: "retried" }];
    await act(async () => result.current.refreshTasks());
    await waitFor(() => expect(result.current.tasksError).toBeNull());
    expect(result.current.tasks[0].mp_task_id).toBe("retried");
    const assetFailure = new Error("Asset summary failed");
    responses["/api/assets/summary"] = assetFailure;
    rerender({ currentRoute: "assets" });
    await waitFor(() => expect(result.current.assetsError).toBe(assetFailure));
    expect(result.current.assetRows).toEqual([]);
  });

  it("retains operation filters on retry, supports paging and resets unspecified filters", async () => {
    const { result } = harness("operations");
    await ready(result);
    const path =
      "/api/operations?limit=25&offset=50&q=scan+%26+retry&status=failed&kind=scan&sort_by=status&sort_dir=asc";
    responses[path] = {
      rows: [{ operation_id: "op-1", status: "failed" }],
      total: 80,
    };
    await act(async () =>
      result.current.refreshOperations({
        limit: 25,
        offset: 50,
        q: "scan & retry",
        status: "failed",
        kind: "scan",
        sort_by: "status",
        sort_dir: "asc",
      }),
    );
    await waitFor(() => expect(result.current.operationsTotal).toBe(80));
    expect(result.current.operationsUpdatedAt).toMatch(/^\d{4}-/);
    api.mockClear();
    await act(async () => result.current.refreshOperations());
    expect(api).toHaveBeenCalledWith(path);
    await act(async () =>
      result.current.refreshOperations({ limit: 0, sort_by: "", sort_dir: "" }),
    );
    expect(api).toHaveBeenCalledWith("/api/operations?limit=50&offset=0");
    await waitFor(() => expect(result.current.operationsTotal).toBe(0));
  });

  it("marks failed operation data stale and clears the error after refreshing", async () => {
    const failure = new Error("Summary unavailable");
    responses["/api/operations/summary"] = failure;
    const { result } = harness("operations");
    await ready(result);
    await waitFor(() =>
      expect(result.current.operationSummaryError).toBe(failure),
    );
    expect(result.current.operationsStale).toBe(true);
    responses["/api/operations/summary"] = { active: 1 };
    await act(async () =>
      expect(await result.current.refreshOperationSummary()).toEqual({
        active: 1,
      }),
    );
    await waitFor(() => expect(result.current.operationsStale).toBe(false));
    const path =
      "/api/operations?limit=50&offset=0&sort_by=created_at&sort_dir=desc";
    responses[path] = failure;
    await act(async () => {
      await expect(result.current.refreshOperations()).rejects.toThrow(
        "Summary unavailable",
      );
    });
    await waitFor(() => expect(result.current.operationsError).toBe(failure));
    expect(result.current.operationsStale).toBe(true);
  });

  it("clears credential lookups on disconnect and updates the shared session cache", async () => {
    const { result, client } = harness("forbidden");
    await ready(result);
    act(() =>
      result.current.setLookups({
        credentials: [{ id: "secret-reference" }],
        scopes: ["scope"],
        scanner_profiles: [],
      }),
    );
    act(() => result.current.setSession({ connected: false }));
    expect(result.current.lookups).toEqual({
      credentials: [],
      scopes: [],
      scanner_profiles: [],
      agents: [],
    });
    expect(client.getQueryData(["session"])).toEqual({ connected: false });
    act(() => result.current.setLookups({ credentials: [{ id: "new" }] }));
    act(() => result.current.setSession({ connected: true }));
    expect(result.current.lookups.credentials).toEqual([{ id: "new" }]);
  });
});

describe("busy operation coordination", () => {
  it("deduplicates double clicks and clears busy state only after completion", async () => {
    const { result } = harness("forbidden");
    await ready(result);
    const pending = deferred();
    const work = vi.fn(() => pending.promise);
    let first, second;
    act(() => {
      first = result.current.runBusy("download", work);
      second = result.current.runBusy("download", work);
    });
    expect(second).toBe(first);
    expect(result.current.busy.download).toBe(true);
    await act(async () => pending.resolve("archive"));
    expect(await first).toBe("archive");
    expect(work).toHaveBeenCalledTimes(1);
    expect(result.current.busy.download).toBe(false);
  });

  it("keeps the shared busy flag until every explicitly concurrent operation finishes", async () => {
    const { result } = harness("forbidden");
    await ready(result);
    const first = deferred(),
      second = deferred();
    act(() => {
      result.current.runBusy("refresh", () => first.promise, {
        allowConcurrent: true,
      });
      result.current.runBusy("refresh", () => second.promise, {
        allowConcurrent: true,
      });
    });
    await act(async () => first.resolve(1));
    expect(result.current.busy.refresh).toBe(true);
    await act(async () => second.resolve(2));
    expect(result.current.busy.refresh).toBe(false);
  });

  it.each([new Error("Download failed"), "Transport failed"])(
    "reports %s and permits a later retry",
    async (error) => {
      const { result } = harness("forbidden");
      await ready(result);
      await act(async () =>
        expect(
          await result.current.runBusy("download", () => Promise.reject(error)),
        ).toBeNull(),
      );
      expect(result.current.alerts).toEqual([
        expect.objectContaining({
          type: "error",
          message: error.message || error,
        }),
      ]);
      expect(result.current.busy.download).toBe(false);
      await act(async () =>
        expect(await result.current.runBusy("download", () => "ok")).toBe("ok"),
      );
      act(() => result.current.dismissAlert(result.current.alerts[0].id));
      expect(result.current.alerts).toEqual([]);
    },
  );
});

it.each(["queued", "running", "cancelling", "recovering"])(
  "polls active %s operations promptly and stops polling after unmount",
  async (status) => {
    vi.useFakeTimers();
    const path =
      "/api/operations?limit=50&offset=0&sort_by=created_at&sort_dir=desc";
    responses[path] = { rows: [{ operation_id: "active", status }], total: 1 };
    responses["/api/operations/summary"] = { active: 1 };
    const { result, unmount } = harness("operations");
    await act(async () => vi.advanceTimersByTimeAsync(1));
    await vi.waitFor(() => expect(result.current.operations).toHaveLength(1));
    const count = () =>
      api.mock.calls.filter(([request]) => request === path).length;
    expect(count()).toBe(1);
    await act(async () => vi.advanceTimersByTimeAsync(2100));
    expect(count()).toBe(2);
    unmount();
    await act(async () => vi.advanceTimersByTimeAsync(30000));
    expect(count()).toBe(2);
  },
);

it("polls completed operations at the slower interval", async () => {
  vi.useFakeTimers();
  const path =
    "/api/operations?limit=50&offset=0&sort_by=created_at&sort_dir=desc";
  responses[path] = {
    rows: [{ operation_id: "completed", status: "completed" }],
    total: 1,
  };
  const { result, unmount } = harness("operations");
  await act(async () => vi.advanceTimersByTimeAsync(1));
  await vi.waitFor(() => expect(result.current.operations).toHaveLength(1));
  const count = () =>
    api.mock.calls.filter(([request]) => request === path).length;
  await act(async () => vi.advanceTimersByTimeAsync(14000));
  expect(count()).toBe(1);
  await act(async () => vi.advanceTimersByTimeAsync(1100));
  expect(count()).toBe(2);
  unmount();
});

it("fills an empty client ID from defaults and safely handles an error without trace metadata", async () => {
  responses["/api/system/status"] = new Error("Offline");
  const { result, client } = harness("forbidden");
  await ready(result);
  expect(
    result.current.systemStatus.components.application.trace_id,
  ).toBeNull();
  act(() =>
    result.current.setConnectionDraft((draft) => ({ ...draft, client_id: "" })),
  );
  act(() =>
    client.setQueryData(["defaults"], { client_id: "configured-client" }),
  );
  await waitFor(() =>
    expect(result.current.connectionDraft.client_id).toBe("configured-client"),
  );
  act(() =>
    result.current.setConnectionDraft((draft) => ({ ...draft, client_id: "" })),
  );
  act(() => client.setQueryData(["defaults"], {}));
  await waitFor(() =>
    expect(result.current.connectionDraft.client_id).toBe("mpx"),
  );
});
