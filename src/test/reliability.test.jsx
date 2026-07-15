import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SystemBanner } from "../app/layout.jsx";
import { api, normalizeApiError } from "../api/client.js";
import { Button, ConfirmDialog } from "../shared/ui.jsx";
import { OperationsPage } from "../pages/OperationsPage.jsx";
import {
  AssetCard,
  buildAssetPropertyRows,
  formatAssetCell,
} from "../panels.jsx";
import { sortRows } from "../shared/table.jsx";

vi.mock("../api/client.js", async (importOriginal) => {
  const original = await importOriginal();
  return { ...original, api: vi.fn(() => Promise.resolve({ rows: [] })) };
});

describe("reliability UI", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockResolvedValue({ rows: [] });
  });

  it("normalizes a network failure into an operator-facing error", () => {
    const error = normalizeApiError(new TypeError("fetch failed"), {
      path: "/api/system/status",
      requestId: "request-1",
    });
    expect(error.code).toBe("NETWORK_UNAVAILABLE");
    expect(error.retryable).toBe(true);
    expect(error.context.path).toBe("/api/system/status");
  });

  it("renders one persistent degraded-state banner", () => {
    render(
      <SystemBanner
        status={{
          state: "degraded",
          components: {
            database: {
              state: "down",
              message: "PostgreSQL недоступен.",
              trace_id: "trace-1",
            },
          },
        }}
        stale
        onRetry={vi.fn()}
        onNavigate={vi.fn()}
      />,
    );
    expect(screen.getByText("Часть системы недоступна")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL недоступен.")).toBeInTheDocument();
    expect(screen.getByText("trace: trace-1")).toBeInTheDocument();
  });

  it("requires the remote object id before destructive confirmation", () => {
    const confirm = vi.fn();
    render(
      <ConfirmDialog
        open
        title="Удалить задачу?"
        description="Изменение MP VM"
        requireText="task-42"
        onConfirm={confirm}
        onClose={vi.fn()}
      />,
    );
    const button = screen.getByRole("button", { name: "Подтвердить" });
    expect(button).toBeDisabled();
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "task-42" },
    });
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(confirm).toHaveBeenCalledOnce();
  });

  it("shows normalized operations and attention count", () => {
    const operations = [
      {
        operation_id: "one",
        kind: "asset_card_build",
        status: "running",
        stage: "tree",
        progress_percent: 42,
        subject: { label: "host-1" },
        updated_at: "2026-07-04T10:00:00Z",
      },
      {
        operation_id: "two",
        kind: "passport_detail_sync",
        status: "failed",
        stage: "failed",
        progress_percent: 73,
        subject: { label: "Passports" },
        updated_at: "2026-07-04T10:01:00Z",
        can_retry: true,
      },
    ];
    render(
      <OperationsPage
        operations={operations}
        total={2}
        updatedAt="2026-07-04T10:02:00Z"
        stale={false}
        refreshOperations={vi.fn()}
        runBusy={(_key, fn) => fn()}
        busy={{}}
        showAlert={vi.fn()}
      />,
    );
    expect(screen.getByText("host-1")).toBeInTheDocument();
    expect(screen.getByText("Passports")).toBeInTheDocument();
    expect(
      screen.getByText("требуют внимания").previousSibling,
    ).toHaveTextContent("1");
  });

  it("blocks busy buttons and deduplicates promise-backed clicks", async () => {
    let resolveAction;
    const action = new Promise((resolve) => {
      resolveAction = resolve;
    });
    const onClick = vi.fn(() => action);
    const { rerender } = render(<Button onClick={onClick}>Run</Button>);
    const button = screen.getByRole("button", { name: "Run" });

    expect(button).toHaveAttribute("type", "button");
    fireEvent.click(button);
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();

    resolveAction();
    await action;
    await waitFor(() => fireEvent.click(button));
    expect(onClick).toHaveBeenCalledTimes(2);

    rerender(
      <Button busy onClick={onClick}>
        Run
      </Button>,
    );
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(2);
  });

  it("sorts typed values stably and always leaves empty cells last", () => {
    const rows = [
      { id: "empty", value: null },
      { id: "ten", value: 10 },
      { id: "two", value: 2 },
    ];
    expect(
      sortRows(rows, { key: "value", direction: "asc" }).map((row) => row.id),
    ).toEqual(["two", "ten", "empty"]);
    expect(
      sortRows(rows, { key: "value", direction: "desc" }).map((row) => row.id),
    ).toEqual(["ten", "two", "empty"]);
  });

  it("removes raw containers while preserving nested asset-card leaves", () => {
    const rows = buildAssetPropertyRows({
      name: "firewall",
      title: "Firewall",
      path: "asset.firewall",
      value: {
        rawDetail: { debug: true },
        rules: [{ port: 443, action: "allow", objectId: "hidden" }],
      },
    });
    expect(rows.map((row) => row.path)).toEqual([
      "asset.firewall.rules[0].port",
      "asset.firewall.rules[0].action",
    ]);
    expect(rows.map((row) => row.value)).toEqual([443, "allow"]);
    expect(formatAssetCell({ arbitrary: "container" })).toBe("—");
  });

  it("opens asset cards through paged endpoints instead of the full legacy card", async () => {
    api.mockImplementation((path) => {
      if (path.includes("/configuration/tree")) {
        return Promise.resolve({
          rows: [
            {
              path: "asset",
              label: "Host",
              kind: "root",
              has_children: true,
              depth: 0,
            },
            {
              path: "asset.software",
              parent_path: "asset",
              label: "Software",
              kind: "collection",
              has_children: false,
              depth: 1,
            },
          ],
          total: 2,
          limit: 200,
          offset: 0,
          has_more: false,
        });
      }
      if (path.includes("/configuration/detail")) {
        return Promise.resolve({
          columns: [{ key: "value", title: "Value" }],
          rows: [{ key: "row-1", value: "nginx" }],
          total: 1,
          limit: 200,
          offset: 0,
          has_more: false,
        });
      }
      if (path.includes("/vulnerabilities/groups")) {
        return Promise.resolve({
          vulnerabilities: {
            header: { os_soft_vulnerabilities_count: 1 },
            sources: [
              {
                source: "os",
                title: "OS vulnerabilities",
                groups: [
                  {
                    source: "os",
                    collection_id: "group-1",
                    name: "OS group",
                    vulnerabilities_count: 1,
                  },
                ],
              },
            ],
          },
        });
      }
      if (path.includes("/vulnerabilities/findings")) {
        return Promise.resolve({
          rows: [
            {
              vulnerability_instance_id: "finding-1",
              name: "Finding",
              cve_name: "CVE-1",
              passport_ids: ["generic-passport", "os-passport"],
              passports: [
                {
                  internal_id: "generic-passport",
                  name: "Generic passport",
                  match_method: "cve_generic",
                },
                {
                  internal_id: "os-passport",
                  name: "OS passport",
                  match_method: "cve_os",
                },
              ],
            },
          ],
          total: 1,
          limit: 100,
          offset: 0,
          has_more: false,
        });
      }
      return Promise.resolve({});
    });

    const onOpenPassport = vi.fn();
    render(
      <AssetCard
        card={{
          asset_id: "asset-1",
          display_name: "Host",
          loaded_sections: ["summary"],
          stats: {},
        }}
        loading={false}
        onOpenPassport={onOpenPassport}
      />,
    );
    const tabButtons = document.querySelectorAll(".asset-tabs button");

    fireEvent.click(tabButtons[2]);
    expect(screen.getByRole("tabpanel")).toHaveClass("asset-tabpanel");
    expect(
      screen.getByRole("tabpanel").querySelector(".asset-config-layout"),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        expect.stringContaining("/api/asset-cards/asset-1/configuration/tree?"),
      ),
    );
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        expect.stringContaining(
          "/api/asset-cards/asset-1/configuration/detail?",
        ),
      ),
    );
    fireEvent.click(await screen.findByText("Software"));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        expect.stringContaining("path=asset.software"),
      ),
    );

    fireEvent.click(tabButtons[1]);
    expect(screen.getByRole("tabpanel")).toHaveClass("asset-tabpanel");
    expect(
      screen.getByRole("tabpanel").querySelector(".asset-vulnerability-pane"),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        expect.stringContaining(
          "/api/asset-cards/asset-1/vulnerabilities/groups",
        ),
      ),
    );
    fireEvent.click((await screen.findByText(/OS group/)).closest("button"));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        expect.stringContaining(
          "/api/asset-cards/asset-1/vulnerabilities/findings?",
        ),
      ),
    );
    expect(screen.queryByText("Паспорта: 2")).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "CVE-1" }));
    expect(onOpenPassport).toHaveBeenCalledWith(
      expect.objectContaining({ internal_id: "os-passport" }),
    );

    const paths = api.mock.calls.map(([path]) => path);
    expect(
      paths.some((path) => /^\/api\/asset-cards\/asset-1(?:\?|$)/.test(path)),
    ).toBe(false);
  });
});
