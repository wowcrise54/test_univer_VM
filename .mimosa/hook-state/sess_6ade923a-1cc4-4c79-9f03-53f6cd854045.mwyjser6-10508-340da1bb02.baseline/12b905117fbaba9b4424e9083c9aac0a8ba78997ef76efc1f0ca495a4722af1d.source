import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { AssetsPanel } from "../panels.jsx";

vi.mock("../api/client.js", () => ({
  api: vi.fn(),
  createIdempotencyKey: vi.fn(() => "test-key"),
}));

const SAVED_VIEW = {
  id: 7,
  name: "Свежие критические",
  filters: {
    q: "server",
    severity: "critical",
    sort: { key: "created_at", direction: "desc" },
  },
};

function renderAssets(refreshAssets = vi.fn().mockResolvedValue({ rows: [] })) {
  const runBusy = vi.fn(async (_key, action) => action());
  render(
    <AssetsPanel
      summary={{ assets: 2, software: 3, findings: 4, cve_rows: 5 }}
      rows={[]}
      total={0}
      refreshAssets={refreshAssets}
      busy={{}}
      runBusy={runBusy}
      showAlert={vi.fn()}
    />,
  );
  return { refreshAssets, runBusy };
}

describe("AssetsPanel", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation(async (url, options = {}) => {
      if (url === "/api/saved-views?route=assets")
        return { rows: [SAVED_VIEW] };
      if (url === "/api/saved-views" && options.method === "POST") {
        return {
          id: 9,
          name: "Windows",
          filters: JSON.parse(options.body).filters,
        };
      }
      return {};
    });
  });

  it("applies a saved selection immediately with its sorting", async () => {
    const { refreshAssets } = renderAssets();
    const savedSelect = screen.getByRole("combobox", {
      name: "Сохранённая выборка",
    });
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: SAVED_VIEW.name }),
      ).toBeInTheDocument(),
    );

    fireEvent.change(savedSelect, { target: { value: "7" } });

    await waitFor(() =>
      expect(refreshAssets).toHaveBeenCalledWith({
        q: "server",
        severity: "critical",
        sort_by: "created_at",
        sort_dir: "desc",
      }),
    );
    expect(screen.getByRole("combobox", { name: "Порядок" })).toHaveValue(
      "desc",
    );
  });

  it("preserves sorting when filters are applied and saved", async () => {
    const { refreshAssets } = renderAssets();
    fireEvent.change(screen.getByRole("combobox", { name: "Сортировать по" }), {
      target: { value: "created_at" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Поиск" }), {
      target: { value: "windows" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Применить фильтры" }));

    await waitFor(() =>
      expect(refreshAssets).toHaveBeenLastCalledWith({
        q: "windows",
        severity: "",
        sort_by: "created_at",
        sort_dir: "desc",
      }),
    );

    fireEvent.change(
      screen.getByRole("textbox", { name: "Название выборки" }),
      { target: { value: "Windows" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Сохранить выборку" }));

    await waitFor(() => {
      const request = api.mock.calls.find(
        ([url, options]) =>
          url === "/api/saved-views" && options?.method === "POST",
      );
      expect(JSON.parse(request[1].body).filters.sort).toEqual({
        key: "created_at",
        direction: "desc",
      });
    });
  });
});
