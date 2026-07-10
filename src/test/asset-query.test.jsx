import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { AssetQueryPage } from "../pages/AssetQueryPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const FIELDS = [
  {
    field_path: "asset.firewall.rules.port",
    field_name: "Порт",
    value_type: "number",
    asset_count: 4,
    sample_value: "443",
  },
  {
    field_path: "asset.firewall.rules.enabled",
    field_name: "Правило включено",
    value_type: "boolean",
    asset_count: 3,
    sample_value: "true",
  },
  {
    field_path: "asset.osName",
    field_name: "Операционная система",
    value_type: "text",
    asset_count: 8,
    sample_value: "Linux",
  },
];

function configureApi({ views = [], queryResult } = {}) {
  api.mockImplementation((path, options = {}) => {
    if (path === "/api/asset-card-query/fields?limit=500") {
      return Promise.resolve({
        rows: FIELDS,
        indexed_cards: 8,
        total_cards: 8,
      });
    }
    if (path === "/api/saved-views?route=asset-query") {
      return Promise.resolve({ rows: views });
    }
    if (path === "/api/asset-card-query" && options.method === "POST") {
      return Promise.resolve(
        queryResult || {
          rows: [],
          total: 0,
          offset: 0,
          indexed_cards: 8,
          total_cards: 8,
        },
      );
    }
    if (path === "/api/saved-views" && options.method === "POST") {
      const payload = JSON.parse(options.body);
      return Promise.resolve({
        id: 11,
        route: payload.route,
        name: payload.name,
        filters: payload.filters,
      });
    }
    if (
      typeof path === "string" &&
      path.startsWith("/api/saved-views/") &&
      options.method === "DELETE"
    ) {
      return Promise.resolve({ deleted: true });
    }
    return Promise.resolve({});
  });
}

function renderPage() {
  const showAlert = vi.fn();
  const runBusy = vi.fn((_key, task) => task());
  render(<AssetQueryPage runBusy={runBusy} busy={{}} showAlert={showAlert} />);
  return { runBusy, showAlert };
}

async function waitForFields() {
  await waitFor(() =>
    expect(
      document.querySelectorAll("#asset-query-fields option"),
    ).toHaveLength(FIELDS.length),
  );
}

describe("asset query UI", () => {
  beforeEach(() => {
    api.mockReset();
  });

  it("applies an active saved query immediately and can delete it", async () => {
    const savedQuery = {
      combinator: "and",
      match_scope: "host",
      rules: [
        {
          field_path: "asset.firewall.rules.port",
          operator: "gte",
          value: "443",
        },
      ],
    };
    configureApi({
      views: [
        {
          id: 7,
          name: "Публичные веб-серверы",
          filters: {
            query: savedQuery,
            sort: { key: "last_seen", direction: "desc" },
            columns: ["display_name", "ip_address"],
          },
        },
      ],
      queryResult: {
        rows: [
          {
            asset_id: "asset-1",
            display_name: "web-01",
            ip_address: "10.0.0.10",
            matches: [
              {
                entity_path: "asset.firewall.rules[0]",
                field_path: "asset.firewall.rules.port",
                field_name: "Порт",
                value: 443,
              },
            ],
          },
        ],
        total: 1,
        offset: 0,
        indexed_cards: 8,
        total_cards: 8,
      },
    });
    const { showAlert } = renderPage();

    await screen.findByRole("option", { name: "Публичные веб-серверы" });
    const picker = screen.getByLabelText("Сохранённая выборка");
    fireEvent.change(picker, { target: { value: "7" } });

    await waitFor(() => {
      const queryCall = api.mock.calls.find(
        ([path, options]) =>
          path === "/api/asset-card-query" && options.method === "POST",
      );
      expect(JSON.parse(queryCall[1].body)).toMatchObject({
        query: savedQuery,
        sort_by: "last_seen",
        sort_dir: "desc",
        offset: 0,
      });
    });
    expect(picker).toHaveValue("7");
    expect(await screen.findByText("web-01")).toBeInTheDocument();
    const evidence = screen.getByText("Почему актив найден").closest("details");
    expect(evidence).not.toHaveAttribute("open");

    fireEvent.click(screen.getByRole("button", { name: "Удалить выборку" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/saved-views/7", {
        method: "DELETE",
      }),
    );
    expect(
      screen.queryByRole("option", { name: "Публичные веб-серверы" }),
    ).not.toBeInTheDocument();
    expect(picker).toHaveValue("");
    expect(showAlert).toHaveBeenCalledWith(
      "Выборка «Публичные веб-серверы» удалена.",
      "success",
    );
  });

  it("saves the current query and marks the saved query as active", async () => {
    configureApi();
    renderPage();
    await waitForFields();

    fireEvent.change(screen.getByLabelText("Параметр актива 1"), {
      target: { value: "asset.osName" },
    });
    fireEvent.change(screen.getByLabelText("Значение 1"), {
      target: { value: "Linux" },
    });
    fireEvent.change(screen.getByLabelText("Название выборки"), {
      target: { value: "Linux-серверы" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить выборку" }));

    await waitFor(() => {
      const saveCall = api.mock.calls.find(
        ([path, options]) =>
          path === "/api/saved-views" && options.method === "POST",
      );
      const payload = JSON.parse(saveCall[1].body);
      expect(payload).toMatchObject({
        route: "asset-query",
        name: "Linux-серверы",
        filters: {
          query: {
            rules: [
              {
                field_path: "asset.osName",
                operator: "equals",
                value: "Linux",
              },
            ],
          },
          sort: { key: "display_name", direction: "asc" },
        },
      });
    });
    expect(screen.getByLabelText("Сохранённая выборка")).toHaveValue("11");
    expect(
      screen.getByRole("button", { name: "Сохранить изменения" }),
    ).toBeInTheDocument();
  });

  it("uses one field list and resets an incompatible operator", async () => {
    configureApi();
    renderPage();
    await waitForFields();

    expect(
      document.querySelectorAll("datalist#asset-query-fields"),
    ).toHaveLength(1);
    const field = screen.getByLabelText("Параметр актива 1");
    const operator = screen.getByLabelText("Сравнение 1");
    fireEvent.change(field, {
      target: { value: "asset.firewall.rules.port" },
    });
    fireEvent.change(operator, { target: { value: "gt" } });
    expect(operator).toHaveValue("gt");

    fireEvent.change(field, {
      target: { value: "asset.firewall.rules.enabled" },
    });
    expect(operator).toHaveValue("is_true");
    expect(screen.getByLabelText("Значение 1")).toBeDisabled();
  });

  it("never removes the last condition and safely removes nested groups", async () => {
    configureApi();
    renderPage();
    await waitForFields();

    expect(
      screen.getByRole("button", { name: "Удалить условие 1" }),
    ).toBeDisabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Добавить группу условий" }),
    );
    expect(screen.getByText("Группа условий 1")).toBeInTheDocument();
    const removeGroup = screen.getByRole("button", { name: "Удалить группу" });
    expect(removeGroup).toBeEnabled();
    fireEvent.click(removeGroup);
    expect(screen.queryByText("Группа условий 1")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Удалить условие 1" }),
    ).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Добавить условие" }));
    const removeConditions = screen.getAllByRole("button", {
      name: /Удалить условие/,
    });
    expect(removeConditions).toHaveLength(2);
    expect(removeConditions[1]).toBeEnabled();
    fireEvent.click(removeConditions[1]);
    expect(
      screen.getByRole("button", { name: "Удалить условие 1" }),
    ).toBeDisabled();
  });
});
