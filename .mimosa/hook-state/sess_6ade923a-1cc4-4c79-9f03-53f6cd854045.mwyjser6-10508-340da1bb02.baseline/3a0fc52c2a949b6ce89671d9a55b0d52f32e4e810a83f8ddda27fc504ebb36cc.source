import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, downloadApiFile } from "../api/client.js";
import { ComplianceDashboard } from "../features/vulnerabilities/ComplianceDashboard.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn(), downloadApiFile: vi.fn() }));
let data, clients, showAlert;
beforeEach(() => {
  clients = [];
  showAlert = vi.fn();
  data = {
    summary: {
      assets_total: 5,
      fresh_assets: 3,
      critical_findings: 5,
      stale_assets: 2,
    },
    findings: {
      rows: [
        {
          asset_id: "a",
          display_name: "Internet server",
          asset_type: "server",
          asset_category: "server",
          ip_address: "10.255.0.1",
          scan_at: "2026-09-29",
          cve: "CVE-2026-1",
          cvss_score: 9.8,
        },
        {
          asset_id: "b",
          asset_category: "user_device",
          vulnerability_id: "v-2",
        },
        { asset_id: "c", asset_category: "unclassified" },
        { asset_id: "d", asset_category: "other-category" },
        { asset_id: "e" },
      ],
    },
    "stale-assets": {
      rows: [
        {
          asset_id: "old-server",
          display_name: "Old server",
          asset_category: "server",
          age_days: 90,
          freshness_reason: "stale",
        },
        { asset_id: "missing-scan" },
      ],
    },
  };
  api.mockReset().mockImplementation(async (path) => {
    const result =
      data[new URL(path, "http://localhost").pathname.split("/").at(-1)];
    if (result instanceof Error) throw result;
    if (result?.then) return result;
    if (result) return result;
    throw new Error(`Unexpected request: ${path}`);
  });
  downloadApiFile
    .mockReset()
    .mockResolvedValue({ filename: "report.pdf", bytes: 20 });
});
afterEach(() => clients.forEach((client) => client.clear()));
function page(enabled = true) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  clients.push(client);
  return render(
    <QueryClientProvider client={client}>
      <ComplianceDashboard enabled={enabled} showAlert={showAlert} />
    </QueryClientProvider>,
  );
}
async function ready() {
  await screen.findByText("Internet server");
}

describe("compliance dashboard and report downloads", () => {
  it("renders counts, categories, finding identity and stale scan evidence", async () => {
    page();
    await ready();
    expect(screen.getByText("10.255.0.1")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-1")).toBeInTheDocument();
    expect(screen.getByText("v-2")).toBeInTheDocument();
    expect(screen.getByText("Пользовательское устройство")).toBeInTheDocument();
    expect(screen.getByText("Не классифицирован")).toBeInTheDocument();
    expect(screen.getByText("other-category")).toBeInTheDocument();
    expect(screen.getByText("Old server")).toBeInTheDocument();
    expect(screen.getByText("90")).toBeInTheDocument();
    expect(screen.getByText("stale")).toBeInTheDocument();
    expect(screen.getAllByRole("table")).toHaveLength(2);
    expect(
      within(screen.getAllByRole("table")[0]).getAllByRole("row"),
    ).toHaveLength(6);
  });

  it("does not fetch a disabled dashboard", () => {
    page(false);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Загружаю контрольный срез",
    );
    expect(api).not.toHaveBeenCalled();
  });

  it("shows a loading state until all three data sources are ready", async () => {
    let complete;
    data.findings = new Promise((resolve) => {
      complete = resolve;
    });
    page();
    expect(screen.getByRole("status")).toBeInTheDocument();
    await act(async () => complete({ rows: [] }));
    expect(
      await screen.findByText(
        "Критические уязвимости на свежих результатах не обнаружены.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("supports missing rows and metrics in an empty response", async () => {
    data = { summary: {}, findings: {}, "stale-assets": {} };
    page();
    await screen.findByText(
      "Все активы имеют результаты сканирования не старше 30 дней.",
    );
    expect(screen.getAllByText("0")).toHaveLength(4);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("changes scope and assessment date and refreshes all datasets", async () => {
    page();
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Организация" }));
    await waitFor(() =>
      expect(
        api.mock.calls.some(([path]) => path.includes("/organization/summary")),
      ).toBe(true),
    );
    expect(
      screen.getByText("Пользовательские устройства и серверы по типу актива"),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Дата оценки"), {
      target: { value: "2026-09-15" },
    });
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/vulnerabilities/compliance/organization/summary?assessment_date=2026-09-15",
      ),
    );
    await ready();
    api.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "Обновить" }));
    await waitFor(() => expect(api).toHaveBeenCalledTimes(3));
    for (const [path] of api.mock.calls) {
      expect(path).toContain("/organization/");
      expect(path).toContain("assessment_date=2026-09-15");
    }
    fireEvent.click(screen.getByRole("button", { name: "Внешний контур" }));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/vulnerabilities/compliance/internet/summary?assessment_date=2026-09-15",
      ),
    );
  });

  it.each(["summary", "findings", "stale-assets"])(
    "exposes %s errors and recovers on refresh",
    async (source) => {
      const original = data[source];
      data[source] = Object.assign(new Error("Request failed"), {
        operatorMessage: "Dataset temporarily unavailable",
      });
      page();
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "Dataset temporarily unavailable",
      );
      data[source] = original;
      fireEvent.click(screen.getByRole("button", { name: "Обновить" }));
      await ready();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    },
  );

  it("uses the ordinary error message when no operator detail is supplied", async () => {
    data.summary = new Error("Summary failed");
    page();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Summary failed",
    );
  });

  it.each(["pdf", "xlsx"])(
    "downloads %s with the chosen assessment and prevents duplicate clicks",
    async (format) => {
      let complete;
      downloadApiFile.mockImplementation(
        () =>
          new Promise((resolve) => {
            complete = resolve;
          }),
      );
      page();
      await ready();
      fireEvent.change(screen.getByLabelText("Дата оценки"), {
        target: { value: "2026-09-15" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Организация" }));
      const button = screen.getByRole("button", { name: format.toUpperCase() });
      fireEvent.click(button);
      expect(button).toBeDisabled();
      fireEvent.click(button);
      expect(downloadApiFile).toHaveBeenCalledTimes(1);
      expect(downloadApiFile).toHaveBeenCalledWith(
        `/api/reports/vulnerabilities/compliance/organization/${format}`,
        {
          method: "POST",
          body: JSON.stringify({ assessment_date: "2026-09-15" }),
        },
      );
      await act(async () => complete({ bytes: 20 }));
      expect(showAlert).toHaveBeenCalledWith(
        `Отчёт ${format.toUpperCase()} загружен.`,
        "success",
      );
      expect(button).not.toBeDisabled();
    },
  );

  it.each([true, false])(
    "reports download failure and re-enables retry (operator detail=%s)",
    async (operatorDetail) => {
      const error = new Error("Download failed");
      if (operatorDetail) error.operatorMessage = "Report unavailable";
      downloadApiFile.mockRejectedValueOnce(error);
      page();
      await ready();
      fireEvent.click(screen.getByRole("button", { name: "PDF" }));
      await waitFor(() =>
        expect(showAlert).toHaveBeenCalledWith(
          operatorDetail ? "Report unavailable" : "Download failed",
          "error",
        ),
      );
      fireEvent.click(screen.getByRole("button", { name: "PDF" }));
      await waitFor(() =>
        expect(showAlert).toHaveBeenCalledWith(
          "Отчёт PDF загружен.",
          "success",
        ),
      );
    },
  );
});
