import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { VulnerabilitiesDashboard } from "../features/vulnerabilities/index.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const VULNERABILITY = {
  selector: "vulnerability:id:vuln-1",
  vulnerability_id: "vuln-1",
  cve: "CVE-2026-1001",
  name: "Удалённое выполнение кода",
  severity: "critical",
  max_cvss: 9.8,
  affected_hosts: 8,
  findings: 11,
  affected_objects: ["kernel"],
  sources: ["os"],
  last_seen: "2026-07-11T08:00:00Z",
};

const SUMMARY = {
  source: "asset_cards",
  totals: {
    hosts_total: 201,
    affected_hosts: 143,
    findings: 4201,
    unique_vulnerabilities: 812,
    unique_cves: 640,
    high_risk_hosts: 57,
    unrated_vulnerabilities: 9,
  },
  by_severity: [
    {
      severity: "critical",
      findings: 128,
      affected_hosts: 22,
      unique_vulnerabilities: 31,
    },
  ],
  coverage: {
    cards_total: 201,
    cards_with_findings: 184,
    truncated_groups: 0,
    complete: true,
    freshest_at: "2026-07-11T08:00:00Z",
    oldest_at: "2026-07-10T08:00:00Z",
  },
  top_vulnerabilities: [VULNERABILITY],
  top_hosts: [
    {
      asset_id: "asset-1",
      display_name: "server-01",
      ip_address: "10.0.0.1",
      findings: 17,
      unique_vulnerabilities: 12,
    },
  ],
};

const HOST = {
  asset_id: "asset-1",
  display_name: "server-01",
  hostname: "server-01",
  fqdn: "server-01.example.test",
  ip_address: "10.0.0.1",
  os_name: "Linux",
  os_version: "9",
  severity: "critical",
  max_cvss: 9.8,
  finding_count: 2,
  objects: ["kernel"],
  sources: ["os"],
  last_seen: "2026-07-11T08:00:00Z",
};

function responseFor(path, { total = 75, empty = false } = {}) {
  const url = new URL(path, "http://localhost");
  if (url.pathname === "/api/vulnerabilities/summary") return SUMMARY;
  if (url.pathname === "/api/vulnerabilities/hosts") {
    return {
      rows: empty ? [] : [HOST],
      total: empty ? 0 : 1,
      limit: 50,
      offset: 0,
    };
  }
  if (url.pathname === "/api/vulnerabilities") {
    return {
      rows: empty ? [] : [VULNERABILITY],
      total: empty ? 0 : total,
      limit: 50,
      offset: Number(url.searchParams.get("offset") || 0),
    };
  }
  return {};
}

function renderDashboard() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, gcTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <VulnerabilitiesDashboard />
    </QueryClientProvider>,
  );
}

describe("vulnerability dashboard", () => {
  beforeEach(() => {
    api.mockReset();
    api.mockImplementation((path) => Promise.resolve(responseFor(path)));
  });

  it("renders source-backed KPIs and opens the host drill-down", async () => {
    renderDashboard();

    const affectedHosts = await screen.findByText("Хосты с уязвимостями");
    expect(affectedHosts.closest("article")).toHaveTextContent("143");
    expect(screen.getByText("Карточки активов")).toBeInTheDocument();
    expect(screen.getByText("184 из 201 · 92%")).toBeInTheDocument();

    const selectors = await screen.findAllByRole("button", {
      name: "Показать хосты с уязвимостью Удалённое выполнение кода",
    });
    fireEvent.click(selectors[0]);

    const heading = await screen.findByRole("heading", {
      name: "Хосты с уязвимостью «Удалённое выполнение кода»",
    });
    await waitFor(() => expect(heading).toHaveFocus());
    expect(
      await screen.findByText("server-01.example.test"),
    ).toBeInTheDocument();
    expect(
      api.mock.calls.some(([path]) => {
        const url = new URL(path, "http://localhost");
        return (
          url.pathname === "/api/vulnerabilities/hosts" &&
          url.searchParams.get("selector") === VULNERABILITY.selector
        );
      }),
    ).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Закрыть" }));
    await waitFor(() => expect(selectors[0]).toHaveFocus());
  });

  it("applies global filters and keeps sorting and pagination server-side", async () => {
    renderDashboard();
    await screen.findAllByText("Удалённое выполнение кода");

    fireEvent.change(screen.getByRole("textbox", { name: "Уязвимость" }), {
      target: { value: "CVE-2026" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Хост" }), {
      target: { value: "server" },
    });
    fireEvent.change(screen.getByRole("combobox", { name: "Критичность" }), {
      target: { value: "critical" },
    });
    fireEvent.change(screen.getByRole("combobox", { name: "Источник" }), {
      target: { value: "os" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Применить фильтры" }));

    await waitFor(() =>
      expect(
        api.mock.calls.some(([path]) => {
          const url = new URL(path, "http://localhost");
          return (
            url.pathname === "/api/vulnerabilities/summary" &&
            url.searchParams.get("q") === "CVE-2026" &&
            url.searchParams.get("host_q") === "server" &&
            url.searchParams.get("severity") === "critical" &&
            url.searchParams.get("source") === "os"
          );
        }),
      ).toBe(true),
    );

    fireEvent.click(
      screen.getByRole("button", {
        name: "Сортировать «Хостов» по возрастанию",
      }),
    );
    await waitFor(() =>
      expect(
        api.mock.calls.some(([path]) => {
          const url = new URL(path, "http://localhost");
          return (
            url.pathname === "/api/vulnerabilities" &&
            url.searchParams.get("sort_by") === "affected_hosts" &&
            url.searchParams.get("sort_dir") === "asc"
          );
        }),
      ).toBe(true),
    );

    const nextPage = screen.getByRole("button", {
      name: "Уязвимости: следующая страница",
    });
    await waitFor(() => expect(nextPage).toBeEnabled());
    fireEvent.click(nextPage);
    await waitFor(() =>
      expect(
        api.mock.calls.some(([path]) => {
          const url = new URL(path, "http://localhost");
          return (
            url.pathname === "/api/vulnerabilities" &&
            url.searchParams.get("offset") === "50"
          );
        }),
      ).toBe(true),
    );
  });

  it("shows an actionable summary error and an empty list state", async () => {
    let summaryFails = true;
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities/summary" && summaryFails) {
        return Promise.reject(new Error("Сводка временно недоступна"));
      }
      return Promise.resolve(responseFor(path, { empty: true }));
    });
    renderDashboard();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Сводка временно недоступна",
    );
    expect(
      await screen.findByText("Уязвимости с такими фильтрами не найдены."),
    ).toBeInTheDocument();

    summaryFails = false;
    fireEvent.click(
      screen.getByRole("button", { name: "Повторить загрузку сводки" }),
    );
    expect(await screen.findByText("Хосты с уязвимостями")).toBeInTheDocument();
  });

  it("renders an absent CVSS as unknown and localizes finding sources", async () => {
    const unrated = {
      ...VULNERABILITY,
      selector: "name:unsupported",
      vulnerability_id: null,
      cve: null,
      name: "Неподдерживаемая версия",
      severity: "unknown",
      max_cvss: null,
      sources: ["os", "software"],
    };
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities") {
        return Promise.resolve({
          rows: [unrated],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return Promise.resolve(responseFor(path));
    });
    renderDashboard();

    const button = await screen.findByRole("button", {
      name: "Показать хосты с уязвимостью Неподдерживаемая версия",
    });
    const cells = within(button.closest("tr")).getAllByRole("cell");
    expect(cells[3]).toHaveTextContent("—");
    expect(cells[7]).toHaveTextContent(
      "Операционная система, Установленное ПО",
    );
  });

  it("marks incomplete aggregates as a lower estimate", async () => {
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities/summary") {
        return Promise.resolve({
          ...SUMMARY,
          coverage: {
            ...SUMMARY.coverage,
            complete: false,
            truncated_groups: 2,
          },
        });
      }
      return Promise.resolve(responseFor(path));
    });
    renderDashboard();

    expect(await screen.findByRole("note")).toHaveTextContent(
      "Показатели неполные",
    );
    expect(screen.getByRole("note")).toHaveTextContent("нижней оценкой");
  });
});
