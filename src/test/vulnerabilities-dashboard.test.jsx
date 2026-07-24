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
  remediation: {
    case_id: "case-1",
    status: "open",
    assignee: null,
    due_at: "2026-07-18T08:00:00Z",
    overdue: false,
  },
};

const TRENDS = {
  scope: "all_asset_cards",
  from: "2026-06-12T00:00:00Z",
  to: "2026-07-12T00:00:00Z",
  bucket: "day",
  retention_days: 90,
  rows: [
    {
      bucket_start: "2026-07-10T00:00:00Z",
      snapshot_at: "2026-07-10T08:00:00Z",
      carried_forward: false,
      totals: {
        hosts_total: 200,
        affected_hosts: 138,
        findings: 4100,
        unique_vulnerabilities: 800,
        unique_cves: 630,
        high_risk_hosts: 54,
        unrated_vulnerabilities: 8,
      },
      by_severity: {
        critical: {
          findings: 120,
          affected_hosts: 20,
          unique_vulnerabilities: 30,
        },
        high: { findings: 240, affected_hosts: 42, unique_vulnerabilities: 80 },
      },
      coverage: {
        cards_total: 200,
        cards_with_findings: 180,
        truncated_groups: 0,
        complete: true,
      },
    },
    {
      bucket_start: "2026-07-11T00:00:00Z",
      snapshot_at: "2026-07-11T08:00:00Z",
      carried_forward: false,
      totals: SUMMARY.totals,
      by_severity: {
        critical: {
          findings: 128,
          affected_hosts: 22,
          unique_vulnerabilities: 31,
        },
        high: { findings: 250, affected_hosts: 45, unique_vulnerabilities: 84 },
      },
      coverage: SUMMARY.coverage,
    },
  ],
};

const RESOLUTION_STATS = {
  period_days: 30,
  confirmed_resolutions: 7,
  resolved_vulnerabilities: 4,
  resolved_hosts: 5,
  currently_resolved: 6,
  mean_time_to_resolve_days: 2.5,
  by_severity: [
    { severity: "critical", confirmed_resolutions: 3 },
    { severity: "high", confirmed_resolutions: 4 },
  ],
  trend: [
    { bucket_start: "2026-07-10T00:00:00Z", resolved_cases: 2 },
    { bucket_start: "2026-07-11T00:00:00Z", resolved_cases: 5 },
  ],
  recent: [
    {
      case_id: "case-resolved-1",
      cve: "CVE-2026-2001",
      title: "Исправленная уязвимость",
      asset_id: "asset-2",
      display_name: "server-02",
      ip_address: "10.0.0.2",
      severity: "critical",
      status: "resolved",
      resolution_confirmed_at: "2026-07-11T09:00:00Z",
    },
  ],
};

function responseFor(path, { total = 75, empty = false } = {}) {
  const url = new URL(path, "http://localhost");
  if (url.pathname === "/api/remediation/resolution-stats") {
    return RESOLUTION_STATS;
  }
  if (url.pathname === "/api/vulnerabilities/trends") {
    return empty ? { ...TRENDS, rows: [] } : TRENDS;
  }
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

function renderDashboard(
  currentUser = {
    permissions: ["assets.read", "remediation.read", "remediation.manage"],
  },
) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, gcTime: 0 },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <VulnerabilitiesDashboard currentUser={currentUser} showAlert={vi.fn()} />
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
    expect(
      screen.getByText("Как читать показатели: уязвимости, findings и хосты"),
    ).toBeInTheDocument();

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

  it("opens a host finding and starts its remediation task", async () => {
    let currentHost = HOST;
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/remediation/cases/start") {
        currentHost = {
          ...HOST,
          remediation: {
            ...HOST.remediation,
            status: "in_progress",
            assignee: "operator",
          },
        };
        return Promise.resolve(currentHost.remediation);
      }
      if (url.pathname === "/api/vulnerabilities/hosts") {
        return Promise.resolve({
          rows: [currentHost],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      return Promise.resolve(responseFor(path));
    });
    renderDashboard();

    const selectors = await screen.findAllByRole("button", {
      name: "Показать хосты с уязвимостью Удалённое выполнение кода",
    });
    fireEvent.click(selectors[0]);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Открыть находку на хосте server-01",
      }),
    );

    const finding = await screen.findByRole("dialog");
    expect(
      within(finding).getByRole("heading", {
        name: "Удалённое выполнение кода",
      }),
    ).toBeInTheDocument();
    fireEvent.click(
      within(finding).getByRole("button", { name: "Взять в работу" }),
    );

    await waitFor(() => {
      const call = api.mock.calls.find(
        ([path]) => path === "/api/remediation/cases/start",
      );
      expect(call).toBeDefined();
      expect(call[1].method).toBe("POST");
      expect(JSON.parse(call[1].body)).toEqual({
        asset_id: HOST.asset_id,
        vulnerability_selector: VULNERABILITY.selector,
        comment: "Задача запущена из вкладки «Уязвимости».",
        resume_exception: false,
      });
    });
    expect(await within(finding).findByText("В работе")).toBeInTheDocument();
  });

  it("opens resolution statistics and renders its KPIs", async () => {
    renderDashboard();

    fireEvent.click(
      await screen.findByRole("button", { name: "Статистика устранений" }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "Подтверждённые устранения",
      }),
    ).toBeInTheDocument();
    const metrics = await screen.findByLabelText("Показатели устранения");
    expect(
      within(metrics).getByText("Подтверждений").closest("article"),
    ).toHaveTextContent("7");
    expect(
      within(metrics).getByText("Уязвимостей").closest("article"),
    ).toHaveTextContent("4");
    expect(
      within(metrics).getByText("Хостов").closest("article"),
    ).toHaveTextContent("5");
    expect(
      within(metrics).getByText("Остаются устранёнными").closest("article"),
    ).toHaveTextContent("6");
    expect(await screen.findByText("CVE-2026-2001")).toBeInTheDocument();
    expect(
      api.mock.calls.some(([path]) => {
        const url = new URL(path, "http://localhost");
        return (
          url.pathname === "/api/remediation/resolution-stats" &&
          url.searchParams.get("days") === "30" &&
          url.searchParams.get("recent_limit") === "20"
        );
      }),
    ).toBe(true);
  });

  it("hides remediation data and actions without remediation permissions", async () => {
    renderDashboard({ permissions: ["assets.read"] });

    expect(
      screen.queryByRole("button", { name: "Статистика устранений" }),
    ).not.toBeInTheDocument();
    const selectors = await screen.findAllByRole("button", {
      name: "Показать хосты с уязвимостью Удалённое выполнение кода",
    });
    fireEvent.click(selectors[0]);

    expect(
      await screen.findByRole("button", {
        name: "Открыть находку на хосте server-01",
      }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Открыта")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Взять в работу/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /Открыть задачу/ }),
    ).not.toBeInTheDocument();
  });

  it("opens a mapped vulnerability passport from the vulnerability table", async () => {
    const mapped = {
      ...VULNERABILITY,
      passports: [
        {
          internal_id: "passport-1",
          external_id: "CVE-2026-1001",
          name: "Mapped passport",
          severity: "critical",
          score: "9.8",
        },
      ],
    };
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities") {
        return Promise.resolve({
          rows: [mapped],
          total: 1,
          limit: 50,
          offset: 0,
        });
      }
      if (url.pathname === "/api/vulnerability-passports/passport-1") {
        return Promise.resolve({
          passport: mapped.passports[0],
          raw: { name: "Mapped passport", severity: "critical" },
          source: "db",
        });
      }
      return Promise.resolve(responseFor(path));
    });
    renderDashboard();

    const hostButtons = await screen.findAllByRole("button", {
      name: `Показать хосты с уязвимостью ${VULNERABILITY.name}`,
    });
    fireEvent.click(hostButtons.at(-1));
    expect(
      await screen.findByRole("heading", {
        name: `Хосты с уязвимостью «${VULNERABILITY.name}»`,
      }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("server-01.example.test"),
    ).toBeInTheDocument();

    const passportButtons = await screen.findAllByRole("button", {
      name: `Открыть паспорт уязвимости ${VULNERABILITY.name}`,
    });
    fireEvent.click(passportButtons.at(-1));

    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toHaveTextContent("passport-1");
    expect(screen.getByRole("dialog")).toHaveTextContent("CVE-2026-1001");
    expect(api).toHaveBeenCalledWith("/api/vulnerability-passports/passport-1");
  });

  it("renders historical risk deltas and switches the aggregation period", async () => {
    renderDashboard();

    const heading = await screen.findByRole("heading", {
      name: "Динамика риска",
    });
    const section = heading.closest("section");
    expect(
      await within(section).findByText("+5 к прошлой точке"),
    ).toBeInTheDocument();
    expect(
      within(section).getByText("Критичность последнего снимка"),
    ).toBeInTheDocument();

    fireEvent.click(within(section).getByRole("button", { name: "90 дней" }));
    await waitFor(() =>
      expect(
        api.mock.calls.some(([path]) => {
          const url = new URL(path, "http://localhost");
          return (
            url.pathname === "/api/vulnerabilities/trends" &&
            url.searchParams.get("bucket") === "week"
          );
        }),
      ).toBe(true),
    );
  });

  it("shows explicit empty and retryable error states for risk history", async () => {
    let trendsFail = true;
    api.mockImplementation((path) => {
      const url = new URL(path, "http://localhost");
      if (url.pathname === "/api/vulnerabilities/trends") {
        if (trendsFail)
          return Promise.reject(new Error("История временно недоступна"));
        return Promise.resolve({ ...TRENDS, rows: [] });
      }
      return Promise.resolve(responseFor(path));
    });
    renderDashboard();

    expect(
      await screen.findByText("История временно недоступна"),
    ).toBeInTheDocument();
    trendsFail = false;
    fireEvent.click(
      screen.getByRole("button", { name: "Повторить загрузку истории" }),
    );
    expect(
      await screen.findByText(/История начнёт формироваться/),
    ).toBeInTheDocument();
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
