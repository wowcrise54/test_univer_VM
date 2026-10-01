import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client.js";
import { RemediationPage } from "../pages/RemediationPage.jsx";

vi.mock("../api/client.js", () => ({ api: vi.fn() }));

const CASE = {
  case_id: "case-1",
  version: 4,
  status: "open",
  severity: "critical",
  cve: "CVE-2026-101",
  title: "RCE",
  asset_id: "asset-1",
  display_name: "server-1",
  ip_address: "192.0.2.1",
  overdue: true,
  due_at: "2026-10-04T12:00:00Z",
  passport_internal_id: "passport/a",
  verification_workflow_id: "workflow/a",
  events: [
    {
      event_id: 1,
      event_type: "created",
      created_at: "2026-10-01T12:00:00Z",
      comment: "Из сканирования",
    },
    { event_id: 2, event_type: "changed" },
  ],
};
const SECOND = {
  ...CASE,
  case_id: "case-2",
  cve: "CVE-2026-102",
  title: "Exposure",
  status: "in_progress",
  severity: "high",
  display_name: null,
  ip_address: null,
  fqdn: "server.example",
  overdue: false,
  due_at: null,
};
const POLICY = {
  critical_days: 7,
  high_days: 30,
  medium_days: 90,
  low_days: 180,
  near_due_days: 7,
};
let rows, riskRows, campaigns, groups, failures, alert;

function key(path, options) {
  return `${options?.method || "GET"} ${path}`;
}
function calls(path, method = "GET") {
  return api.mock.calls.filter(
    ([url, opts]) => url === path && (opts?.method || "GET") === method,
  );
}
function payload(path, method) {
  return JSON.parse(calls(path, method).at(-1)[1].body);
}
function riskRegion() {
  return within(screen.getByRole("region", { name: "Приоритет риска" }));
}
async function openRisk() {
  fireEvent.click(
    screen.getByText("Приоритизация и кампании", { exact: true }),
  );
  await waitFor(() =>
    expect(
      riskRegion().getByLabelText("Выбрать CVE-2026-101"),
    ).toBeInTheDocument(),
  );
}
async function openCase() {
  fireEvent.click(await screen.findByRole("button", { name: CASE.cve }));
  await screen.findByLabelText("Ответственный");
}
async function ready() {
  await screen.findByRole("button", { name: CASE.cve });
}
function mount() {
  return render(<RemediationPage showAlert={alert} />);
}

beforeEach(() => {
  api.mockReset();
  alert = vi.fn();
  failures = new Map();
  window.history.replaceState({}, "", "/remediation");
  rows = [CASE, SECOND];
  riskRows = [CASE, SECOND].map((row, index) => ({
    ...row,
    risk_score: 91 - index,
    risk_level: "urgent",
    cvss_score: index ? null : 9.8,
    criticality: "critical",
    environment: "production",
    exposure: "external",
    risk_explanation: "SLA просрочен",
  }));
  campaigns = [
    {
      campaign_id: "campaign",
      name: "October",
      resolved: 1,
      total: 2,
      in_progress: 1,
      overdue: 0,
      risk_accepted: 0,
      asset_group_id: "group/a",
      asset_group_name: "Servers",
    },
    { campaign_id: "fallback", name: "Fallback", asset_group_id: "group/b" },
    { campaign_id: "plain", name: "Plain" },
  ];
  groups = [
    {
      group_id: "parent",
      name: "Parent",
      children: [{ group_id: "child", name: "Child" }],
    },
  ];
  api.mockImplementation(async (path, options) => {
    if (failures.has(key(path, options)))
      throw failures.get(key(path, options));
    if (path.startsWith("/api/remediation/cases?") && !options)
      return { rows, total: rows.length };
    if (path === "/api/remediation/summary")
      return { open: 2, overdue: 1, near_due: 1, mttr_days: 2 };
    if (path === "/api/remediation/policy") return POLICY;
    if (path === "/api/remediation/cases/bulk-update")
      return { updated_count: rows.length };
    if (path === "/api/remediation/cases/case-1")
      return options
        ? { ...CASE, ...JSON.parse(options.body), version: 5 }
        : CASE;
    if (path.startsWith("/api/risk/queue"))
      return { rows: riskRows, total: riskRows.length };
    if (path === "/api/risk/summary")
      return { urgent: 2, risk_model_version: "local-risk-v2" };
    if (path === "/api/remediation/campaigns")
      return options ? {} : { rows: campaigns };
    if (path === "/api/asset-groups/tree") return { rows: groups };
    if (path === "/api/assets/context") return {};
    if (path === "/api/assets/context/import")
      return { matched: 1, unmatched: ["unknown"], errors: [] };
    throw new Error(`Unexpected ${key(path, options)}`);
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.history.replaceState({}, "", "/");
});

describe("remediation workflows", () => {
  it("serializes search, status, severity and overdue filters", async () => {
    mount();
    await ready();
    fireEvent.change(screen.getByLabelText("Поиск кейсов"), {
      target: { value: "CVE & host" },
    });
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/remediation/cases?q=CVE+%26+host"),
    );
    fireEvent.click(
      screen.getByText("Фильтры и массовые действия", { exact: true }),
    );
    fireEvent.change(screen.getByLabelText("Статус"), {
      target: { value: "in_progress" },
    });
    fireEvent.change(screen.getByLabelText("Критичность"), {
      target: { value: "high" },
    });
    fireEvent.click(screen.getByLabelText("Только просроченные"));
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith(
        "/api/remediation/cases?q=CVE+%26+host&status=in_progress&severity=high&overdue=true",
      ),
    );
  });

  it("bulk updates only checked cases and clears the selection after success", async () => {
    mount();
    await ready();
    fireEvent.click(
      screen.getByText("Фильтры и массовые действия", { exact: true }),
    );
    expect(
      screen.getByRole("button", { name: "Взять в работу (0)" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Выбрать RCE"));
    fireEvent.click(screen.getByLabelText("Выбрать Exposure"));
    fireEvent.click(screen.getByLabelText("Выбрать Exposure"));
    fireEvent.click(screen.getByRole("button", { name: "Взять в работу (1)" }));
    await waitFor(() =>
      expect(alert).toHaveBeenCalledWith("Обновлено кейсов: 2.", "success"),
    );
    expect(payload("/api/remediation/cases/bulk-update", "POST")).toEqual({
      case_ids: ["case-1"],
      status: "in_progress",
      comment: "Массовое обновление",
    });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Взять в работу (0)" }),
      ).toBeDisabled(),
    );
  });

  it("drops checked cases removed by a subsequent refresh", async () => {
    mount();
    await ready();
    fireEvent.click(screen.getByLabelText("Выбрать RCE"));
    rows = [SECOND];
    fireEvent.click(
      screen.getByRole("button", { name: "Обновить", exact: true }),
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("Выбрать RCE")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByText("Фильтры и массовые действия", { exact: true }),
    );
    expect(
      screen.getByRole("button", { name: "Взять в работу (0)" }),
    ).toBeDisabled();
  });

  it("saves optimistic version, nullable fields and an exception reason", async () => {
    mount();
    await openCase();
    const editor = within(document.querySelector(".remediation-detail"));
    fireEvent.change(editor.getByLabelText("Статус"), {
      target: { value: "risk_accepted" },
    });
    fireEvent.change(editor.getByLabelText("Ответственный"), {
      target: { value: "security" },
    });
    fireEvent.change(editor.getByLabelText("Срок"), { target: { value: "" } });
    fireEvent.change(editor.getByLabelText("Обоснование исключения"), {
      target: { value: "Изолированный сегмент" },
    });
    fireEvent.change(editor.getByLabelText("Исключение действует до"), {
      target: { value: "2026-12-01T12:00" },
    });
    fireEvent.change(editor.getByLabelText("Комментарий"), {
      target: { value: "Согласовано" },
    });
    fireEvent.click(
      editor.getByRole("button", { name: "Сохранить", exact: true }),
    );
    await waitFor(() =>
      expect(alert).toHaveBeenCalledWith("Кейс обновлён.", "success"),
    );
    expect(payload("/api/remediation/cases/case-1", "PATCH")).toEqual({
      status: "risk_accepted",
      assignee: "security",
      due_at: null,
      exception_reason: "Изолированный сегмент",
      exception_expires_at: "2026-12-01T12:00",
      comment: "Согласовано",
      expected_version: 4,
    });
    fireEvent.click(editor.getByRole("button", { name: "Закрыть" }));
    expect(screen.queryByLabelText("Ответственный")).not.toBeInTheDocument();
  });

  it("preserves history and encodes navigation to related evidence", async () => {
    mount();
    await openCase();
    const editor = within(document.querySelector(".remediation-detail"));
    fireEvent.click(editor.getByText("Связанные данные", { exact: true }));
    expect(
      editor.getByRole("link", { name: "Карточка актива" }),
    ).toHaveAttribute("href", "/asset-cards?asset=asset-1");
    expect(editor.getByRole("link", { name: "Паспорт" })).toHaveAttribute(
      "href",
      "/passports?passport=passport%2Fa",
    );
    expect(editor.getByRole("link", { name: "Проверка" })).toHaveAttribute(
      "href",
      "/vm?workflow=workflow%2Fa",
    );
    fireEvent.click(editor.getByText("История", { exact: true }));
    expect(editor.getByText("Из сканирования")).toBeInTheDocument();
    expect(editor.getByText("changed")).toBeInTheDocument();
  });

  it("opens a case from the URL and restores legacy risk fields", async () => {
    window.history.replaceState({}, "", "/remediation?case=case-1");
    api.mockImplementationOnce(() => Promise.resolve({ rows: [], total: 0 }));
    const original = api.getMockImplementation();
    api.mockImplementation((path, options) =>
      path === "/api/remediation/cases/case-1"
        ? Promise.resolve({
            ...CASE,
            status: "false_positive",
            due_at: null,
            risk_reason: "Legacy reason",
            risk_expires_at: "2026-12-01T12:00:00Z",
            events: undefined,
            passport_internal_id: null,
            verification_workflow_id: null,
          })
        : original(path, options),
    );
    mount();
    expect(await screen.findByLabelText("Обоснование исключения")).toHaveValue(
      "Legacy reason",
    );
    expect(screen.getByLabelText("Исключение действует до").value).toMatch(
      /^2026-12-01T/,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Сохранить", exact: true }),
    );
    // The replacement transport above returns a synthetic detail; the original path's version is not discarded.
    await waitFor(() =>
      expect(calls("/api/remediation/cases/case-1", "PATCH")).toHaveLength(1),
    );
    expect(
      payload("/api/remediation/cases/case-1", "PATCH").expected_version,
    ).toBe(4);
  });

  it.each([false, true])(
    "saves policy with apply_to_open=%s and numeric day values",
    async (apply) => {
      mount();
      await ready();
      fireEvent.click(screen.getByText("Настройка SLA", { exact: true }));
      for (const [label, value] of [
        ["critical", "3"],
        ["high", "14"],
        ["medium", "60"],
        ["low", "120"],
        ["Скоро срок", "0"],
      ])
        fireEvent.change(screen.getByLabelText(new RegExp(`^${label}`)), {
          target: { value },
        });
      fireEvent.click(
        screen.getByRole("button", {
          name: apply
            ? "Сохранить и пересчитать открытые"
            : "Сохранить для новых",
        }),
      );
      await waitFor(() =>
        expect(alert).toHaveBeenCalledWith(
          "SLA-политика сохранена.",
          "success",
        ),
      );
      expect(payload("/api/remediation/policy", "PUT")).toEqual({
        critical_days: 3,
        high_days: 14,
        medium_days: 60,
        low_days: 120,
        near_due_days: 0,
        apply_to_open: apply,
      });
    },
  );

  it("shows list failures and recovers without losing the page", async () => {
    failures.set("GET /api/remediation/cases?", {
      operatorMessage: "Нет доступа к кейсам",
      message: "internal",
    });
    mount();
    expect(await screen.findByText("Нет доступа к кейсам")).toBeInTheDocument();
    failures.clear();
    rows = [];
    fireEvent.click(
      screen.getByRole("button", { name: "Обновить", exact: true }),
    );
    expect(await screen.findByText("Кейсы не найдены.")).toBeInTheDocument();
    expect(screen.queryByText("Нет доступа к кейсам")).not.toBeInTheDocument();
  });

  it.each(["detail", "save", "bulk", "policy"])(
    "surfaces %s operation errors and allows a retry",
    async (operation) => {
      const route =
        operation === "bulk"
          ? "/api/remediation/cases/bulk-update"
          : operation === "policy"
            ? "/api/remediation/policy"
            : "/api/remediation/cases/case-1";
      const method = {
        detail: "GET",
        save: "PATCH",
        bulk: "POST",
        policy: "PUT",
      }[operation];
      mount();
      await ready();
      if (operation === "save") await openCase();
      if (operation === "bulk") {
        fireEvent.click(
          screen.getByText("Фильтры и массовые действия", { exact: true }),
        );
        fireEvent.click(screen.getByLabelText("Выбрать RCE"));
      }
      if (operation === "policy")
        fireEvent.click(screen.getByText("Настройка SLA", { exact: true }));
      failures.set(`${method} ${route}`, new Error("Conflict"));
      const action = () =>
        fireEvent.click(
          screen.getByRole("button", {
            name: {
              detail: CASE.cve,
              save: "Сохранить",
              bulk: "Взять в работу (1)",
              policy: "Сохранить для новых",
            }[operation],
            exact: true,
          }),
        );
      action();
      await waitFor(() =>
        expect(alert).toHaveBeenCalledWith("Conflict", "error"),
      );
      failures.clear();
      action();
      await waitFor(() => expect(calls(route, method)).toHaveLength(2));
      if (operation === "detail") await screen.findByLabelText("Ответственный");
      else
        await waitFor(() =>
          expect(alert.mock.calls.some(([, type]) => type === "success")).toBe(
            true,
          ),
        );
    },
  );

  it("reports URL detail errors through the operator message", async () => {
    window.history.replaceState({}, "", "/remediation?case=case-1");
    failures.set("GET /api/remediation/cases/case-1", {
      operatorMessage: "Кейс удалён",
    });
    mount();
    await waitFor(() =>
      expect(alert).toHaveBeenCalledWith("Кейс удалён", "error"),
    );
  });
});

describe("risk workspace workflows", () => {
  it("loads nested groups, campaign summaries and risk-level filters", async () => {
    mount();
    await openRisk();
    const risk = riskRegion();
    expect(risk.getByRole("option", { name: "Child" })).toHaveValue("child");
    fireEvent.change(risk.getByLabelText("Уровень риска"), {
      target: { value: "urgent" },
    });
    await waitFor(() =>
      expect(api).toHaveBeenCalledWith("/api/risk/queue?level=urgent"),
    );
    fireEvent.click(risk.getByText("Кампании устранения (3)"));
    expect(risk.getByRole("link", { name: "Servers" })).toHaveAttribute(
      "href",
      "/asset-groups?group=group%2Fa",
    );
    expect(risk.getByRole("link", { name: "Группа активов" })).toHaveAttribute(
      "href",
      "/asset-groups?group=group%2Fb",
    );
  });

  it("deduplicates selected assets when changing their business context", async () => {
    mount();
    await openRisk();
    const risk = riskRegion();
    fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-101"));
    fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-102"));
    fireEvent.change(risk.getByLabelText("Критичность актива"), {
      target: { value: "high" },
    });
    fireEvent.change(risk.getByLabelText("Среда"), {
      target: { value: "test" },
    });
    fireEvent.change(risk.getByLabelText("Доступность"), {
      target: { value: "isolated" },
    });
    fireEvent.click(risk.getByRole("button", { name: "Применить к активам" }));
    await waitFor(() =>
      expect(alert).toHaveBeenCalledWith(
        "Контекст обновлён для активов: 1.",
        "success",
      ),
    );
    expect(payload("/api/assets/context", "PATCH")).toEqual({
      asset_ids: ["asset-1"],
      values: {
        criticality: "high",
        environment: "test",
        exposure: "isolated",
      },
    });
  });

  it.each(["child", ""])(
    "creates a campaign with optional group %s and clears selected cases",
    async (group) => {
      vi.spyOn(window, "prompt").mockReturnValue("October patching");
      mount();
      await openRisk();
      const risk = riskRegion();
      fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-101"));
      fireEvent.change(risk.getByLabelText("Группа активов кампании"), {
        target: { value: group },
      });
      fireEvent.click(
        risk.getByRole("button", { name: "Создать кампанию (1)" }),
      );
      await waitFor(() =>
        expect(alert).toHaveBeenCalledWith("Кампания создана.", "success"),
      );
      expect(payload("/api/remediation/campaigns", "POST")).toEqual({
        name: "October patching",
        case_ids: ["case-1"],
        asset_group_id: group || null,
      });
      await waitFor(() =>
        expect(
          risk.getByRole("button", { name: "Создать кампанию (0)" }),
        ).toBeDisabled(),
      );
    },
  );

  it("does not submit a cancelled campaign and removes deselected rows", async () => {
    vi.spyOn(window, "prompt").mockReturnValue(null);
    mount();
    await openRisk();
    const risk = riskRegion();
    fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-101"));
    fireEvent.click(risk.getByRole("button", { name: "Создать кампанию (1)" }));
    expect(calls("/api/remediation/campaigns", "POST")).toHaveLength(0);
    fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-101"));
    expect(
      risk.getByRole("button", { name: "Применить к активам" }),
    ).toBeDisabled();
  });

  it.each([false, true])(
    "imports context CSV with warning=%s and reports unmatched assets",
    async (hasErrors) => {
      const original = api.getMockImplementation();
      api.mockImplementation((path, options) =>
        path === "/api/assets/context/import"
          ? Promise.resolve({
              matched: 2,
              ...(hasErrors
                ? { unmatched: ["missing"], errors: [{ row: 3 }] }
                : {}),
            })
          : original(path, options),
      );
      mount();
      await openRisk();
      const input = screen.getByLabelText("Импорт контекста CSV");
      const file = new File(["asset_id,owner\nasset-1,team"], "context.csv", {
        type: "text/csv",
      });
      Object.defineProperty(file, "text", {
        value: vi.fn().mockResolvedValue("asset_id,owner\nasset-1,team"),
      });
      fireEvent.change(input, { target: { files: [file] } });
      await waitFor(() =>
        expect(alert).toHaveBeenCalledWith(
          `CSV обработан: сопоставлено 2, не найдено ${hasErrors ? 1 : 0}.`,
          hasErrors ? "warning" : "success",
        ),
      );
      expect(payload("/api/assets/context/import", "POST")).toEqual({
        csv_text: "asset_id,owner\nasset-1,team",
      });
      expect(input.value).toBe("");
      const count = calls("/api/assets/context/import", "POST").length;
      fireEvent.change(input, { target: { files: [] } });
      expect(calls("/api/assets/context/import", "POST")).toHaveLength(count);
    },
  );

  it.each(["context", "campaign", "import"])(
    "surfaces %s errors without clearing an unsuccessful selection",
    async (operation) => {
      vi.spyOn(window, "prompt").mockReturnValue("Patch");
      mount();
      await openRisk();
      const risk = riskRegion();
      fireEvent.click(risk.getByLabelText("Выбрать CVE-2026-101"));
      const route = {
        context: "PATCH /api/assets/context",
        campaign: "POST /api/remediation/campaigns",
        import: "POST /api/assets/context/import",
      }[operation];
      failures.set(route, {
        operatorMessage: "Операция отклонена",
        message: "internal",
      });
      if (operation === "import") {
        const file = new File(["csv"], "context.csv");
        Object.defineProperty(file, "text", { value: async () => "csv" });
        fireEvent.change(screen.getByLabelText("Импорт контекста CSV"), {
          target: { files: [file] },
        });
      } else
        fireEvent.click(
          risk.getByRole("button", {
            name:
              operation === "context"
                ? "Применить к активам"
                : "Создать кампанию (1)",
          }),
        );
      await waitFor(() =>
        expect(alert).toHaveBeenCalledWith("Операция отклонена", "error"),
      );
      expect(risk.getByLabelText("Выбрать CVE-2026-101")).toBeChecked();
    },
  );

  it.each([true, false])(
    "recovers risk loading errors, including unavailable PostgreSQL=%s",
    async (database) => {
      failures.set(
        "GET /api/risk/queue",
        database
          ? { code: "DATABASE_UNAVAILABLE", message: "backend details" }
          : { operatorMessage: "Нет доступа к риску" },
      );
      mount();
      fireEvent.click(
        screen.getByText("Приоритизация и кампании", { exact: true }),
      );
      const risk = riskRegion();
      await waitFor(() =>
        expect(risk.getByRole("alert")).toHaveTextContent(
          database ? "Примените миграции" : "Нет доступа к риску",
        ),
      );
      failures.clear();
      fireEvent.click(risk.getByRole("button", { name: "Повторить" }));
      await waitFor(() =>
        expect(risk.getByLabelText("Выбрать CVE-2026-101")).toBeInTheDocument(),
      );
      expect(risk.queryByRole("alert")).not.toBeInTheDocument();
    },
  );

  it("tolerates missing group permissions and empty optional response fields", async () => {
    failures.set("GET /api/asset-groups/tree", new Error("Forbidden"));
    const original = api.getMockImplementation();
    api.mockImplementation((path, options) =>
      ["/api/risk/queue", "/api/remediation/campaigns"].includes(path)
        ? Promise.resolve({})
        : original(path, options),
    );
    mount();
    fireEvent.click(
      screen.getByText("Приоритизация и кампании", { exact: true }),
    );
    await waitFor(() =>
      expect(
        riskRegion().queryByText("Расчёт приоритета…"),
      ).not.toBeInTheDocument(),
    );
    expect(
      riskRegion().getByLabelText("Группа активов кампании").options,
    ).toHaveLength(1);
    expect(riskRegion().queryByRole("alert")).not.toBeInTheDocument();
  });
});
