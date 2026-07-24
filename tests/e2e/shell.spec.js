import { expect, test } from "@playwright/test";

const API_ROUTE = /^https?:\/\/[^/]+\/api(?:\/|$)/;
const ROUTES = [
  "/connection",
  "/vm",
  "/tasks",
  "/operations",
  "/export",
  "/vulnerabilities",
  "/remediation",
  "/asset-cards",
  "/automations",
  "/asset-query",
  "/passports",
  "/assets",
];

const EMPTY_TRENDS = {
  scope: "all_saved_asset_cards",
  from: "2026-06-12T00:00:00Z",
  to: "2026-07-12T00:00:00Z",
  bucket: "day",
  retention_days: 90,
  rows: [],
};

const POPULATED_TRENDS = {
  ...EMPTY_TRENDS,
  rows: [
    {
      bucket_start: "2026-07-10T00:00:00Z",
      snapshot_at: "2026-07-10T08:30:00Z",
      carried_forward: false,
      totals: {
        affected_hosts: 12,
        findings: 37,
        unique_vulnerabilities: 9,
        high_risk_hosts: 5,
      },
      by_severity: {
        critical: { affected_hosts: 3, findings: 7 },
        high: { affected_hosts: 5, findings: 12 },
        medium: { affected_hosts: 7, findings: 13 },
        low: { affected_hosts: 3, findings: 4 },
        unknown: { affected_hosts: 1, findings: 1 },
      },
      coverage: {
        complete: true,
        cards_total: 12,
        cards_with_findings: 12,
        truncated_groups: 0,
      },
    },
    {
      bucket_start: "2026-07-11T00:00:00Z",
      snapshot_at: "2026-07-11T08:30:00Z",
      carried_forward: true,
      totals: {
        affected_hosts: 12,
        findings: 37,
        unique_vulnerabilities: 9,
        high_risk_hosts: 5,
      },
      by_severity: {
        critical: { affected_hosts: 3, findings: 7 },
        high: { affected_hosts: 5, findings: 12 },
        medium: { affected_hosts: 7, findings: 13 },
        low: { affected_hosts: 3, findings: 4 },
        unknown: { affected_hosts: 1, findings: 1 },
      },
      coverage: {
        complete: true,
        cards_total: 12,
        cards_with_findings: 12,
        truncated_groups: 0,
      },
    },
    {
      bucket_start: "2026-07-12T00:00:00Z",
      snapshot_at: "2026-07-12T08:30:00Z",
      carried_forward: false,
      totals: {
        affected_hosts: 14,
        findings: 41,
        unique_vulnerabilities: 10,
        high_risk_hosts: 6,
      },
      by_severity: {
        critical: { affected_hosts: 4, findings: 8 },
        high: { affected_hosts: 6, findings: 14 },
        medium: { affected_hosts: 8, findings: 14 },
        low: { affected_hosts: 3, findings: 4 },
        unknown: { affected_hosts: 1, findings: 1 },
      },
      coverage: {
        complete: false,
        cards_total: 15,
        cards_with_findings: 14,
        truncated_groups: 1,
      },
    },
  ],
};

const OPERATION = {
  operation_id: "operation-e2e-001",
  kind: "automation_run",
  status: "running",
  stage: "execute",
  progress_percent: 42,
  message: "E2E operation",
  subject: { id: "runbook-1", label: "E2E operation" },
  can_cancel: true,
  can_retry: false,
  created_at: "2026-07-12T08:00:00Z",
  updated_at: "2026-07-12T08:01:00Z",
  request: {},
  result: null,
  error: null,
  events: [],
};

async function installApiMock(page, overrides = {}) {
  await page.route(API_ROUTE, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const override =
      overrides[`${request.method()} ${url.pathname}`] ||
      overrides[url.pathname];

    if (override) {
      await override(route, url);
      return;
    }

    await route.fulfill({ json: defaultApiResponse(url.pathname) });
  });
}

function defaultApiResponse(path) {
  if (path === "/api/auth/me") {
    return { user: { id: 1, username: "e2e", display_name: "E2E Operator", role: "admin", permissions: [
      "system.read", "connection.read", "connection.manage", "tasks.read", "tasks.manage", "tasks.execute",
      "operations.read", "operations.cancel", "operations.retry", "assets.read", "asset_cards.read", "asset_cards.build",
      "asset_cards.manage", "passports.read", "passports.manage", "imports_exports.read", "imports_exports.manage",
      "remediation.read", "remediation.manage", "remediation.policy", "risk.read", "risk.manage", "automations.read",
      "automations.manage", "automations.execute", "notifications.read", "notifications.manage", "saved_views.read",
      "saved_views.manage", "diagnostics.write", "security.users.read", "security.roles.read", "security.audit.read",
    ] } };
  }
  if (path === "/api/auth/bootstrap-status") return { configured: true };
  if (path === "/api/session") {
    return {
      connected: true,
      api_url: "https://mpvm.example.test",
      token_url: "https://mpvm.example.test/connect/token",
      verify_tls: true,
    };
  }
  if (path === "/api/defaults") {
    return {
      client_id: "mpx",
      scope: "",
      utc_offset: "+05:00",
      asset_card_pdql: "",
      vulnerability_passport_pdql: "",
    };
  }
  if (path === "/api/system/status") {
    return {
      state: "ok",
      checked_at: "2026-07-12T08:00:00Z",
      components: {
        application: { state: "ok" },
        database: { state: "ok" },
        mpvm: { state: "ok" },
        background_workers: { state: "ok" },
      },
    };
  }
  if (path === "/api/operations/summary") {
    return {
      total: 0,
      active: 0,
      attention: 0,
      by_status: {},
      by_kind: {},
      updated_at: "2026-07-12T08:00:00Z",
    };
  }
  if (path === "/api/operations") return { rows: [], total: 0 };
  if (path === "/api/vm/overview") return { active_workflows: 0, active_operations: 0, open_cases: 0, overdue_cases: 0, awaiting_verification: 0, asset_count: 0, attention: [], recent_workflows: [] };
  if (path === "/api/vm/workflows") return { rows: [], total: 0 };
  if (path === "/api/remediation/campaigns") return { rows: [], total: 0 };
  if (path === "/api/scanner-tasks") return [];
  if (path === "/api/assets/summary") {
    return { assets: 0, software: 0, findings: 0, cve_rows: 0 };
  }
  if (path === "/api/assets") return { rows: [], total: 0 };
  if (path === "/api/vulnerabilities/trends") return EMPTY_TRENDS;
  if (path === "/api/vulnerabilities/summary") {
    return {
      scope: "all_saved_asset_cards",
      generated_at: "2026-07-12T08:00:00Z",
      totals: {},
      coverage: {
        complete: true,
        cards_total: 0,
        cards_with_findings: 0,
        truncated_groups: 0,
      },
      by_severity: [],
      top_vulnerabilities: [],
      top_hosts: [],
    };
  }
  if (path === "/api/vulnerabilities") return { rows: [], total: 0 };
  if (path === "/api/vulnerabilities/hosts") return { rows: [], total: 0 };
  if (path === "/api/remediation/cases") return { rows: [], total: 0 };
  if (path === "/api/remediation/summary") return { open: 0, overdue: 0, near_due: 0, risk_accepted: 0, resolved_30d: 0 };
  if (path === "/api/remediation/policy") return { critical_days: 7, high_days: 30, medium_days: 90, low_days: 180, near_due_days: 7 };
  if (path === "/api/notifications") return { rows: [], unread: 0 };
  if (path === "/api/asset-cards/build-jobs/active") return { job: null };
  if (path === "/api/vulnerability-passports/detail-jobs/active") {
    return { job: null };
  }
  return { rows: [], total: 0 };
}

function collectPageErrors(page) {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  return errors;
}

async function expectRoute(page, path) {
  await expect(page).toHaveURL(new RegExp(`${path.replaceAll("/", "\\/")}$`));
  const heading = page.locator("main.workspace h1");
  await expect(heading).toHaveCount(1);
  await expect(heading).toBeVisible();
  await expect(heading).not.toHaveText("");
  await expect(page.locator(`.nav a[href="${path}"]`)).toHaveAttribute(
    "aria-current",
    "page",
  );
}

test("application shell keeps stable routes and navigation", async ({
  page,
}) => {
  await installApiMock(page);

  await page.goto("/connection");
  await expectRoute(page, "/connection");

  await page.locator('.nav a[href="/operations"]').click();
  await expectRoute(page, "/operations");

  await page.locator('.nav a[href="/automations"]').click();
  await expectRoute(page, "/automations");
  await expect(page.getByRole("tabpanel")).toBeVisible();
});

for (const viewport of [
  { name: "desktop", width: 1440, height: 900 },
  { name: "tablet", width: 1024, height: 768 },
]) {
  test.describe(`${viewport.name} route smoke`, () => {
    test.use({ viewport });

    test("renders all application routes", async ({ page }) => {
      const pageErrors = collectPageErrors(page);
      await installApiMock(page);
      await page.goto(ROUTES[0]);

      for (const path of ROUTES) {
        await test.step(path, async () => {
          if (path !== ROUTES[0]) {
            await page.locator(`.nav a[href="${path}"]`).click();
          }
          await expectRoute(page, path);
        });
      }

      expect(pageErrors).toEqual([]);
    });
  });
}

test("VM Management launches and tracks a controlled scan workflow", async ({ page }) => {
  const workflow = {
    workflow_id: "workflow-e2e-1", kind: "scan", status: "running", stage: "postprocess",
    progress_percent: 48, can_cancel: true, can_retry: false,
    steps: [
      { position: 1, step_key: "validation", status: "completed", progress_percent: 100 },
      { position: 2, step_key: "scan", status: "completed", progress_percent: 100 },
      { position: 3, step_key: "postprocess", status: "running", progress_percent: 24, message: "Загрузка карточек" },
      { position: 4, step_key: "reconcile", status: "pending", progress_percent: 0 },
    ],
  };
  await installApiMock(page, {
    "/api/scanner-tasks": (route) => route.fulfill({ json: [{ mp_task_id: "task-e2e-1", payload: { name: "Production perimeter" } }] }),
    "POST /api/vm/workflows/scan": (route) => route.fulfill({ status: 202, json: { workflow_id: workflow.workflow_id, status: "queued", workflow: { ...workflow, status: "queued" } } }),
    "/api/vm/workflows/workflow-e2e-1": (route) => route.fulfill({ json: workflow }),
  });
  await page.goto("/vm");
  await page.getByLabel("Задача MP VM").selectOption("task-e2e-1");
  await page.getByRole("button", { name: "Запустить конвейер" }).click();
  const dialog = page.getByRole("dialog", { name: "Полное сканирование" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Загрузка карточек")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Остановить" })).toBeVisible();
});

test("remediation lifecycle reaches scan-confirmed resolution", async ({ page }) => {
  let caseStatus = "open";
  let assignee = null;
  const remediationCase = () => ({
    case_id: "case-e2e-1", version: caseStatus === "open" ? 1 : 2,
    status: caseStatus, severity: "critical", cve: "CVE-2026-9001",
    title: "E2E critical vulnerability", asset_id: "asset-e2e-1",
    display_name: "server-e2e", assignee, overdue: caseStatus !== "resolved",
    due_at: "2026-07-01T08:00:00Z", events: [],
  });
  await installApiMock(page, {
    "/api/remediation/cases": (route) => route.fulfill({ json: { rows: [remediationCase()], total: 1 } }),
    "/api/remediation/summary": (route) => route.fulfill({ json: { open: caseStatus === "resolved" ? 0 : 1, overdue: caseStatus === "resolved" ? 0 : 1, near_due: 0, risk_accepted: 0, resolved_30d: caseStatus === "resolved" ? 1 : 0 } }),
    "/api/remediation/policy": (route) => route.fulfill({ json: { critical_days: 7, high_days: 30, medium_days: 90, low_days: 180, near_due_days: 7 } }),
    "/api/remediation/cases/case-e2e-1": (route) => route.fulfill({ json: remediationCase() }),
    "PATCH /api/remediation/cases/case-e2e-1": async (route) => {
      const payload = route.request().postDataJSON();
      expect(payload.expected_version).toBe(1);
      caseStatus = payload.status;
      assignee = payload.assignee;
      await route.fulfill({ json: remediationCase() });
    },
    "POST /api/asset-cards/build-jobs": async (route) => {
      caseStatus = "resolved";
      await route.fulfill({ status: 202, json: { job: { job_id: "job-e2e-1", status: "queued" } } });
    },
  });

  await page.goto("/remediation");
  await expect(page.getByText("CVE-2026-9001")).toBeVisible();
  await expect(page.getByText("Просрочено").last()).toBeVisible();
  await page.getByRole("button", { name: "CVE-2026-9001" }).click();
  await page.getByLabel("Ответственный").fill("Иван Петров");
  await page.getByLabel("Статус").last().selectOption("in_progress");
  await page.getByRole("button", { name: "Сохранить", exact: true }).click();
  await expect(page.getByText("Иван Петров").first()).toBeVisible();

  await expect(page.getByRole("cell", { name: "Устранена" })).toBeVisible();
});

test.describe("mobile shell", () => {
  test.use({ viewport: { width: 360, height: 800 } });

  test("keeps the active navigation item visible and navigates at 360px", async ({
    page,
  }) => {
    await installApiMock(page);
    await page.goto("/assets");
    await expectRoute(page, "/assets");

    const activeItem = page.locator('.nav a[aria-current="page"]');
    await expect
      .poll(() =>
        activeItem.evaluate((element) => {
          const scroller = element.closest(".nav");
          const itemBox = element.getBoundingClientRect();
          const scrollerBox = scroller.getBoundingClientRect();
          return (
            itemBox.left >= scrollerBox.left - 1 &&
            itemBox.right <= scrollerBox.right + 1
          );
        }),
      )
      .toBe(true);

    await page.locator('.nav a[href="/operations"]').click();
    await expectRoute(page, "/operations");
    await expect(page.locator(".operation-filters")).toBeVisible();
  });
});

test("operation drawer traps focus, closes with Escape, and blocks a duplicate cancel", async ({
  page,
}) => {
  let cancelRequests = 0;
  await installApiMock(page, {
    "/api/operations": (route) =>
      route.fulfill({ json: { rows: [OPERATION], total: 1 } }),
    "/api/operations/operation-e2e-001": (route) =>
      route.fulfill({ json: OPERATION }),
    "POST /api/operations/operation-e2e-001/cancel": async (route) => {
      cancelRequests += 1;
      await new Promise((resolve) => setTimeout(resolve, 150));
      await route.fulfill({
        json: { ...OPERATION, status: "cancelling", can_cancel: false },
      });
    },
  });

  await page.goto("/operations");
  const operationRow = page
    .locator('code[title="operation-e2e-001"]')
    .locator("xpath=ancestor::tr");
  await expect(operationRow).toBeVisible();

  const openButton = operationRow.locator(".row-actions button").first();
  await openButton.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("button").first()).toBeFocused();

  await page.keyboard.press("Shift+Tab");
  await expect(dialog.locator("a[href*='/diagnostics']")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(openButton).toBeFocused();

  const cancelButton = operationRow.locator(".row-actions button").nth(1);
  await cancelButton.dblclick({ delay: 10 });
  await expect.poll(() => cancelRequests).toBe(1);
});

test.describe("risk history states", () => {
  test("renders populated history with deltas, severity, and coverage warning", async ({
    page,
  }) => {
    await installApiMock(page, {
      "/api/vulnerabilities/trends": (route) =>
        route.fulfill({ json: POPULATED_TRENDS }),
    });

    await page.goto("/vulnerabilities");
    const history = page.locator(".risk-trend");
    await expect(history.locator(".risk-trend__chart")).toBeVisible();
    await expect(history.locator(".risk-trend__delta")).toHaveCount(4);
    await expect(history.locator(".risk-trend__severity-card")).toBeVisible();
    await expect(history.getByRole("note")).toBeVisible();
  });

  test("renders a distinct empty history state", async ({ page }) => {
    await installApiMock(page, {
      "/api/vulnerabilities/trends": (route) =>
        route.fulfill({ json: EMPTY_TRENDS }),
    });

    await page.goto("/vulnerabilities");
    const history = page.locator(".risk-trend");
    await expect(history.locator(".vulnerability-empty")).toBeVisible();
    await expect(history.locator(".risk-trend__chart")).toHaveCount(0);
  });

  test("renders an error and can retry history independently", async ({
    page,
  }) => {
    let failHistory = true;
    await installApiMock(page, {
      "/api/vulnerabilities/trends": (route) =>
        failHistory
          ? route.fulfill({
              status: 503,
              json: {
                detail: {
                  code: "HISTORY_UNAVAILABLE",
                  operator_message: "History unavailable",
                  retryable: true,
                },
              },
            })
          : route.fulfill({ json: EMPTY_TRENDS }),
    });

    await page.goto("/vulnerabilities");
    const history = page.locator(".risk-trend");
    const error = history.getByRole("alert");
    await expect(error).toContainText("History unavailable");

    failHistory = false;
    await error.locator("button").click();
    await expect(history.locator(".vulnerability-empty")).toBeVisible();
    await expect(error).toHaveCount(0);
  });
});
