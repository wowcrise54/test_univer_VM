import { expect, test } from "@playwright/test";

const API_ROUTE = /^https?:\/\/[^/]+\/api(?:\/|$)/;
const ROUTES = [
  "/connection",
  "/vm",
  "/tasks",
  "/operations",
  "/export",
  "/dashboards",
  "/vulnerabilities",
  "/remediation",
  "/asset-cards",
  "/automations",
  "/asset-query",
  "/passports",
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

test("passport refresh disappears on completion and stays hidden after reload", async ({
  page,
}) => {
  let completed = false;
  await installApiMock(page, {
    "/api/vulnerability-passports/refresh-jobs/latest": (route) =>
      route.fulfill({
        json: {
          job: {
            operation_id: "refresh-ui",
            status: completed ? "completed" : "running",
            progress_percent: completed ? 100 : 42,
          },
        },
      }),
    "/api/vulnerability-passports/refresh-jobs/refresh-ui": (route) => {
      completed = true;
      return route.fulfill({
        json: {
          operation_id: "refresh-ui",
          status: "completed",
          progress_percent: 100,
          result: { db: { saved: 1 } },
        },
      });
    },
  });
  await page.goto("/passports");
  await expect(
    page.getByRole("progressbar", { name: "Обновление списка паспортов" }),
  ).toBeVisible();
  await expect(
    page.getByRole("progressbar", { name: "Обновление списка паспортов" }),
  ).toHaveCount(0);
  await expect(
    page.getByText(/Обновление завершено: сохранено 1 паспортов/),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("button", { name: "Обновить", exact: true }),
  ).toBeEnabled();
  await expect(page.locator(".passport-job--completed")).toHaveCount(0);
});

for (const width of [1440, 1011, 768, 390]) {
  test(`asset query controls stay inside their frames at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript(() =>
      localStorage.setItem("mpvm-client-theme", "dark"),
    );
    await installApiMock(page);
    await page.goto("/asset-query");
    await page.getByText("Сохранение выборки", { exact: true }).click();
    const group = page.locator("#asset-query > .query-group");
    await group
      .locator(".query-group__actions > .action-menu > summary")
      .click();
    await page
      .getByRole("button", { name: "Добавить группу условий", exact: true })
      .click();
    await page.getByText("Область совпадений", { exact: true }).first().click();
    const problems = await page.locator("#asset-query").evaluate((panel) => {
      const problems = [];
      const frames = panel.querySelectorAll(".asset-query-view, .query-group");
      for (const frame of frames) {
        const bounds = frame.getBoundingClientRect();
        const legend = frame.querySelector(":scope > legend");
        if (legend && legend.getBoundingClientRect().top < bounds.top + 8)
          problems.push("heading intersects frame border");
        for (const element of frame.querySelectorAll(
          "input, select, button, legend",
        )) {
          if (!element.checkVisibility()) continue;
          const rect = element.getBoundingClientRect();
          if (!rect.width || !rect.height) continue;
          if (
            rect.left < bounds.left - 1 ||
            rect.right > bounds.right + 1 ||
            rect.top < bounds.top - 1 ||
            rect.bottom > bounds.bottom + 1
          )
            problems.push(element.textContent || element.tagName);
        }
      }
      for (const row of panel.querySelectorAll(
        ".query-rule, .query-group__controls, .asset-query-view__save",
      )) {
        const children = [...row.children].filter(
          (element) => element.getBoundingClientRect().height,
        );
        for (let i = 0; i < children.length; i++) {
          for (let j = i + 1; j < children.length; j++) {
            const a = children[i].getBoundingClientRect();
            const b = children[j].getBoundingClientRect();
            if (
              Math.min(a.right, b.right) - Math.max(a.left, b.left) > 1 &&
              Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 1
            )
              problems.push("overlapping controls");
          }
        }
      }
      return problems;
    });
    expect(problems).toEqual([]);
    await page.screenshot({
      path: `output/playwright/asset-query-${width}.png`,
      fullPage: true,
    });
  });
}

test("running passport progress and asset vulnerability rows use dark surfaces", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1011, height: 715 });
  await page.addInitScript(() =>
    localStorage.setItem("mpvm-client-theme", "dark"),
  );
  const job = {
    operation_id: "dark-progress",
    status: "running",
    progress_percent: 82,
    message: "Сохранение паспортов в БД.",
  };
  const card = {
    asset_id: "dark-asset",
    display_name: "Dark theme host",
    loaded_sections: ["summary"],
    stats: {},
  };
  await installApiMock(page, {
    "/api/vulnerability-passports/refresh-jobs/latest": (route) =>
      route.fulfill({ json: { job } }),
    "/api/vulnerability-passports/refresh-jobs/dark-progress": (route) =>
      route.fulfill({ json: job }),
    "/api/asset-cards/local": (route) =>
      route.fulfill({ json: { rows: [card], total: 1 } }),
    "/api/asset-cards/dark-asset/summary": (route) =>
      route.fulfill({ json: card }),
    "/api/asset-cards/dark-asset/vulnerabilities/groups": (route) =>
      route.fulfill({
        json: {
          vulnerabilities: {
            header: { os_soft_vulnerabilities_count: 2 },
            sources: [
              {
                source: "software",
                groups: ["linux-image", "containerd"].map((name) => ({
                  source: "software",
                  collection_id: name,
                  name,
                  vulnerabilities_count: 1,
                })),
              },
            ],
          },
        },
      }),
  });
  const expectDarkSurface = async (locator) => {
    await expect(locator.first()).toBeVisible();
    const colors = await locator.evaluateAll((elements) =>
      elements.map((element) => {
        let surface = element;
        let background;
        do {
          background = getComputedStyle(surface).backgroundColor;
          surface = surface.parentElement;
        } while (
          surface &&
          (background === "rgba(0, 0, 0, 0)" || background === "transparent")
        );
        const rgb = background
          .match(/[\d.]+/g)
          .slice(0, 3)
          .map(Number);
        return Math.max(...rgb);
      }),
    );
    for (const channel of colors) expect(channel).toBeLessThan(90);
  };
  await page.goto("/passports");
  await expectDarkSurface(page.locator(".passport-job--running"));
  await expectDarkSurface(page.locator(".passport-job__track"));
  await expect(
    page.getByRole("progressbar", { name: "Обновление списка паспортов" }),
  ).toHaveAttribute("aria-valuenow", "82");
  await page.screenshot({
    path: "output/playwright/passport-progress-dark.png",
    fullPage: true,
  });
  await page.goto("/asset-cards");
  await page
    .getByRole("button", { name: "Сохранённые карточки", exact: true })
    .click();
  await page.getByRole("button", { name: "Открыть", exact: true }).click();
  await page.getByRole("tab", { name: "Уязвимости", exact: true }).click();
  await expect(page.locator(".asset-vulnerability-group")).toHaveCount(2);
  await expectDarkSurface(page.locator(".asset-vulnerability-toolbar > span"));
  await expectDarkSurface(page.locator(".asset-vulnerability-group td"));
  await page.screenshot({
    path: "output/playwright/asset-vulnerabilities-dark.png",
    fullPage: true,
  });
});

function defaultApiResponse(path) {
  if (path === "/api/auth/me") {
    return {
      user: {
        id: 1,
        username: "e2e",
        display_name: "E2E Operator",
        role: "admin",
        permissions: [
          "system.read",
          "connection.read",
          "connection.manage",
          "tasks.read",
          "tasks.manage",
          "tasks.execute",
          "operations.read",
          "operations.cancel",
          "operations.retry",
          "assets.read",
          "asset_cards.read",
          "asset_cards.build",
          "asset_cards.manage",
          "passports.read",
          "passports.manage",
          "imports_exports.read",
          "imports_exports.manage",
          "remediation.read",
          "remediation.manage",
          "remediation.policy",
          "risk.read",
          "risk.manage",
          "automations.read",
          "automations.manage",
          "automations.execute",
          "notifications.read",
          "notifications.manage",
          "saved_views.read",
          "saved_views.manage",
          "diagnostics.write",
          "diagnostics.read",
          "security.users.read",
          "security.roles.read",
          "security.audit.read",
        ],
      },
    };
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
  if (path === "/api/vm/overview")
    return {
      active_workflows: 0,
      active_operations: 0,
      open_cases: 0,
      overdue_cases: 0,
      awaiting_verification: 0,
      asset_count: 0,
      attention: [],
      recent_workflows: [],
    };
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
  if (path === "/api/remediation/summary")
    return {
      open: 0,
      overdue: 0,
      near_due: 0,
      risk_accepted: 0,
      resolved_30d: 0,
    };
  if (path === "/api/remediation/policy")
    return {
      critical_days: 7,
      high_days: 30,
      medium_days: 90,
      low_days: 180,
      near_due_days: 7,
    };
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

async function navigateFromSidebar(page, path) {
  const link = page.locator(`.nav a[href="${path}"]`);
  if (!(await link.isVisible())) {
    const section = link.locator("xpath=ancestor::details[1]");
    await section.locator("summary").click();
  }
  await link.click();
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
            await navigateFromSidebar(page, path);
          }
          await expectRoute(page, path);
        });
      }

      expect(pageErrors).toEqual([]);
    });
  });
}

test("VM Management launches and tracks a controlled scan workflow", async ({
  page,
}) => {
  const workflow = {
    workflow_id: "workflow-e2e-1",
    kind: "scan",
    status: "running",
    stage: "postprocess",
    progress_percent: 48,
    can_cancel: true,
    can_retry: false,
    steps: [
      {
        position: 1,
        step_key: "validation",
        status: "completed",
        progress_percent: 100,
      },
      {
        position: 2,
        step_key: "scan",
        status: "completed",
        progress_percent: 100,
      },
      {
        position: 3,
        step_key: "postprocess",
        status: "running",
        progress_percent: 24,
        message: "Загрузка карточек",
      },
      {
        position: 4,
        step_key: "reconcile",
        status: "pending",
        progress_percent: 0,
      },
    ],
  };
  await installApiMock(page, {
    "/api/scanner-tasks": (route) =>
      route.fulfill({
        json: [
          {
            mp_task_id: "task-e2e-1",
            payload: { name: "Production perimeter" },
          },
        ],
      }),
    "POST /api/vm/workflows/scan/preflight": (route) =>
      route.fulfill({
        json: {
          ready: true,
          blocking_issues: [],
          warnings: [],
          target_count: 1,
          conflicting_operations: [],
          task: { task_id: "task-e2e-1", name: "Production perimeter" },
        },
      }),
    "POST /api/vm/workflows/scan": (route) =>
      route.fulfill({
        status: 202,
        json: {
          workflow_id: workflow.workflow_id,
          status: "queued",
          workflow: { ...workflow, status: "queued" },
        },
      }),
    "/api/vm/workflows/workflow-e2e-1": (route) =>
      route.fulfill({ json: workflow }),
  });
  await page.goto("/vm");
  await page.getByLabel("Задача MP VM").selectOption("task-e2e-1");
  await page.getByRole("button", { name: "Проверить перед запуском" }).click();
  await expect(page.getByText("Проверка пройдена")).toBeVisible();
  await page.getByRole("button", { name: "Запустить конвейер" }).click();
  const dialog = page.getByRole("dialog", { name: "Полное сканирование" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Загрузка карточек")).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Остановить" }),
  ).toBeVisible();
});

test("remediation lifecycle reaches scan-confirmed resolution", async ({
  page,
}) => {
  let caseStatus = "open";
  let assignee = null;
  const remediationCase = () => ({
    case_id: "case-e2e-1",
    version: caseStatus === "open" ? 1 : 2,
    status: caseStatus,
    severity: "critical",
    cve: "CVE-2026-9001",
    title: "E2E critical vulnerability",
    asset_id: "asset-e2e-1",
    display_name: "server-e2e",
    assignee,
    overdue: caseStatus !== "resolved",
    due_at: "2026-07-01T08:00:00Z",
    events: [],
  });
  await installApiMock(page, {
    "/api/remediation/cases": (route) =>
      route.fulfill({ json: { rows: [remediationCase()], total: 1 } }),
    "/api/remediation/summary": (route) =>
      route.fulfill({
        json: {
          open: caseStatus === "resolved" ? 0 : 1,
          overdue: caseStatus === "resolved" ? 0 : 1,
          near_due: 0,
          risk_accepted: 0,
          resolved_30d: caseStatus === "resolved" ? 1 : 0,
        },
      }),
    "/api/remediation/policy": (route) =>
      route.fulfill({
        json: {
          critical_days: 7,
          high_days: 30,
          medium_days: 90,
          low_days: 180,
          near_due_days: 7,
        },
      }),
    "/api/remediation/cases/case-e2e-1": (route) =>
      route.fulfill({ json: remediationCase() }),
    "PATCH /api/remediation/cases/case-e2e-1": async (route) => {
      const payload = route.request().postDataJSON();
      expect(payload.expected_version).toBe(1);
      caseStatus = payload.status;
      assignee = payload.assignee;
      await route.fulfill({ json: remediationCase() });
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

  // Resolution is scan-confirmed by the backend, never selected manually.
  caseStatus = "resolved";
  await page.getByRole("button", { name: "Обновить", exact: true }).click();
  await expect(page.getByRole("cell", { name: "Устранена" })).toBeVisible();
});

test.describe("mobile shell", () => {
  test.use({ viewport: { width: 360, height: 800 } });

  test("keeps the active navigation item visible and navigates at 360px", async ({
    page,
  }) => {
    await installApiMock(page);
    await page.goto("/assets");
    await expectRoute(page, "/asset-cards");

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
  await expect(dialog.locator(":focus")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(openButton).toBeFocused();

  await openButton.click();
  const cancelButton = page
    .getByRole("dialog")
    .getByRole("button", { name: "Остановить" });
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

    await page.goto("/dashboards");
    await page.getByText("История риска", { exact: true }).click();
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

    await page.goto("/dashboards");
    await page.getByText("История риска", { exact: true }).click();
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

    await page.goto("/dashboards");
    await page.getByText("История риска", { exact: true }).click();
    const history = page.locator(".risk-trend");
    const error = history.getByRole("alert");
    await expect(error).toContainText("History unavailable");

    failHistory = false;
    await error.locator("button").click();
    await expect(history.locator(".vulnerability-empty")).toBeVisible();
    await expect(error).toHaveCount(0);
  });
});

test("task selection, results, and a new task are separate actions", async ({
  page,
}) => {
  const pageErrors = [];
  const historyRequests = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await installApiMock(page, {
    "/api/scanner-tasks": (route) =>
      route.fulfill({
        json: [
          {
            mp_task_id: "task-select-1",
            name: "Audit alpha",
            status: "finished",
            include_targets: ["10.1.1.1"],
            payload: {
              name: "Audit alpha",
              include: { targets: ["10.1.1.1"] },
            },
          },
        ],
      }),
    "/api/scanner-tasks/task-select-1/runs": (route) => {
      historyRequests.push("runs");
      return route.fulfill({
        json: {
          items: [
            {
              id: "run-e2e-1",
              status: "finished",
              startedAt: "2026-10-02T08:00:00Z",
              startedBy: {
                id: "user-e2e-1",
                login: "Administrator",
                firstName: null,
                lastName: null,
              },
            },
          ],
          has_more: false,
        },
      });
    },
    "/api/scanner-tasks/task-select-1/runs/run-e2e-1/jobs": (route) =>
      route.fulfill({
        json: {
          items: [
            {
              id: "job-e2e-1",
              status: "finished",
              targets: ["10.1.1.1"],
              profile: { name: "Unix Audit" },
            },
          ],
        },
      }),
  });
  await page.goto("/tasks");
  await page.getByText("Audit alpha", { exact: true }).first().click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Audit alpha", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Название задачи")).toHaveCount(0);
  expect(historyRequests).toEqual([]);
  await page.getByText("task-select-1", { exact: true }).first().dblclick();
  await expect(
    page.getByRole("heading", { name: "Запуски", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Administrator", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("cell", { name: "10.1.1.1", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("cell", { name: "Unix Audit", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Основная навигация" }),
  ).toBeVisible();
  expect(pageErrors).toEqual([]);
  await page.screenshot({
    path: "output/playwright/task-details-started-by.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "← К задачам", exact: true }).click();
  await page
    .getByRole("button", { name: "+ Создать задачу", exact: true })
    .click();
  await expect(page.getByLabel("Название задачи")).toHaveValue("");
  await expect(
    page.getByRole("button", { name: "Создать задачу", exact: true }),
  ).toBeVisible();
});

test("operation diagnostics shows a download failure and permits a retry", async ({
  page,
}) => {
  let attempts = 0;
  await installApiMock(page, {
    "/api/operations": (route) =>
      route.fulfill({ json: { rows: [OPERATION], total: 1 } }),
    "/api/operations/operation-e2e-001": (route) =>
      route.fulfill({ json: OPERATION }),
    "/api/operations/operation-e2e-001/diagnostics": (route) => {
      attempts += 1;
      if (attempts === 1)
        return route.fulfill({
          status: 503,
          json: {
            detail: {
              message: "Archive temporarily unavailable",
              retryable: true,
            },
          },
        });
      return route.fulfill({
        contentType: "application/zip",
        headers: {
          "content-disposition":
            'attachment; filename="operation-diagnostics.zip"',
        },
        body: Buffer.from("UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==", "base64"),
      });
    },
  });
  await page.goto("/operations");
  await page.getByRole("button", { name: "Открыть", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByRole("button", { name: "Скачать диагностику", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Archive temporarily unavailable",
  );
  const downloadPromise = page.waitForEvent("download");
  await dialog
    .getByRole("button", { name: "Скачать диагностику", exact: true })
    .click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("operation-diagnostics.zip");
  expect(await download.failure()).toBeNull();
});

test("vulnerability results wait for applied asset selection", async ({
  page,
}) => {
  const selections = [];
  await installApiMock(page, {
    "/api/asset-cards/local": (route) =>
      route.fulfill({
        json: {
          rows: [{ asset_id: "host-e2e-1", display_name: "Selected server" }],
          total: 1,
        },
      }),
    "/api/vulnerabilities/summary": (route, url) => {
      selections.push(url.searchParams.get("asset_id"));
      return route.fulfill({
        json: defaultApiResponse("/api/vulnerabilities/summary"),
      });
    },
  });
  await page.goto("/vulnerabilities");
  await expect(
    page.getByRole("button", { name: "Применить фильтры" }),
  ).toBeVisible();
  await expect(page.getByText("История риска", { exact: true })).toHaveCount(0);
  expect(selections).toEqual([]);
  await page.getByLabel("Актив", { exact: true }).fill("host-e2e-1");
  await page.getByRole("button", { name: "Применить фильтры" }).click();
  await expect.poll(() => selections).toEqual(["host-e2e-1"]);
});
