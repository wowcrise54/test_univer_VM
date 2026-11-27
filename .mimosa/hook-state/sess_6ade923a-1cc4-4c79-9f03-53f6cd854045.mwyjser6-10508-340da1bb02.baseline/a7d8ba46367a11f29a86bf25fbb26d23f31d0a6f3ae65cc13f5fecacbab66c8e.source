import { expect, test } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

const API_ROUTE = /^https?:\/\/[^/]+\/api(?:\/|$)/;
const PERMISSIONS = [
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
  "security.users.manage",
  "security.roles.read",
  "security.audit.read",
  "asset_groups.read",
];
const PAGES = [
  "/dashboards",
  "/export",
  "/vulnerabilities",
  "/remediation",
  "/operations",
  "/tasks",
  "/asset-groups",
  "/asset-cards",
  "/automations",
  "/asset-query",
  "/passports",
  "/task-presets",
  "/users",
];
const WIDTHS = (process.env.AUDIT_WIDTHS || "360,768,1280")
  .split(",")
  .map(Number);
const THEMES = (process.env.AUDIT_THEMES || "dark,light").split(",");

const FINDING = {
  display_name: "srv-app-01.corp.example.test",
  asset_id: "a-1",
  ip_address: "10.20.30.41",
  asset_type: "Host",
  asset_category: "server",
  scan_at: "2026-10-20",
  cve: "CVE-2026-12345",
  cvss_score: 9.8,
  age_days: 45,
  freshness_reason: "stale",
};
const RESOLUTION = {
  period_days: 30,
  confirmed_resolutions: 12,
  resolved_vulnerabilities: 9,
  resolved_hosts: 5,
  currently_resolved: 11,
  mean_time_to_resolve_days: 6.5,
  by_severity: [{ severity: "critical", confirmed_resolutions: 4 }],
  trend: [{ date: "2026-10-20", confirmed_resolutions: 3 }],
  recent: [],
};
const TASKS = [
  {
    mp_task_id: "t1",
    name: "php_package_inventory_scan_weekly",
    status: "idle",
  },
  {
    mp_task_id: "t2",
    name: "Внешний периметр: полное сканирование",
    status: "idle",
  },
];
const FOLDERS = [
  {
    folder_id: "f1",
    name: "php_package_inventory_scan_weekly",
    task_ids: ["t1"],
  },
  {
    folder_id: "f2",
    name: "Внешний периметр и DMZ сегменты",
    task_ids: ["t2"],
  },
];
const USERS = [
  {
    id: 1,
    username: "admin",
    display_name: "Administrator",
    is_active: true,
    roles: [{ id: 1, name: "admin" }],
  },
  {
    id: 2,
    username: "ivanov",
    display_name: "Иванов Иван",
    is_active: true,
    roles: [{ id: 2, name: "operator" }],
  },
  {
    id: 3,
    username: "petrov",
    display_name: "Петров Пётр",
    is_active: false,
    roles: [{ id: 3, name: "viewer" }],
  },
];

function response(path) {
  if (path === "/api/auth/me")
    return {
      user: {
        id: 1,
        username: "admin",
        display_name: "Administrator",
        role: "admin",
        permissions: PERMISSIONS,
      },
    };
  if (path === "/api/auth/bootstrap-status") return { configured: true };
  if (path === "/api/session")
    return {
      connected: true,
      api_url: "https://mpvm.example.test",
      token_url: "https://mpvm.example.test/connect/token",
      verify_tls: true,
    };
  if (path === "/api/defaults")
    return { client_id: "mpx", scope: "", utc_offset: "+05:00" };
  if (path === "/api/system/status")
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
  if (path === "/api/scanner-tasks") return TASKS;
  if (path === "/api/scanner-task-folders") return { rows: FOLDERS };
  if (path === "/api/auth/users") return { rows: USERS };
  if (path === "/api/auth/roles")
    return {
      rows: [
        { id: 1, name: "admin" },
        { id: 2, name: "operator" },
        { id: 3, name: "viewer" },
      ],
    };
  if (path.startsWith("/api/vulnerabilities/compliance/")) {
    if (path.endsWith("/summary"))
      return {
        assets_total: 120,
        fresh_assets: 100,
        critical_findings: 7,
        stale_assets: 20,
      };
    return {
      rows: [
        FINDING,
        { ...FINDING, asset_id: "a-2", display_name: "ws-0042", cve: "CVE-1" },
      ],
    };
  }
  if (path === "/api/remediation/resolution-stats") return RESOLUTION;
  if (path === "/api/vulnerabilities/trends")
    return {
      scope: "all_saved_asset_cards",
      rows: [],
      bucket: "day",
      retention_days: 90,
    };
  if (path === "/api/operations/summary")
    return { total: 0, active: 0, attention: 0, by_status: {}, by_kind: {} };
  if (path === "/api/assets/summary")
    return { assets: 0, software: 0, findings: 0, cve_rows: 0 };
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
  if (
    path === "/api/asset-cards/build-jobs/active" ||
    path === "/api/vulnerability-passports/detail-jobs/active"
  )
    return { job: null };
  return { rows: [], total: 0 };
}

// Walks the DOM and returns text whose contrast against the effective
// background (gradients expand into one candidate per colour stop) is below
// the WCAG AA threshold.
function auditContrast() {
  const parse = (value) => {
    const m = value.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1]
      .split(/[ ,/]+/)
      .filter(Boolean)
      .map(Number);
    return [p[0], p[1], p[2], p[3] ?? 1];
  };
  const over = (top, bottom) => {
    const a = top[3] + bottom[3] * (1 - top[3]);
    if (!a) return [0, 0, 0, 0];
    return [0, 1, 2]
      .map(
        (i) =>
          (top[i] * top[3] + bottom[i] * bottom[3] * (1 - top[3])) / a,
      )
      .concat(a);
  };
  const lum = ([r, g, b]) => {
    const [R, G, B] = [r, g, b].map((v) => {
      const c = v / 255;
      return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * R + 0.7152 * G + 0.0722 * B;
  };
  const ratio = (a, b) => {
    const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
    return (hi + 0.05) / (lo + 0.05);
  };
  const backgrounds = (element) => {
    let candidates = [[255, 255, 255, 1]];
    const chain = [];
    for (let node = element; node; node = node.parentElement)
      chain.unshift(node);
    for (const node of chain) {
      const style = getComputedStyle(node);
      const layers = [];
      const color = parse(style.backgroundColor);
      if (color && color[3] > 0) layers.push([color]);
      if (/gradient/.test(style.backgroundImage)) {
        const stops = (style.backgroundImage.match(/rgba?\([^)]+\)/g) || [])
          .map(parse)
          .filter(Boolean);
        if (stops.length) layers.push(stops);
      }
      for (const layer of layers)
        candidates = candidates.flatMap((base) =>
          layer.map((c) => over(c, base)),
        );
    }
    return candidates;
  };
  const problems = [];
  const seen = new Set();
  for (const element of document.body.querySelectorAll("*")) {
    if (!element.checkVisibility() || element.closest("svg")) continue;
    if (element.closest(":disabled, [aria-disabled='true']")) continue;
    const isField = element.matches(
      "input:not([type=checkbox]):not([type=radio]):not([type=file]):not([type=range]), textarea, select",
    );
    const own = [...element.childNodes].some(
      (n) => n.nodeType === Node.TEXT_NODE && /[\p{L}\p{N}]/u.test(n.textContent),
    );
    if (!own && !(isField && (element.value || element.placeholder))) continue;
    const style = getComputedStyle(element);
    if (Number(style.opacity) === 0) continue;
    const fg = parse(style.color);
    if (!fg) continue;
    const size = parseFloat(style.fontSize);
    const large =
      size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
    let worst = Infinity;
    for (const bg of backgrounds(element))
      worst = Math.min(worst, ratio(over(fg, bg), bg));
    if (worst < (large ? 3 : 4.5)) {
      const key = `${element.tagName}.${element.className}|${style.color}`;
      if (seen.has(key)) continue;
      seen.add(key);
      problems.push({
        el: `${element.tagName.toLowerCase()}.${String(element.className).trim().replace(/\s+/g, ".")}`,
        text: (element.value || element.placeholder || element.textContent)
          .trim()
          .slice(0, 40),
        ratio: Math.round(worst * 100) / 100,
        color: style.color,
      });
    }
  }
  return {
    problems,
    overflow: document.documentElement.scrollWidth > innerWidth + 1,
    lightTables: [...document.querySelectorAll("main table")]
      .filter(() => document.documentElement.dataset.theme === "dark")
      .filter((t) => t.checkVisibility())
      .map((t) => ({
        cls: t.className,
        bg: getComputedStyle(t).backgroundColor,
      }))
      .filter((t) => t.bg === "rgb(255, 255, 255)"),
  };
}

for (const theme of THEMES) {
  for (const width of WIDTHS) {
    test(`${theme} theme contrast audit at ${width}px`, async ({ page }) => {
      test.setTimeout(240000);
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width, height: 900 });
      await page.addInitScript(
        (value) => localStorage.setItem("mpvm-client-theme", value),
        theme,
      );
      await page.route(API_ROUTE, (route) =>
        route.fulfill({
          json: response(new URL(route.request().url()).pathname),
        }),
      );
      const report = [];
      for (const path of PAGES) {
        await page.goto(path);
        await expect(page.locator("main.workspace h1")).toBeVisible();
        const labels =
          path === "/dashboards"
            ? ["Обзор риска", "Контроль и отчёты", "Статистика устранений"]
            : [null];
        for (const label of labels) {
          if (label)
            await page
              .getByRole("button", { name: label })
              .click()
              .catch(() => {});
          await page.waitForTimeout(250);
          for (const summary of await page
            .locator("main .disclosure > summary")
            .all())
            if (!(await summary.evaluate((el) => el.parentElement.open)))
              await summary.click();
          const result = await page.evaluate(auditContrast);
          const name = `${path}${label ? `#${label}` : ""}`;
          report.push({ path: name, ...result });
          await mkdir(`output/playwright/audit/${theme}-${width}`, {
            recursive: true,
          });
          await page.screenshot({
            path: `output/playwright/audit/${theme}-${width}/${name.replace(/[/#]/g, "_")}.png`,
            fullPage: true,
          });
        }
      }
      await writeFile(
        `output/playwright/audit/${theme}-${width}.json`,
        JSON.stringify(report, null, 2),
      );
      expect(
        report.filter(
          (r) => r.problems.length || r.lightTables.length || r.overflow,
        ),
      ).toEqual([]);
    });
  }
}

for (const width of WIDTHS) {
  test(`"Ещё" is a dropdown that closes on Escape and outside click at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route(API_ROUTE, (route) =>
      route.fulfill({
        json: response(new URL(route.request().url()).pathname),
      }),
    );
    await page.goto("/tasks");
    const more = page.locator(".nav-more");
    const panel = page.locator(".nav-more__panel");
    await expect(panel).toBeHidden();
    await more.locator("summary").click();
    await expect(panel).toBeVisible();
    const box = await panel.boundingBox();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(width);
    expect(box.y + box.height).toBeLessThanOrEqual(900);
    await mkdir("output/playwright/audit", { recursive: true });
    await page.screenshot({ path: `output/playwright/audit/menu-${width}.png` });
    await page.keyboard.press("Escape");
    await expect(panel).toBeHidden();
    await more.locator("summary").click();
    await expect(panel).toBeVisible();
    await page.locator("main.workspace h1").click();
    await expect(panel).toBeHidden();
    const labels = await panel.locator("a").evaluateAll((links) =>
      links.map((link) => link.getAttribute("title")),
    );
    expect(labels.every(Boolean)).toBe(true);
  });
}

test("tasks page has no horizontal scroll at 1280px", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.route(API_ROUTE, (route) =>
    route.fulfill({ json: response(new URL(route.request().url()).pathname) }),
  );
  await page.goto("/tasks");
  await expect(page.locator(".task-folder-item")).toHaveCount(4);
  const scrolling = await page.evaluate(() =>
    [...document.querySelectorAll("main *")]
      .filter(
        (el) =>
          el.checkVisibility() &&
          /(auto|scroll)/.test(getComputedStyle(el).overflowX) &&
          el.scrollWidth > el.clientWidth + 1,
      )
      .map((el) => el.className),
  );
  expect(scrolling).toEqual([]);
});
