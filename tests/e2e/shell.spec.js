import { expect, test } from "@playwright/test";

test("application shell keeps stable routes and navigation", async ({
  page,
}) => {
  page.on("pageerror", (error) =>
    console.error(`browser page error: ${error.message}`),
  );
  page.on("console", (message) => {
    if (message.type() === "error")
      console.error(`browser console error: ${message.text()}`);
  });
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (!path.startsWith("/api/")) {
      await route.continue();
      return;
    }
    if (path === "/api/session") {
      await route.fulfill({ json: { connected: false } });
    } else if (path === "/api/defaults") {
      await route.fulfill({ json: { client_id: "mpx", scope: "" } });
    } else if (path === "/api/system/status") {
      await route.fulfill({
        json: {
          state: "degraded",
          components: {
            database: { state: "ok" },
            mpvm: { state: "degraded" },
          },
        },
      });
    } else if (path === "/api/operations") {
      await route.fulfill({ json: { rows: [], total: 0 } });
    } else {
      await route.fulfill({ json: { rows: [], total: 0 } });
    }
  });

  await page.goto("/connection");
  await expect(page).toHaveURL(/\/connection$/);
  await expect(
    page.getByRole("heading", { level: 1, name: "Подключение к MP VM" }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Операции" }).click();
  await expect(page).toHaveURL(/\/operations$/);
  await expect(
    page.getByRole("heading", { level: 1, name: "Центр операций" }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Автоматизация" }).click();
  await expect(page).toHaveURL(/\/automations$/);
  await expect(
    page.getByRole("heading", { level: 1, name: "Автоматизация" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Новый runbook" }),
  ).toBeVisible();
});
