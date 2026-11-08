import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const baseUrl = process.env.DEMO_APP_URL || "http://demo-app:8000";
const username = process.env.DEMO_USERNAME || "demo-admin";
const password = process.env.DEMO_PASSWORD || "demo-only-pass";
const assetName = process.env.SMOKE_ASSET_NAME || "demo-linux-01";
const cveName = process.env.SMOKE_CVE || "CVE-2026-113214";
const passportName = process.env.SMOKE_PASSPORT || "Demo vulnerability";
const operationText = process.env.SMOKE_OPERATION || "Synthetic removal";
const groupName = process.env.SMOKE_GROUP || "Demo Linux assets";
const vulnerabilityGroup = process.env.SMOKE_VULNERABILITY_GROUP || "Software findings";
const findingName = process.env.SMOKE_FINDING || "OpenSSL security update available";
const outputDir = process.env.SMOKE_OUTPUT_DIR || "/workspace/output/demo-ui";
await mkdir(outputDir, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
  args: ["--no-sandbox"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  console.log("Loaded page:", await page.title(), (await page.locator("body").innerText()).slice(0, 300));
  await page.screenshot({ path: path.join(outputDir, "login.png"), fullPage: true });
  await page.locator('input[autocomplete="username"]').fill(username);
  await page.locator('input[autocomplete="current-password"]').fill(password);
  await page.getByRole("button", { name: "Войти" }).click();
  await page.getByRole("navigation").waitFor();

  const pages = [
    ["asset-cards", "/asset-cards", assetName],
    ["passports", "/passports", passportName],
    ["operations", "/operations", operationText],
    ["asset-groups", "/asset-groups", groupName],
  ];
  for (const [name, route, expectedText] of pages) {
    await page.goto(`${baseUrl}${route}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("main").waitFor();
    if (name === "passports") {
      await page.getByRole("button", { name: "Сохранённые" }).click();
    }
    await page.waitForTimeout(1000);
    console.log(name, (await page.locator("body").innerText()).slice(0, 500));
    await page.screenshot({ path: path.join(outputDir, `${name}-before-check.png`), fullPage: true });
    await page.getByText(expectedText, { exact: false }).first().waitFor({ timeout: 15000 });
    if (name === "asset-cards") {
      const linuxRow = page.locator("tr").filter({ hasText: assetName });
      await linuxRow.getByRole("button", { name: "Открыть" }).click();
      await page.getByRole("tab", { name: "Уязвимости" }).click();
      await page.getByRole("button").filter({ hasText: vulnerabilityGroup }).click();
      await page.getByText(findingName, { exact: false }).first().waitFor({ timeout: 15000 });
      await page.getByText(cveName, { exact: false }).first().waitFor({ timeout: 15000 });
      await page.screenshot({ path: path.join(outputDir, "asset-card-findings.png"), fullPage: true });
    }
    if (name === "asset-groups") {
      await page.getByText(groupName, { exact: true }).click();
      await page.getByText(assetName, { exact: true }).waitFor({ timeout: 15000 });
      await page.screenshot({ path: path.join(outputDir, "asset-group-members.png"), fullPage: true });
    }
    await page.screenshot({ path: path.join(outputDir, `${name}.png`), fullPage: true });
  }
  console.log(`Verified ${pages.length} seeded UI sections; screenshots: ${outputDir}`);
} finally {
  await browser.close();
}
