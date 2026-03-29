/**
 * ci/screenshots.mjs
 *
 * Playwright script that captures screenshots of every identree screen in both
 * light and dark modes. Run after seed-data.sh has populated the test instance.
 *
 * Usage:
 *   node ci/screenshots.mjs
 *
 * Requires: @playwright/test installed, Chromium available via playwright install.
 * Output: ./screenshots/{page}-light.png and ./screenshots/{page}-dark.png
 */

import { chromium } from "@playwright/test";
import { mkdir } from "fs/promises";
import { existsSync } from "fs";

const BASE_URL = process.env.IDENTREE_URL || "http://localhost:8090";
const SCREENSHOTS_DIR = "./screenshots";
const VIEWPORT = { width: 1440, height: 900 };

// ── Setup ──────────────────────────────────────────────────────────────────────

if (!existsSync(SCREENSHOTS_DIR)) {
  await mkdir(SCREENSHOTS_DIR, { recursive: true });
}

const browser = await chromium.launch({ headless: true });

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Create a new page with a valid admin session cookie via the dev login endpoint.
 */
async function loginPage(context, user = "testadmin", role = "admin") {
  const page = await context.newPage();
  await page.setViewportSize(VIEWPORT);
  await page.goto(`${BASE_URL}/dev/login?user=${user}&role=${role}`, {
    waitUntil: "load",
  });
  return page;
}

/**
 * Take a screenshot in both light and dark modes.
 * `captureFn` receives the page and should navigate/interact before returning.
 */
async function screenshot(context, name, captureFn) {
  for (const mode of ["light", "dark"]) {
    const page = await loginPage(context);
    try {
      await page.emulateMedia({ colorScheme: mode === "dark" ? "dark" : "light" });
      await captureFn(page, mode);
      await page.waitForTimeout(400);
      const dest = `${SCREENSHOTS_DIR}/${name}-${mode}.png`;
      await page.screenshot({ path: dest, fullPage: false });
      console.log(`  saved ${dest}`);
    } finally {
      await page.close();
    }
  }
}

// ── Wait for identree ──────────────────────────────────────────────────────────

console.log("Waiting for identree...");
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  for (let i = 0; i < 30; i++) {
    try {
      const resp = await page.goto(`${BASE_URL}/healthz`, {
        timeout: 5000,
        waitUntil: "domcontentloaded",
      });
      if (resp && resp.ok()) break;
    } catch { /* not up yet */ }
    await page.waitForTimeout(2000);
  }
  await page.close();
  await ctx.close();
}
console.log("identree ready.\n");

// ── Open browser context ───────────────────────────────────────────────────────

const context = await browser.newContext({ viewport: VIEWPORT });

// ── 1. Sessions (root / — pending challenges + active sessions) ───────────────

console.log("Sessions...");
await screenshot(context, "sessions", async (page) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "load" });
  // Wait for the sessions table or challenge rows to appear
  await page.waitForSelector(".sessions-table, .gtcol, table, .list, .row", {
    timeout: 5000,
  }).catch(() => {});
});

// ── 2. Access ──────────────────────────────────────────────────────────────────

console.log("Access...");
await screenshot(context, "access", async (page) => {
  await page.goto(`${BASE_URL}/access`, { waitUntil: "load" });
});

// ── 3. History ─────────────────────────────────────────────────────────────────

console.log("History...");
await screenshot(context, "history", async (page) => {
  await page.goto(`${BASE_URL}/history`, { waitUntil: "load" });
});

// ── 4. Hosts ───────────────────────────────────────────────────────────────────

console.log("Hosts...");
await screenshot(context, "hosts", async (page) => {
  await page.goto(`${BASE_URL}/admin/hosts`, { waitUntil: "load" });
});

// ── 5. Users ───────────────────────────────────────────────────────────────────

console.log("Users...");
await screenshot(context, "users", async (page) => {
  await page.goto(`${BASE_URL}/admin/users`, { waitUntil: "load" });
  // Wait for user rows to render
  await page.waitForSelector(".users-table-row, tr, [class*='user-row']", {
    timeout: 5000,
  }).catch(() => {});
});

console.log("Users (claims expanded)...");
await screenshot(context, "users-expanded", async (page) => {
  await page.goto(`${BASE_URL}/admin/users`, { waitUntil: "load" });
  await page.waitForSelector(".ssh-keys-toggle, [data-claims-target]", {
    timeout: 5000,
  }).catch(() => {});
  // Click the toggle for the first user that has claims (alice has SSH keys)
  const toggles = await page.locator(".ssh-keys-toggle, [data-claims-target]").all();
  if (toggles.length > 0) {
    await toggles[0].click();
    await page.waitForTimeout(500);
    // Scroll to ensure the expanded panel is visible (swallow if still hidden)
    const panel = page.locator(".user-claims-panel, [id^='uclaims-']").first();
    if (await panel.count() > 0) await panel.scrollIntoViewIfNeeded().catch(() => {});
  }
});

// ── 6. Groups ──────────────────────────────────────────────────────────────────

console.log("Groups...");
await screenshot(context, "groups", async (page) => {
  await page.goto(`${BASE_URL}/admin/groups`, { waitUntil: "load" });
  await page.waitForSelector(".groups-table-row, [id^='group-']", {
    timeout: 5000,
  }).catch(() => {});
});

console.log("Groups (sudo claims expanded)...");
await screenshot(context, "groups-expanded", async (page) => {
  await page.goto(`${BASE_URL}/admin/groups`, { waitUntil: "load" });
  await page.waitForSelector(".claims-toggle-btn, [data-claims-target]", {
    timeout: 5000,
  }).catch(() => {});
  // Click the toggle for the developers group (has rich sudo claims)
  const devGroup = page.locator("[id='group-developers']").first();
  const toggleBtn = (await devGroup.count()) > 0
    ? devGroup.locator(".claims-toggle-btn").first()
    : page.locator(".claims-toggle-btn").first();
  if (await toggleBtn.count() > 0) {
    await toggleBtn.click();
    await page.waitForTimeout(500);
    // Scroll to show the expanded panel (swallow if still hidden)
    const panel = page.locator(".claims-panel.visible, [id^='gclaims-']").first();
    if (await panel.count() > 0) await panel.scrollIntoViewIfNeeded().catch(() => {});
  }
});

// ── 7. Admin info ──────────────────────────────────────────────────────────────

console.log("Admin info...");
await screenshot(context, "admin-info", async (page) => {
  await page.goto(`${BASE_URL}/admin/info`, { waitUntil: "load" });
});

// ── 8. Admin config ────────────────────────────────────────────────────────────

console.log("Admin config...");
await screenshot(context, "admin-config", async (page) => {
  await page.goto(`${BASE_URL}/admin/config`, { waitUntil: "load" });
});

// ── 9. Profile popup (sidebar lower-left) ──────────────────────────────────────

console.log("Profile popup...");
await screenshot(context, "profile", async (page) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "load" });
  // Click the user button to open the profile dropdown
  const userBtn = page.locator(".user-btn").first();
  await userBtn.click();
  await page.waitForTimeout(300);
});

// ── Cleanup ────────────────────────────────────────────────────────────────────

await context.close();
await browser.close();

console.log("\nAll screenshots saved to", SCREENSHOTS_DIR);
