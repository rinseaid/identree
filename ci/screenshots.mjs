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
 * Create a new page, set viewport, and log in via the dev login endpoint.
 * Returns the page object with a valid session cookie.
 */
async function loginPage(context, user = "testadmin", role = "admin") {
  const page = await context.newPage();
  await page.setViewportSize(VIEWPORT);
  // Dev login sets a session cookie and redirects to /
  await page.goto(`${BASE_URL}/dev/login?user=${user}&role=${role}`, {
    waitUntil: "load",
  });
  return page;
}

/**
 * Take a screenshot in both light and dark modes and save to SCREENSHOTS_DIR.
 * `name` is the filename stem (e.g. "dashboard").
 * `captureFn` receives the page and mode string ("light"|"dark") and should
 * navigate / interact before resolving — the screenshot is taken on return.
 */
async function screenshot(context, name, captureFn) {
  for (const mode of ["light", "dark"]) {
    const page = await loginPage(context);
    try {
      // Apply color scheme before navigation so CSS media query fires correctly.
      await page.emulateMedia({
        colorScheme: mode === "dark" ? "dark" : "light",
      });

      await captureFn(page, mode);

      // Short pause to let any animations settle.
      await page.waitForTimeout(300);

      const dest = `${SCREENSHOTS_DIR}/${name}-${mode}.png`;
      await page.screenshot({ path: dest, fullPage: false });
      console.log(`  saved ${dest}`);
    } finally {
      await page.close();
    }
  }
}

// ── Wait for identree to be ready ─────────────────────────────────────────────

console.log("Waiting for identree...");
{
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const resp = await page.goto(`${BASE_URL}/healthz`, {
        timeout: 5000,
        waitUntil: "domcontentloaded",
      });
      if (resp && resp.ok()) break;
    } catch {
      // not up yet
    }
    await page.waitForTimeout(2000);
  }
  await page.close();
  await ctx.close();
}
console.log("identree ready.\n");

// ── Open a single persistent browser context ──────────────────────────────────

const context = await browser.newContext({
  viewport: VIEWPORT,
  // Accept all redirects; don't store credentials between pages.
});

// ── 1. Dashboard ──────────────────────────────────────────────────────────────

console.log("Dashboard...");
await screenshot(context, "dashboard", async (page) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "load" });
});

// ── 2. Sessions page ──────────────────────────────────────────────────────────

console.log("Sessions...");
await screenshot(context, "sessions", async (page) => {
  await page.goto(`${BASE_URL}/sessions`, { waitUntil: "load" });
});

// ── 3. Access page ────────────────────────────────────────────────────────────

console.log("Access...");
await screenshot(context, "access", async (page) => {
  await page.goto(`${BASE_URL}/access`, { waitUntil: "load" });
});

// ── 4. History page ───────────────────────────────────────────────────────────

console.log("History (default)...");
await screenshot(context, "history", async (page) => {
  await page.goto(`${BASE_URL}/history`, { waitUntil: "load" });
});

console.log("History (with filters)...");
await screenshot(context, "history-filtered", async (page) => {
  await page.goto(`${BASE_URL}/history`, { waitUntil: "load" });
  // Type into filter boxes if they exist
  const userFilter = page.locator('input[name="user"], input[placeholder*="user" i]').first();
  if (await userFilter.count() > 0) {
    await userFilter.fill("alice");
    await page.waitForTimeout(400);
  }
  const hostFilter = page.locator('input[name="host"], input[placeholder*="host" i]').first();
  if (await hostFilter.count() > 0) {
    await hostFilter.fill("prod");
    await page.waitForTimeout(400);
  }
});

// ── 5. Hosts page ─────────────────────────────────────────────────────────────

console.log("Hosts...");
await screenshot(context, "hosts", async (page) => {
  await page.goto(`${BASE_URL}/admin/hosts`, { waitUntil: "load" });
});

// ── 6. Users page ─────────────────────────────────────────────────────────────

console.log("Users...");
await screenshot(context, "users", async (page) => {
  await page.goto(`${BASE_URL}/admin/users`, { waitUntil: "load" });
});

console.log("Users (SSH key claims expanded)...");
await screenshot(context, "users-expanded", async (page) => {
  await page.goto(`${BASE_URL}/admin/users`, { waitUntil: "load" });
  // Try to open the first user's claims detail row or expand button
  const expandBtn = page
    .locator(
      'button[aria-label*="claim" i], button[aria-label*="expand" i], details > summary, .expand-claims, [data-action="expand"]'
    )
    .first();
  if (await expandBtn.count() > 0) {
    await expandBtn.click();
    await page.waitForTimeout(400);
  }
  // Also try clicking on alice's row if visible
  const aliceRow = page.locator("tr, .user-row, li").filter({ hasText: "alice" }).first();
  if (await aliceRow.count() > 0) {
    const aliceToggle = aliceRow.locator("button, summary").first();
    if (await aliceToggle.count() > 0) {
      await aliceToggle.click();
      await page.waitForTimeout(400);
    }
  }
});

// ── 7. Groups page ────────────────────────────────────────────────────────────

console.log("Groups...");
await screenshot(context, "groups", async (page) => {
  await page.goto(`${BASE_URL}/admin/groups`, { waitUntil: "load" });
});

console.log("Groups (developers expanded)...");
await screenshot(context, "groups-expanded", async (page) => {
  await page.goto(`${BASE_URL}/admin/groups`, { waitUntil: "load" });
  // Expand the developers group to show its custom claims
  const devRow = page
    .locator("tr, .group-row, li, details")
    .filter({ hasText: "developers" })
    .first();
  if (await devRow.count() > 0) {
    const toggle = devRow.locator("button, summary").first();
    if (await toggle.count() > 0) {
      await toggle.click();
      await page.waitForTimeout(500);
    } else {
      // The row itself may be clickable
      await devRow.click();
      await page.waitForTimeout(500);
    }
  } else {
    // Fallback: try expanding any first expand button
    const anyExpand = page
      .locator("button[aria-expanded], details > summary, .toggle-claims")
      .first();
    if (await anyExpand.count() > 0) {
      await anyExpand.click();
      await page.waitForTimeout(500);
    }
  }
});

// ── 8. Admin info page ────────────────────────────────────────────────────────

console.log("Admin info...");
await screenshot(context, "admin-info", async (page) => {
  await page.goto(`${BASE_URL}/admin/info`, { waitUntil: "load" });
});

// ── 9. Admin config page ──────────────────────────────────────────────────────

console.log("Admin config (top)...");
await screenshot(context, "admin-config", async (page) => {
  await page.goto(`${BASE_URL}/admin/config`, { waitUntil: "load" });
});

console.log("Admin config (LDAP section)...");
await screenshot(context, "admin-config-ldap", async (page) => {
  await page.goto(`${BASE_URL}/admin/config`, { waitUntil: "load" });
  // Scroll to the LDAP section
  const ldapSection = page
    .locator(
      'section, fieldset, [id*="ldap" i], [class*="ldap" i], h2, h3'
    )
    .filter({ hasText: /ldap/i })
    .first();
  if (await ldapSection.count() > 0) {
    await ldapSection.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);
  } else {
    await page.evaluate(() => window.scrollBy(0, 600));
    await page.waitForTimeout(300);
  }
});

// ── 10. Approval / challenge page ─────────────────────────────────────────────

console.log("Approval page (generic state)...");
await screenshot(context, "approval", async (page) => {
  // Navigate to /approve/ with a fake token — we expect a "not found" or
  // "expired" state page, which is still a meaningful screenshot.
  await page.goto(`${BASE_URL}/approve/ci-screenshot-placeholder`, {
    waitUntil: "domcontentloaded",
  });
});

// ── 11. Sudo rules page ───────────────────────────────────────────────────────

console.log("Sudo rules...");
await screenshot(context, "sudo-rules", async (page) => {
  await page.goto(`${BASE_URL}/admin/sudo-rules`, { waitUntil: "load" });
});

// ── Cleanup ───────────────────────────────────────────────────────────────────

await context.close();
await browser.close();

console.log("\nAll screenshots saved to", SCREENSHOTS_DIR);
