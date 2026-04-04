/**
 * ci/elevation.mjs
 *
 * Captures a 5-screenshot sequence showing the identree elevation (sudo approval) flow:
 *
 *   elevation-1.png  — terminal: sudo issued, waiting for approval
 *   elevation-2.png  — browser:  dashboard showing single pending challenge with justification picker
 *   elevation-3.png  — terminal: sudo proceeds after approval
 *   elevation-4.png  — browser:  dashboard showing multiple pending challenges (Review › button)
 *   elevation-5.png  — browser:  pending modal open with per-row justification pickers
 *
 * Requires the testclient container to be running:
 *   docker compose -f test/docker-compose.yml up -d testclient
 *
 * Output: ./screenshots/elevation-{1,2,3,4,5}.png  (light mode, no split)
 */

import { chromium } from "@playwright/test";
import { mkdir } from "fs/promises";
import { existsSync } from "fs";
import { spawn } from "child_process";

const BASE_URL = process.env.IDENTREE_URL || "http://localhost:8090";
const SHARED_SECRET = process.env.IDENTREE_SHARED_SECRET || "test-shared-secret-1234567890abc";
const SCREENSHOTS_DIR = "./screenshots";
const BROWSER_VIEWPORT = { width: 1440, height: 900 };

if (!existsSync(SCREENSHOTS_DIR)) {
  await mkdir(SCREENSHOTS_DIR, { recursive: true });
}

const browser = await chromium.launch({ headless: true });

// ── Terminal renderer ──────────────────────────────────────────────────────────
//
// Each line is an array of { c: cssClass, t: text } spans.
// Available classes: ps1 (green prompt), host (blue), cmd (white),
//                    dim (grey), url (light-blue), code (orange), ok (green bold).

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function renderTermHTML(lines) {
  const rows = lines.map(spans => {
    if (!Array.isArray(spans)) spans = [{ c: "dim", t: String(spans) }];
    return `<div class="line">${spans.map(p => `<span class="${p.c}">${esc(p.t)}</span>`).join("")}</div>`;
  }).join("");

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { background: #0d1117; }
  body { padding: 28px 36px 36px; display: inline-block; min-width: 820px; }
  .term {
    font-family: 'SF Mono', 'Cascadia Code', 'Consolas', 'Monaco', 'Menlo', monospace;
    font-size: 14.5px;
    line-height: 1.65;
    color: #e6edf3;
    white-space: pre;
  }
  .line  { min-height: 1.65em; }
  .ps1   { color: #3fb950; }
  .host  { color: #58a6ff; }
  .cmd   { color: #e6edf3; }
  .dim   { color: #8b949e; }
  .url   { color: #79c0ff; }
  .code  { color: #ffa657; font-weight: 600; }
  .ok    { color: #3fb950; font-weight: 600; }
  .cursor {
    display: inline-block; width: 9px; height: 1.05em;
    background: #c9d1d9; vertical-align: text-bottom; border-radius: 1px;
  }
</style>
</head>
<body>
<div class="term">${rows}</div>
</body>
</html>`;
}

async function saveTermShot(name, lines) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.setContent(renderTermHTML(lines));
  await page.waitForTimeout(80);
  const dest = `${SCREENSHOTS_DIR}/${name}.png`;
  await page.screenshot({ path: dest, fullPage: true });
  console.log(`  saved ${dest}`);
  await ctx.close();
}

// Helpers for common line patterns
const ps1 = (user, host) => [
  { c: "ps1", t: `${user}@` }, { c: "host", t: host }, { c: "ps1", t: ":~$ " },
];
const cmdLine   = (user, host, cmd) => [...ps1(user, host), { c: "cmd", t: cmd }];
const cursorLine = (user, host)      => [...ps1(user, host), { c: "cursor", t: "" }];

// ── Helper: create a challenge via the API ────────────────────────────────────

async function createApiChallenge(username, hostname, reason) {
  const body = { username, hostname };
  if (reason) body.reason = reason;
  const resp = await fetch(`${BASE_URL}/api/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shared-Secret": SHARED_SECRET,
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    console.warn(`  createApiChallenge: HTTP ${resp.status} for ${username}@${hostname}`);
    return null;
  }
  const d = await resp.json();
  return d.challenge_id || null;
}

// ── Start PAM helper in testclient container ──────────────────────────────────

// Use a user with no seeded grace session so the challenge flow is triggered
const USER = "eve";
const HOST = "prod-web-01";
const CMD  = "sudo systemctl restart nginx";

console.log(`Starting PAM helper (${USER} on ${HOST})...`);

let pamOutput = "";
let pamDone   = false;

const pamProc = spawn("docker", [
  "exec",
  "-e", "PAM_TYPE=auth",
  "-e", "PAM_USER=" + USER,
  "-e", "SUDO_REASON=Deployment",
  "identree-test-client",
  "identree",
], { stdio: ["ignore", "pipe", "pipe"] });

pamProc.stdout.on("data", d => { pamOutput += d.toString(); });
pamProc.stderr.on("data", d => { process.stderr.write(d); });
pamProc.on("exit", code => { pamDone = true; if (code !== 0 && code !== null) console.warn(`  PAM process exited with code ${code}`); });

// Wait up to 10s for the "Code:" line to appear
const pamStart = Date.now();
while (!pamOutput.includes("Code:") && Date.now() - pamStart < 10_000) {
  await new Promise(r => setTimeout(r, 300));
}
if (!pamOutput.includes("Code:")) {
  console.error("PAM helper did not produce expected output:", pamOutput);
  process.exit(1);
}

// Extract user code and approval URL from the real PAM output
const codeMatch = pamOutput.match(/Code:\s+([A-Z0-9]{6}-\d+)/);
const urlMatch  = pamOutput.match(/Approve at:\s+(\S+)/);
const userCode  = codeMatch ? codeMatch[1] : "??????-??????";
const approveURL = urlMatch ? urlMatch[1] : `${BASE_URL}/approve/${userCode}`;

console.log(`  challenge created — code: ${userCode}`);

// ── elevation-1: terminal — waiting for approval ──────────────────────────────

console.log("elevation-1 (terminal — justification prompt + waiting)...");
await saveTermShot("elevation-1", [
  cmdLine(USER, HOST, CMD),
  [{ c: "dim", t: "  Justification required. Select a reason:" }],
  [{ c: "dim", t: "    [1] Routine maintenance" }],
  [{ c: "dim", t: "    [2] Incident response" }],
  [{ c: "dim", t: "    [3] Deployment" }],
  [{ c: "dim", t: "    [4] Other (enter custom reason)" }],
  [{ c: "dim", t: "  Choice [1]: " }, { c: "cmd", t: "3" }],
  [],
  [{ c: "dim", t: "  Sudo requires Pocket ID approval." }],
  [{ c: "dim", t: "  Approve at: " }, { c: "url", t: approveURL }],
  [{ c: "dim", t: "  Code: " }, { c: "code", t: userCode }, { c: "dim", t: " (notification sent)" }],
]);

// ── elevation-2: browser — single pending challenge with justification picker ──

console.log("elevation-2 (browser — single pending with justification picker)...");
const ctx2 = await browser.newContext({ viewport: BROWSER_VIEWPORT });
const dashPage = await ctx2.newPage();
await dashPage.setViewportSize(BROWSER_VIEWPORT);
// Dev login as eve — sets session cookie and redirects to /
await dashPage.goto(`${BASE_URL}/dev/login?user=${USER}&role=user`, { waitUntil: "load" });
await dashPage.emulateMedia({ colorScheme: "light" });
// Wait for the pending bar to appear
await dashPage.waitForSelector(".pending-bar", { timeout: 8000 }).catch(() => {});
await dashPage.waitForTimeout(300);

// Pre-select a justification choice so the picker is clearly visible
const justSel = dashPage.locator(".pbar-actions .just-sel").first();
if (await justSel.count() > 0) {
  await justSel.selectOption({ index: 1 }); // pick first real option (after optional blank)
  await dashPage.waitForTimeout(150);
}

await dashPage.screenshot({ path: `${SCREENSHOTS_DIR}/elevation-2.png`, fullPage: false });
console.log(`  saved ${SCREENSHOTS_DIR}/elevation-2.png`);

// Approve the challenge so the PAM process can complete
const approveBtn = dashPage.locator(".pbar-actions button.btn-success").first();
if (await approveBtn.count() > 0) {
  await approveBtn.click();
  console.log(`  clicked Approve for ${USER}`);
} else {
  console.warn("  Approve button not found in pending bar — challenge may have expired");
}

await dashPage.close();
await ctx2.close();

// ── Wait for PAM process to finish ───────────────────────────────────────────

const pamDeadline = Date.now() + 12_000;
while (!pamDone && Date.now() < pamDeadline) {
  await new Promise(r => setTimeout(r, 200));
}
if (!pamDone) {
  pamProc.kill();
  console.warn("  PAM process did not finish in time — killed");
}

// ── elevation-3: terminal — approved ─────────────────────────────────────────

console.log("elevation-3 (terminal — approved)...");
await saveTermShot("elevation-3", [
  cmdLine(USER, HOST, CMD),
  [{ c: "dim", t: "  Sudo requires Pocket ID approval." }],
  [{ c: "dim", t: "  Approve at: " }, { c: "url", t: approveURL }],
  [{ c: "dim", t: "  Code: " }, { c: "code", t: userCode }, { c: "dim", t: " (notification sent)" }],
  [{ c: "ok", t: "  Approved!" }],
  cursorLine(USER, HOST),
]);

// ── Create multiple pending challenges for elevation-4 and elevation-5 ────────

console.log("Creating multiple pending challenges for eve...");
const ch1 = await createApiChallenge(USER, "staging-01",     "Deploy new release");
const ch2 = await createApiChallenge(USER, "data-worker-01", "Incident response");
const ch3 = await createApiChallenge(USER, "prod-db-01",     "Routine maintenance");
console.log(`  challenge IDs: ${ch1} ${ch2} ${ch3}`);

if (!ch1 && !ch2 && !ch3) {
  console.warn("  No challenges created — skipping elevation-4 and elevation-5");
  await browser.close();
  process.exit(0);
}

// ── elevation-4: browser — multiple pending challenges ────────────────────────

console.log("elevation-4 (browser — multiple pending challenges)...");
const ctx4 = await browser.newContext({ viewport: BROWSER_VIEWPORT });
const dashPage4 = await ctx4.newPage();
await dashPage4.setViewportSize(BROWSER_VIEWPORT);
await dashPage4.goto(`${BASE_URL}/dev/login?user=${USER}&role=user`, { waitUntil: "load" });
await dashPage4.emulateMedia({ colorScheme: "light" });
// Wait for pending bar showing multiple challenges (Review › button instead of inline form)
await dashPage4.waitForSelector("#pending-modal-open-btn", { timeout: 8000 }).catch(() => {});
await dashPage4.waitForTimeout(300);

await dashPage4.screenshot({ path: `${SCREENSHOTS_DIR}/elevation-4.png`, fullPage: false });
console.log(`  saved ${SCREENSHOTS_DIR}/elevation-4.png`);

// ── elevation-5: browser — modal open with per-row justification pickers ──────

console.log("elevation-5 (browser — pending modal with per-row pickers)...");
const modalOpenBtn = dashPage4.locator("#pending-modal-open-btn");
if (await modalOpenBtn.count() > 0) {
  await modalOpenBtn.click();
  // Wait for the modal overlay to gain the "open" class
  await dashPage4.waitForSelector("#pending-modal.open", { timeout: 5000 }).catch(() => {});
  await dashPage4.waitForTimeout(400); // let CSS transition finish

  // Pre-select a reason in the first modal row picker so it's clearly visible
  const modalJustSel = dashPage4.locator("#pending-modal .just-sel").first();
  if (await modalJustSel.count() > 0) {
    await modalJustSel.selectOption({ index: 1 });
    await dashPage4.waitForTimeout(150);
  }

  await dashPage4.screenshot({ path: `${SCREENSHOTS_DIR}/elevation-5.png`, fullPage: false });
  console.log(`  saved ${SCREENSHOTS_DIR}/elevation-5.png`);
} else {
  console.warn("  Review › button not found — skipping elevation-5");
}

await dashPage4.close();
await ctx4.close();

// ── Cleanup ───────────────────────────────────────────────────────────────────

await browser.close();
console.log("\nElevation screenshots saved to", SCREENSHOTS_DIR);
