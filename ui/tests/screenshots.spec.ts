import { test } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";

// Captures dark-theme dashboard screenshots into docs/images/ for the README,
// including a dedicated, settled shot of the interactive crypto-exposure graph.
// Manual tool, NOT part of the e2e suite — it needs a live server on :8080 with
// real data, so it is skipped unless JANUS_CAPTURE is set. Run with:
//   JANUS_CAPTURE=1 node node_modules/playwright/cli.js test screenshots.spec.ts
// (relies on the standard harness: globalSetup logs in; webServer starts npm run dev).

// Playwright runs with cwd = ui/, so docs/images is one level up.
const OUT_DIR = path.resolve(process.cwd(), "..", "docs", "images");

test.use({ viewport: { width: 1600, height: 1000 } });

test("capture dark-theme dashboard previews", async ({ page }) => {
  test.skip(!process.env.JANUS_CAPTURE, "manual screenshot tool — set JANUS_CAPTURE=1 with a live server on :8080");
  test.setTimeout(180_000); // graph settle + full-page + 9 tabs exceeds the 30s default
  mkdirSync(OUT_DIR, { recursive: true });

  // Boot the SPA in dark mode (App reads these on mount and sets data-theme).
  await page.addInitScript(() => {
    localStorage.setItem("theme", "dark");
    localStorage.setItem("darkMode", "true");
  });

  await page.goto("/");
  await page.locator("#main-content").waitFor({ state: "visible", timeout: 30_000 });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(2_000);

  // --- Hero: the interactive crypto-exposure graph (Overview tab, below the fold) ---
  const graph = page.locator("#crypto-graph");
  if (await graph.count()) {
    await graph.scrollIntoViewIfNeeded();
    // Let the force-directed layout settle before capture.
    await page.waitForTimeout(4_000);
    await graph.screenshot({ path: path.join(OUT_DIR, "crypto-graph-dark.png") });
    // eslint-disable-next-line no-console
    console.log("captured docs/images/crypto-graph-dark.png");
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(500);
  }

  // Full-page Overview (cards + certificate health + agent status + graph).
  await page.screenshot({ path: path.join(OUT_DIR, "overview-dark-full.png"), fullPage: true });
  // eslint-disable-next-line no-console
  console.log("captured docs/images/overview-dark-full.png");

  // --- Per-tab dark viewport shots ---
  const tabIds: string[] = await page.$$eval('[role="tab"]', (els) =>
    els.map((e) => (e.getAttribute("id") || "").replace(/^tab-/, "")).filter(Boolean)
  );

  for (const id of tabIds) {
    await page.locator(`#tab-${id}`).click();
    await page.waitForLoadState("networkidle").catch(() => {});
    // Charts / force-directed graph / async panels settle before capture.
    await page.waitForTimeout(2_500);
    await page.screenshot({ path: path.join(OUT_DIR, `dashboard-${id}-dark.png`) });
    // eslint-disable-next-line no-console
    console.log(`captured docs/images/dashboard-${id}-dark.png`);
  }
});
