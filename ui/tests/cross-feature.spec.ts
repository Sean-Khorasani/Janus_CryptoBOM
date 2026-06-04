import { test, expect } from "@playwright/test";
import * as fs from "fs";

test.describe("Tier 3: Cross-Feature Combinations", () => {
  const mockAssets = [
    { host_uuid: "asset-1", hostname: "host-web-01", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" }
  ];

  const mockFindings = [
    { finding_id: "f1", host_uuid: "asset-1", severity: 4, title: "Weak RSA Key", description: "RSA 1024", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" },
    { finding_id: "f2", host_uuid: "asset-1", severity: 3, title: "MD5 Hash Usage", description: "MD5 used", asset_ref: "host-web-01", algorithm: "MD5", policy_rule_id: "JANUS-CLASSICAL-003", created_at: "2026-06-03T12:00:00Z" }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: mockAssets });
    });
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });
  });

  test("Cross-Feature 1: Lifecycle Status + Compliance Score - Updates matrix and recalculates score", async ({ page }) => {
    await page.goto("/");
    
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const initialScore = await page.locator('.asset-compliance-score, [data-testid="compliance-score"]').first().textContent();

    await page.locator('button:has-text("Overview"), button:has-text("CBOM")').first().click();
    await page.locator('tr:has-text("Weak RSA Key")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const updatedScore = await page.locator('.asset-compliance-score, [data-testid="compliance-score"]').first().textContent();
    expect(updatedScore).not.toBe(initialScore);
  });

  test("Cross-Feature 2: Search/Filter + Export CSV - Export contains only filtered findings", async ({ page }) => {
    await page.goto("/");
    
    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("MD5");
    
    const csvBtn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    const downloadPromise = page.waitForEvent("download");
    await csvBtn.click();
    const download = await downloadPromise;
    const path = await download.path();
    const content = fs.readFileSync(path, "utf8");

    expect(content).toContain("MD5");
    expect(content).not.toContain("RSA");
  });

  test("Cross-Feature 3: Lifecycle Status + Findings Table Sorting - Muted finding sorts correctly", async ({ page }) => {
    await page.goto("/");
    
    await page.locator('tr:has-text("Weak RSA Key")').click();
    await page.locator('button:has-text("Accept Risk"), [data-action="accept-risk"]').click();
    
    const header = page.locator('th:has-text("Severity"), [data-sort-col="severity"]').first();
    await header.click();

    const row = page.locator('tr:has-text("Weak RSA Key")');
    await expect(row).toHaveClass(/muted|opacity|accepted/);
  });

  test("Cross-Feature 4: Dark Mode + Interactive Graph - Graph styles adjust", async ({ page }) => {
    await page.goto("/");
    
    const darkToggle = page.locator('.dark-mode-toggle, [data-action="toggle-dark-mode"], button:has-text("Theme")');
    await darkToggle.click();

    const graphContainer = page.locator(".crypto-graph-container, #crypto-graph, svg.crypto-graph");
    await expect(graphContainer.first()).toBeVisible();
    await expect(graphContainer.first()).toHaveClass(/dark|bg-dark|bg-[#17211c]/);
  });

  test("Cross-Feature 5: Pagination + Search/Filter - Pagination controls adjust to filter size", async ({ page }) => {
    const largeFindings = [
      ...Array.from({ length: 38 }, (_, i) => ({
        finding_id: `f-${i}`,
        host_uuid: "asset-1",
        severity: 2,
        title: `Standard Finding ${i}`,
        description: `Description ${i}`,
        asset_ref: "host-web-01",
        algorithm: "RSA",
        policy_rule_id: "JANUS-PQC-002"
      })),
      { finding_id: "f-md5-1", host_uuid: "asset-1", severity: 4, title: "MD5 Hash A", description: "MD5 used", asset_ref: "host-web-01", algorithm: "MD5", policy_rule_id: "JANUS-CLASSICAL-003" },
      { finding_id: "f-md5-2", host_uuid: "asset-1", severity: 3, title: "MD5 Hash B", description: "MD5 used", asset_ref: "host-web-01", algorithm: "MD5", policy_rule_id: "JANUS-CLASSICAL-003" }
    ];
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: largeFindings });
    });

    await page.goto("/");
    
    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("MD5");

    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(2);

    const nextBtn = page.locator('button:has-text("Next"), [data-action="next-page"]').first();
    await expect(nextBtn).toBeDisabled();
  });
});
