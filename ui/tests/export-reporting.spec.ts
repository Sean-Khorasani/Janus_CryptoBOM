import { test, expect } from "@playwright/test";
import * as fs from "fs";

test.describe("Feature 4: Export & Reporting Buttons (R5)", () => {
  const mockComponents = [
    { host_uuid: "h1", telemetry_id: "t1", bom_ref: "b1", name: "openssl-lib", version: "1.1.1", component_type: "library", file_path: "/usr/lib/libcrypto.so", algorithms: ["RSA"] }
  ];

  const mockFindings = [
    { finding_id: "f1", host_uuid: "h1", severity: 4, title: "Weak Key", description: "RSA 1024", asset_ref: "host-1", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002" }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: mockComponents });
    });
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });
  });

  // Tier 1 - Feature Coverage
  test("Tier 1.1: \"Download Findings CSV\" button is visible", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]');
    await expect(btn.first()).toBeVisible();
  });

  test("Tier 1.2: Clicking \"Download Findings CSV\" triggers a download", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain(".csv");
  });

  test("Tier 1.3: \"Download CBOM JSON\" button is visible", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]');
    await expect(btn.first()).toBeVisible();
  });

  test("Tier 1.4: Clicking \"Download CBOM JSON\" triggers a download", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]').first();
    
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain(".json");
  });

  test("Tier 1.5: \"Open HTML Report\" authenticated new-tab button is visible", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Open HTML report (opens in new tab)" }).first()).toBeVisible();
  });

  // Tier 2 - Boundary & Corner Cases
  test("Tier 2.1: Downloaded Findings CSV has correct headers", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    const path = await download.path();
    const content = fs.readFileSync(path, "utf8");
    
    const firstLine = content.split("\n")[0].toLowerCase();
    expect(firstLine).toContain("id");
    expect(firstLine).toContain("title");
    expect(firstLine).toContain("severity");
    expect(firstLine).toContain("algorithm");
    expect(firstLine).toContain("asset");
  });

  test("Tier 2.2: Downloaded CBOM JSON is valid CycloneDX 1.6 JSON", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]').first();
    
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    const path = await download.path();
    const content = fs.readFileSync(path, "utf8");
    
    const json = JSON.parse(content);
    expect(json.bomFormat).toBe("CycloneDX");
    expect(json.specVersion).toBe("1.6");
    expect(json.components).toBeInstanceOf(Array);
  });

  test("Tier 2.3: Export buttons handle empty state gracefully when list is empty", async ({ page }) => {
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });

    await page.goto("/");
    const csvBtn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    const jsonBtn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]').first();
    
    if (await csvBtn.isEnabled()) {
      const downloadPromise = page.waitForEvent("download");
      await csvBtn.click();
      const download = await downloadPromise;
      const path = await download.path();
      const content = fs.readFileSync(path, "utf8");
      expect(content.split("\n").length).toBeLessThanOrEqual(2);
    } else {
      await expect(csvBtn).toBeDisabled();
      await expect(jsonBtn).toBeDisabled();
    }
  });

  test("Tier 2.4: CSV content matches current filtered findings", async ({ page }) => {
    const multipleFindings = [
      { finding_id: "f1", host_uuid: "h1", severity: 4, title: "Weak Key RSA", description: "RSA 1024", asset_ref: "host-1", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002" },
      { finding_id: "f2", host_uuid: "h1", severity: 3, title: "MD5 Hash", description: "MD5 used", asset_ref: "host-1", algorithm: "MD5", policy_rule_id: "JANUS-CLASSICAL-003" }
    ];
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: multipleFindings });
    });

    await page.goto("/");
    
    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("MD5");
    
    const btn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    const path = await download.path();
    const content = fs.readFileSync(path, "utf8");
    
    expect(content).toContain("MD5");
    expect(content).not.toContain("RSA");
  });

  test("Tier 2.5: CBOM JSON contains all component records from API state", async ({ page }) => {
    await page.goto("/");
    const btn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]').first();
    
    const downloadPromise = page.waitForEvent("download");
    await btn.click();
    const download = await downloadPromise;
    const path = await download.path();
    const content = fs.readFileSync(path, "utf8");
    
    const json = JSON.parse(content);
    expect(json.components.length).toBe(mockComponents.length);
    expect(json.components[0].name).toBe("openssl-lib");
  });
});
