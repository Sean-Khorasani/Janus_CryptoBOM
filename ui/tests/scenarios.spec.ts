import { test, expect } from "@playwright/test";
import * as fs from "var/local/fs" assert { type: "json" }; // wait, use standard fs import
import * as fsStandard from "fs";

test.describe("Tier 4: Real-World Application Scenarios", () => {
  const mockAssets = [
    { host_uuid: "asset-101", hostname: "host-finance-app", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" }
  ];

  const mockFindings = [
    { finding_id: "f101", host_uuid: "asset-101", severity: 5, title: "RSA-1024 Quantum Vulnerable Key", description: "Weak classical key", asset_ref: "host-finance-app", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" }
  ];

  const mockComponents = [
    { host_uuid: "asset-101", telemetry_id: "t101", bom_ref: "b101", name: "crypto-library", version: "2.0.1", component_type: "library", file_path: "/app/lib/crypto.jar", algorithms: ["RSA"] }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: mockAssets });
    });
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: mockComponents });
    });
  });

  test("Scenario 1: Full Remediation Workflow", async ({ page }) => {
    await page.goto("/");

    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("finance");

    const row = page.locator('tr:has-text("RSA-1024 Quantum Vulnerable Key")');
    await row.click();

    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();

    await expect(row).toHaveClass(/muted|opacity|accepted|remediated/);
    await expect(row.locator('.badge, span:has-text("Remediated")').first()).toBeVisible();

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const scoreText = await page.locator('.asset-compliance-score, [data-testid="compliance-score"]').first().textContent();
    expect(scoreText).toContain("100%");

    await page.locator('button:has-text("Overview"), button:has-text("CBOM")').first().click();
    const csvBtn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    const downloadPromise = page.waitForEvent("download");
    await csvBtn.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain(".csv");
  });

  test("Scenario 2: Security Compliance Assessment", async ({ page }) => {
    await page.goto("/");

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const failingAsset = page.locator('tr:has-text("host-finance-app") .cell-fail, tr:has-text("host-finance-app") [data-status="fail"]');
    await expect(failingAsset.first()).toBeVisible();

    await page.locator('tr:has-text("host-finance-app")').click();

    await page.locator('button:has-text("Graph"), button:has-text("Overview")').first().click();
    const libraryNode = page.locator('[data-node-label="crypto-library"], rect.node-component');
    await expect(libraryNode.first()).toBeVisible();

    await libraryNode.first().click();
    const highlightedEdge = page.locator('.edge-highlighted, [data-highlighted="true"]');
    await expect(highlightedEdge.first()).toBeVisible();

    await page.locator('button:has-text("CBOM"), button:has-text("Overview")').first().click();
    await expect(page.locator('tr:has-text("RSA-1024 Quantum Vulnerable Key")').first()).toBeVisible();
  });

  test("Scenario 3: Migration and Verification Lifecycle", async ({ page }) => {
    await page.route("**/api/migrations/enqueue", async (route) => {
      await route.fulfill({
        status: 200,
        json: { command_id: "cmd-remedi-101", status: "queued" }
      });
    });

    await page.route("**/api/migrations", async (route) => {
      await route.fulfill({
        status: 200,
        json: [
          {
            command_id: "cmd-remedi-101",
            host_uuid: "asset-101",
            target_service: "nginx",
            migration_profile: "hybrid-tls13-mlkem-mldsa",
            target_kem: "mlkem768",
            target_signature: "mldsa65",
            config_path: "/etc/nginx/nginx.conf",
            state: 3,
            dry_run: true,
            issued_at: "2026-06-03T12:00:00Z",
            updated_at: "2026-06-03T12:00:00Z",
            last_error: "",
            output: ""
          }
        ]
      });
    });

    await page.goto("/");

    const migrationsTab = page.locator('button:has-text("Migrations")');
    await migrationsTab.click();

    await page.locator('button:has-text("Queue Dry Run"), button:has-text("Run"), [data-action="enqueue"]').click();

    const toast = page.locator('.toast, [data-testid="toast-notification"], :text("Queued cmd-remedi-101")');
    await expect(toast.first()).toBeVisible();

    const statusCell = page.locator('tr:has-text("cmd-remedi-101")').locator('.badge, span');
    await expect(statusCell.first()).toBeVisible();

    await page.locator('button:has-text("Overview"), button:has-text("CBOM")').first().click();
    await page.locator('tr:has-text("RSA-1024 Quantum Vulnerable Key")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();
  });

  test("Scenario 4: Report Export and Validation", async ({ page }) => {
    await page.goto("/");

    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("RSA");

    const rsaRow = page.locator('tr:has-text("RSA-1024 Quantum Vulnerable Key")');
    await expect(rsaRow.first()).toBeVisible();

    const jsonBtn = page.locator('button:has-text("Download CBOM JSON"), button:has-text("Export CBOM"), [data-action="download-json"]').first();
    const jsonPromise = page.waitForEvent("download");
    await jsonBtn.click();
    const jsonDownload = await jsonPromise;
    const jsonPath = await jsonDownload.path();
    const jsonContent = fsStandard.readFileSync(jsonPath, "utf8");
    expect(jsonContent).toContain("bomFormat");

    const csvBtn = page.locator('button:has-text("Download Findings CSV"), button:has-text("Export CSV"), [data-action="download-csv"]').first();
    const csvPromise = page.waitForEvent("download");
    await csvBtn.click();
    const csvDownload = await csvPromise;
    const csvPath = await csvDownload.path();
    const csvContent = fsStandard.readFileSync(csvPath, "utf8");
    expect(csvContent).toContain("RSA");
  });

  test("Scenario 5: Preference and View Configuration", async ({ page }) => {
    await page.goto("/");

    const darkToggle = page.locator('.dark-mode-toggle, [data-action="toggle-dark-mode"], button:has-text("Theme")');
    await darkToggle.click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

    const nextBtn = page.locator('button:has-text("Next"), [data-action="next-page"]').first();
    if (await nextBtn.isEnabled()) {
      await nextBtn.click();
    }

    const severityHeader = page.locator('th:has-text("Severity"), [data-sort-col="severity"]').first();
    await severityHeader.click();

    await page.locator('button:has-text("Graph"), button:has-text("Overview")').first().click();
    const graphContainer = page.locator(".crypto-graph-container, #crypto-graph, svg.crypto-graph");
    await expect(graphContainer.first()).toBeVisible();

    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  });
});
