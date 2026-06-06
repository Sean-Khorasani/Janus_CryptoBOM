import { test, expect } from "@playwright/test";

test.describe("Lead Fullstack Developer Enhancements Tests", () => {
  const mockAssets = [
    {
      host_uuid: "asset-101",
      hostname: "host-finance-app",
      os_name: "Linux",
      os_version: "ubuntu",
      arch: "x86_64",
      execution_mode: 2,
      last_seen: new Date().toISOString(),
      status: "Scanning Source",
      scan_progress: 45,
      current_scan_path: "/var/www/html/auth.py",
      cpu_usage: 2.5,
      mem_usage: 50.4,
      total_files_scanned: 1240
    }
  ];

  const mockComponents = [
    {
      host_uuid: "asset-101",
      telemetry_id: "t1",
      bom_ref: "pkg:npm/auth-module@1.0.0",
      name: "auth-module",
      version: "1.0.0",
      component_type: "library",
      file_path: "src/auth/login.ts",
      language: "typescript",
      algorithms: ["RSA-1024"],
      dependencies: [],
      reachable: true,
      scan_finished_unix: Math.floor(Date.now() / 1000)
    }
  ];

  const mockFindings = [
    {
      finding_id: "f-101",
      host_uuid: "asset-101",
      severity: 4,
      title: "Vulnerable RSA Cryptography",
      description: "Vulnerable key size RSA-1024 detected",
      asset_ref: "pkg:npm/auth-module@1.0.0",
      algorithm: "RSA-1024",
      policy_rule_id: "JANUS-PQC-002",
      migration_profile: "none",
      confidence: 0.9
    }
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
    await page.route("**/api/overview", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          assets: 1,
          components: 1,
          findings: 1,
          critical_findings: 0,
          high_findings: 1,
          open_migrations: 0,
          algorithm_histogram: { "RSA-1024": 1 }
        }
      });
    });
    await page.route("**/api/fleet/profiles", async (route) => {
      if (route.request().method() === "POST") {
        await route.fulfill({ status: 200, json: { status: "saved", profile_id: "profile-xyz" } });
      } else if (route.request().method() === "DELETE") {
        await route.fulfill({ status: 200, json: { status: "deleted" } });
      } else {
        await route.fulfill({
          status: 200,
          json: [
            {
              profile_id: "profile-xyz",
              name: "Secure Core Profile",
              exclude_dirs: ".git, target",
              min_key_size: 3072,
              scan_schedule: "daily",
              llm_api_key: "",
              llm_api_url: "https://api.openai.com/v1"
            }
          ]
        });
      }
    });
    await page.route("**/api/fleet/profiles/mapping", async (route) => {
      if (route.request().method() === "POST") {
        await route.fulfill({ status: 200, json: { status: "mapped" } });
      } else {
        await route.fulfill({
          status: 200,
          json: [{ host_uuid: "asset-101", profile_id: "profile-xyz" }]
        });
      }
    });
    await page.route("**/api/fleet/config", async (route) => {
      await route.fulfill({
        status: 200,
        json: { exclude_dirs: ".git", min_key_size: 2048, scan_schedule: "daily" }
      });
    });
    await page.route("**/api/policies", async (route) => {
      await route.fulfill({ status: 200, json: { active: "v1", available: [] } });
    });
    await page.route("**/api/migrations", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/webhooks**", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/retention", async (route) => {
      await route.fulfill({ status: 200, json: { retention_days: 90, auto_purge: true } });
    });
    await page.route("**/api/audit-logs", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
  });

  test("R1 & R4: Should display active scan banner at top and restructured grid layout", async ({ page }) => {
    await page.goto("/");
    
    // R4: Verify prominent active scan alert banner is shown at the very top
    const banner = page.locator(".active-scan-banner");
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("host-finance-app");
    await expect(banner).toContainText("Scanning Source");
    await expect(banner).toContainText("Progress");
    await expect(banner).toContainText("45%");
    await expect(banner).toContainText("/var/www/html/auth.py");
    await expect(banner).toContainText("1,240");

    // R1: Verify exposure distribution and findings tables are present in the DOM
    await expect(page.locator('h2:has-text("Algorithm Exposure Distribution")')).toBeVisible();
    await expect(page.locator('h2:has-text("Highest Priority Findings")')).toBeVisible();
  });

  test("R2: Should map finding asset_ref and display source file path in table row and slide-out drawer", async ({ page }) => {
    await page.goto("/");

    // R2: Verify file path is rendered underneath the description in the findings table row
    const tableCell = page.locator('td:has-text("src/auth/login.ts")');
    await expect(tableCell).toBeVisible();

    // Click the finding to open the drawer
    await page.locator('tr:has-text("Vulnerable RSA Cryptography")').click();

    // Verify detail drawer is shown
    const drawer = page.locator('[data-testid="finding-drawer"]');
    await expect(drawer).toBeVisible();

    // Verify metadata section for "Source File Path" displaying exact file path
    await expect(drawer.locator('span:has-text("Source File Path")')).toBeVisible();
    await expect(drawer.locator('span:has-text("src/auth/login.ts")')).toBeVisible();
  });

  test("R3: Should dynamically group algorithm exposure in distribution", async ({ page }) => {
    await page.goto("/");

    // R3: RSA-1024 should be normalized and grouped as "RSA"
    const rsaLabel = page.locator('span:has-text("RSA")').first();
    await expect(rsaLabel).toBeVisible();
    // Verify it doesn't render "RSA-1024" as the primary label if grouped
    const rsa1024Label = page.locator('span.font-mono:has-text("RSA-1024")');
    await expect(rsa1024Label).not.toBeVisible();
  });

  test("R5: Should load config profiles and allow mapping asset to custom profiles", async ({ page }) => {
    await page.goto("/");
    await page.locator('button:has-text("Fleet Command")').click();

    // Verify profile creation form and configuration profiles management section
    await expect(page.locator('h2:has-text("Configuration Profiles")')).toBeVisible();

    // Verify Config Profile dropdown exists in Host Inventory table and selects custom profile
    const select = page.locator("table tbody tr select").first();
    await expect(select).toBeVisible();
    
    // Select Custom Profile ("Secure Core Profile")
    await select.selectOption({ label: "Secure Core Profile" });

    // Toast notification should show success toast
    const toast = page.locator('[data-testid="fleet-toast"]');
    await expect(toast).toBeVisible();
    await expect(toast).toContainText("Profile status updated: host mapped to Secure Core Profile");
  });
});
