import { test, expect } from "@playwright/test";

test.describe("Feature: Fleet Command Console (R9)", () => {
  const mockAssets = [
    {
      host_uuid: "asset-101",
      hostname: "host-finance-app",
      os_name: "Linux",
      os_version: "ubuntu",
      arch: "x86_64",
      execution_mode: 2,
      last_seen: new Date().toISOString(),
      status: "Idle",
      scan_progress: 0,
      current_scan_path: "",
      cpu_usage: 0.5,
      mem_usage: 12.4,
      total_files_scanned: 150
    }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: mockAssets });
    });
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/overview", async (route) => {
      await route.fulfill({
        status: 200,
        json: {
          assets: 1,
          components: 0,
          findings: 0,
          critical_findings: 0,
          high_findings: 0,
          open_migrations: 0,
          algorithm_histogram: {}
        }
      });
    });
    await page.route("**/api/webhooks**", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/retention", async (route) => {
      await route.fulfill({
        status: 200,
        json: { retention_days: 90, auto_purge: true }
      });
    });
    await page.route("**/api/fleet/config", async (route) => {
      await route.fulfill({
        status: 200,
        json: { exclude_dirs: ".git, target", min_key_size: 2048, scan_schedule: "daily" }
      });
    });
    await page.route("**/api/audit-logs", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/policies", async (route) => {
      await route.fulfill({ status: 200, json: { active: "v1", available: [] } });
    });
    await page.route("**/api/migrations", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/agent/diagnostics**", async (route) => {
      await route.fulfill({ status: 200, json: { logs: "Starting Janus Cryptographic Agent Daemon\nExclusions configured" } });
    });
  });

  test("Should navigate to Fleet Command and display cards and assets grid", async ({ page }) => {
    await page.goto("/");
    await page.locator('button:has-text("Fleet Command")').click();

    // Verify stats cards
    await expect(page.locator('div:has-text("Total Registered Agents")').first()).toBeVisible();
    await expect(page.locator('div:has-text("Online Heartbeats")').first()).toBeVisible();
    await expect(page.locator('div:has-text("Active Scanning Phase")').first()).toBeVisible();

    // Verify asset table contains host-finance-app
    await expect(page.locator('td:has-text("host-finance-app")')).toBeVisible();
  });

  test("Should trigger force scan simulation on click", async ({ page }) => {
    await page.goto("/");
    await page.locator('button:has-text("Fleet Command")').click();

    const scanBtn = page.locator('#force-scan-asset-101');
    await expect(scanBtn).toBeVisible();
    await scanBtn.click();

    // Verify toast is displayed
    const toast = page.locator('[data-testid="fleet-toast"]');
    await expect(toast).toBeVisible();
    await expect(toast).toContainText("Force scan command dispatched");

    // Scan progress should change and scan button should be disabled during scan
    await expect(scanBtn).toBeDisabled();
  });

  test("Should open agent diagnostics log viewer", async ({ page }) => {
    await page.goto("/");
    await page.locator('button:has-text("Fleet Command")').click();

    const logsBtn = page.locator('#view-logs-asset-101');
    await expect(logsBtn).toBeVisible();
    await logsBtn.click();

    // Verify side logs drawer is visible
    await expect(page.locator('h3:has-text("Agent Diagnostics Console")')).toBeVisible();
    await expect(page.locator('div:has-text("Starting Janus Cryptographic Agent Daemon")').last()).toBeVisible();

    // Close drawer
    await page.locator('#close-logs-drawer').click();
    await expect(page.locator('h3:has-text("Agent Diagnostics Console")')).not.toBeVisible();
  });

  test("Should allow deploying central config profiles", async ({ page }) => {
    await page.goto("/");
    await page.locator('button:has-text("Fleet Command")').click();

    const minKeySizeInput = page.locator('#cfg-min-key-size');
    await minKeySizeInput.fill("4096");

    const saveBtn = page.locator('#cfg-save-btn');
    await saveBtn.click();

    // Verify toast
    const toast = page.locator('[data-testid="fleet-toast"]');
    await expect(toast).toBeVisible();
    await expect(toast).toContainText("Global fleet configurations applied");
  });
});
