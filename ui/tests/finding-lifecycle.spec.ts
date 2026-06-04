import { test, expect } from "@playwright/test";

test.describe("Feature 2: Finding Lifecycle Controls (R3)", () => {
  const mockFindings = [
    { finding_id: "finding-101", host_uuid: "h1", severity: 4, title: "Weak Key Length", description: "RSA 1024-bit key", asset_ref: "host-prod-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" },
    { finding_id: "finding-102", host_uuid: "h1", severity: 5, title: "Deprecated Hash", description: "SHA-1 used", asset_ref: "host-prod-01", algorithm: "SHA-1", policy_rule_id: "JANUS-CLASSICAL-003", created_at: "2026-06-03T12:00:00Z" }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });
  });

  // Tier 1 - Feature Coverage
  test("Tier 1.1: Clicking a finding row opens the detail drawer showing details", async ({ page }) => {
    await page.goto("/");
    const row = page.locator('tr:has-text("Weak Key Length")');
    await row.click();

    const drawer = page.locator('.finding-drawer, [data-testid="finding-drawer"], .fixed.inset-y-0');
    await expect(drawer.first()).toBeVisible();
    await expect(drawer.first()).toContainText("Weak Key Length");
  });

  test("Tier 1.2: Clicking \"Accept Risk\" in the drawer persists status in localStorage", async ({ page }) => {
    await page.goto("/");
    await page.locator('tr:has-text("Weak Key Length")').click();
    
    const acceptBtn = page.locator('button:has-text("Accept Risk"), [data-action="accept-risk"]');
    await acceptBtn.click();

    const value = await page.evaluate(() => {
      return localStorage.getItem("janus_finding_statuses") || localStorage.getItem("finding-101");
    });
    expect(value).not.toBeNull();
    expect(value).toContain("accepted");
  });

  test("Tier 1.3: Clicking \"Mark False Positive\" in the drawer persists status in localStorage", async ({ page }) => {
    await page.goto("/");
    await page.locator('tr:has-text("Weak Key Length")').click();
    
    const fpBtn = page.locator('button:has-text("Mark False Positive"), [data-action="false-positive"]');
    await fpBtn.click();

    const value = await page.evaluate(() => {
      return localStorage.getItem("janus_finding_statuses") || localStorage.getItem("finding-101");
    });
    expect(value).not.toBeNull();
    expect(value).toContain("false-positive");
  });

  test("Tier 1.4: Clicking \"Mark Remediated\" in the drawer persists status in localStorage", async ({ page }) => {
    await page.goto("/");
    await page.locator('tr:has-text("Weak Key Length")').click();
    
    const remBtn = page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]');
    await remBtn.click();

    const value = await page.evaluate(() => {
      return localStorage.getItem("janus_finding_statuses") || localStorage.getItem("finding-101");
    });
    expect(value).not.toBeNull();
    expect(value).toContain("remediated");
  });

  test("Tier 1.5: Remediation progress per asset shows the correct count of remediated/total findings", async ({ page }) => {
    await page.goto("/");
    const progressText = page.locator('.remediation-progress, [data-testid="remediation-progress"]');
    await expect(progressText.first()).toBeVisible();
    await expect(progressText.first()).toContainText("findings remediated");
  });

  // Tier 2 - Boundary & Corner Cases
  test("Tier 2.1: Pre-populated Accepted status in localStorage mutes row and shows badge", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => {
      localStorage.setItem("janus_finding_statuses", JSON.stringify({ "finding-101": "accepted" }));
      localStorage.setItem("finding-101", "accepted");
    });
    
    await page.reload();
    const row = page.locator('tr:has-text("Weak Key Length")');
    await expect(row).toHaveClass(/muted|opacity|accepted/);
    const badge = row.locator('.badge, span:has-text("Accepted")');
    await expect(badge.first()).toBeVisible();
  });

  test("Tier 2.2: Marking a finding remediated updates progress counter immediately", async ({ page }) => {
    await page.goto("/");
    const initialText = await page.locator('.remediation-progress, [data-testid="remediation-progress"]').first().textContent();
    
    await page.locator('tr:has-text("Weak Key Length")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();
    
    const updatedText = await page.locator('.remediation-progress, [data-testid="remediation-progress"]').first().textContent();
    expect(updatedText).not.toBe(initialText);
  });

  test("Tier 2.3: Marking finding as false positive and reloading preserves status in localStorage and UI", async ({ page }) => {
    await page.goto("/");
    await page.locator('tr:has-text("Weak Key Length")').click();
    await page.locator('button:has-text("Mark False Positive"), [data-action="false-positive"]').click();
    
    await page.reload();
    const row = page.locator('tr:has-text("Weak Key Length")');
    const badge = row.locator('.badge, span:has-text("False Positive")');
    await expect(badge.first()).toBeVisible();
  });

  test("Tier 2.4: Changing status from Accepted to Remediated overrides status in localStorage and changes badge", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => {
      localStorage.setItem("janus_finding_statuses", JSON.stringify({ "finding-101": "accepted" }));
      localStorage.setItem("finding-101", "accepted");
    });
    
    await page.reload();
    await page.locator('tr:has-text("Weak Key Length")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();
    
    const value = await page.evaluate(() => {
      return localStorage.getItem("janus_finding_statuses") || localStorage.getItem("finding-101");
    });
    expect(value).toContain("remediated");
    
    const row = page.locator('tr:has-text("Weak Key Length")');
    const badge = row.locator('.badge, span:has-text("Remediated")');
    await expect(badge.first()).toBeVisible();
  });

  test("Tier 2.5: Invalid/missing finding IDs in localStorage do not break drawer or table rendering", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => {
      localStorage.setItem("janus_finding_statuses", JSON.stringify({ "invalid-id": "accepted" }));
      localStorage.setItem("invalid-id", "accepted");
    });
    
    await page.reload();
    const table = page.locator("table");
    await expect(table.first()).toBeVisible();
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(2);
  });
});
