import { test, expect } from "@playwright/test";

test.describe("Feature 3: Compliance Posture Dashboard (R4)", () => {
  const mockAssets = [
    { host_uuid: "asset-1", hostname: "host-web-01", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" },
    { host_uuid: "asset-2", hostname: "host-db-01", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" }
  ];

  const mockFindings = [
    { finding_id: "f1", host_uuid: "asset-1", severity: 4, title: "Weak Key", description: "RSA 1024", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" },
    { finding_id: "f2", host_uuid: "asset-2", severity: 5, title: "Weak Key", description: "RSA 1024", asset_ref: "host-db-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-001", created_at: "2026-06-03T12:00:00Z" }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: mockAssets });
    });
  });

  // Tier 1 - Feature Coverage
  test("Tier 1.1: Clicking the Compliance tab displays the compliance matrix", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });

    await page.goto("/");
    const complianceTab = page.locator('button:has-text("Compliance"), a:has-text("Compliance")');
    await complianceTab.click();

    const matrix = page.locator(".compliance-matrix, [data-testid=\"compliance-matrix\"], table.compliance");
    await expect(matrix.first()).toBeVisible();
  });

  test("Tier 1.2: Matrix displays rows for each scanned asset and columns for policy rule categories", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();

    const matrixHeader = page.locator("thead tr");
    await expect(matrixHeader).toContainText("JANUS-PQC");
    await expect(matrixHeader).toContainText("JANUS-NET");
    await expect(matrixHeader).toContainText("JANUS-CLASSICAL");

    const assetRow1 = page.locator('tr:has-text("host-web-01")');
    const assetRow2 = page.locator('tr:has-text("host-db-01")');
    await expect(assetRow1).toBeVisible();
    await expect(assetRow2).toBeVisible();
  });

  test("Tier 1.3: Cell status (pass, fail, unknown) is rendered correctly based on open findings", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();

    const failCell = page.locator('.cell-fail, [data-status="fail"], :text("✗")');
    const passCell = page.locator('.cell-pass, [data-status="pass"], :text("✓")');
    
    await expect(failCell.first()).toBeVisible();
    await expect(passCell.first()).toBeVisible();
  });

  test("Tier 1.4: Overall compliance score per asset is calculated and displayed as a percentage", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();

    const scoreCell = page.locator('.asset-compliance-score, [data-testid="compliance-score"]');
    await expect(scoreCell.first()).toContainText("%");
  });

  test("Tier 1.5: Summary row displays correct fleet-wide compliance rate per rule category", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();

    const summaryRow = page.locator('tr:has-text("Fleet"), tr:has-text("Summary"), tr:has-text("Average")');
    await expect(summaryRow.first()).toBeVisible();
  });

  // Tier 2 - Boundary & Corner Cases
  test("Tier 2.1: Compliance matrix handles empty findings data gracefully", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();

    const table = page.locator(".compliance-matrix, [data-testid=\"compliance-matrix\"], table.compliance");
    await expect(table.first()).toBeVisible();
    
    const passCells = page.locator('.cell-pass, [data-status="pass"], :text("✓")');
    await expect(passCells.first()).toBeVisible();
  });

  test("Tier 2.2: Cell status updates to pass and score increases when finding status is Remediated or False Positive", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [mockFindings[0]] });
    });

    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    
    const initialScore = await page.locator('.asset-compliance-score, [data-testid="compliance-score"]').first().textContent();

    await page.locator('button:has-text("Overview"), button:has-text("CBOM")').first().click();
    await page.locator('tr:has-text("Weak Key")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const updatedScore = await page.locator('.asset-compliance-score, [data-testid="compliance-score"]').first().textContent();
    expect(updatedScore).not.toBe(initialScore);
  });

  test("Tier 2.3: Cell status remains fail when finding is Accepted", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [mockFindings[0]] });
    });

    await page.goto("/");
    
    await page.locator('tr:has-text("Weak Key")').click();
    await page.locator('button:has-text("Accept Risk"), [data-action="accept-risk"]').click();

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const failCell = page.locator('.cell-fail, [data-status="fail"], :text("✗")');
    await expect(failCell.first()).toBeVisible();
  });

  test("Tier 2.4: Asset with multiple findings in same category shows fail if one remains open", async ({ page }) => {
    const multiFindings = [
      { finding_id: "f1", host_uuid: "asset-1", severity: 4, title: "Weak Key 1", description: "RSA 1024", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" },
      { finding_id: "f2", host_uuid: "asset-1", severity: 5, title: "Weak Key 2", description: "RSA 1024", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002", created_at: "2026-06-03T12:00:00Z" }
    ];
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: multiFindings });
    });

    await page.goto("/");
    
    await page.locator('tr:has-text("Weak Key 1")').click();
    await page.locator('button:has-text("Mark Remediated"), [data-action="remediated"]').click();

    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const cell = page.locator('tr:has-text("host-web-01") td.cell-fail, tr:has-text("host-web-01") [data-status="fail"]');
    await expect(cell.first()).toBeVisible();
  });

  test("Tier 2.5: Formatting of compliance percentage at boundaries (0% and 100%)", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.goto("/");
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const score100 = page.locator('.asset-compliance-score:has-text("100%"), [data-testid="compliance-score"]:has-text("100%")');
    await expect(score100.first()).toBeVisible();

    const allFailingFindings = [
      { finding_id: "f1", host_uuid: "asset-1", severity: 4, title: "F1", description: "D1", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-PQC-001", created_at: "2026-06-03T12:00:00Z" },
      { finding_id: "f2", host_uuid: "asset-1", severity: 4, title: "F2", description: "D2", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-NET-001", created_at: "2026-06-03T12:00:00Z" },
      { finding_id: "f3", host_uuid: "asset-1", severity: 4, title: "F3", description: "D3", asset_ref: "host-web-01", algorithm: "RSA", policy_rule_id: "JANUS-CLASSICAL-003", created_at: "2026-06-03T12:00:00Z" }
    ];
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: allFailingFindings });
    });
    await page.reload();
    await page.locator('button:has-text("Compliance"), a:has-text("Compliance")').click();
    const score0 = page.locator('.asset-compliance-score:has-text("0%"), [data-testid="compliance-score"]:has-text("0%")');
    await expect(score0.first()).toBeVisible();
  });
});
