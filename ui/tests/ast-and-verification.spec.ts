import { test, expect } from "@playwright/test";

test.describe("AST Scanning & Post-Migration Verification Spec", () => {
  const mockAssets = [
    { host_uuid: "asset-verify-1", hostname: "shahin-desktop", os_name: "Windows", os_version: "11", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-04T12:00:00Z" }
  ];

  const mockFindings = [
    {
      finding_id: "f-ast-high",
      host_uuid: "asset-verify-1",
      severity: 4,
      title: "RSA-1024 Weak Cryptography in Code",
      description: "Observed in main.go",
      asset_ref: "file:///D:/src/main.go",
      algorithm: "RSA",
      policy_rule_id: "JANUS-PQC-002",
      created_at: "2026-06-04T12:00:00Z",
      confidence: 0.90
    },
    {
      finding_id: "f-ast-low",
      host_uuid: "asset-verify-1",
      severity: 2,
      title: "RSA-1024 Weak Cryptography in Comments",
      description: "Observed in comments in main.go",
      asset_ref: "file:///D:/src/main.go",
      algorithm: "RSA",
      policy_rule_id: "JANUS-PQC-002",
      created_at: "2026-06-04T12:00:00Z",
      confidence: 0.30
    }
  ];

  const mockMigrations = [
    {
      command_id: "cmd-verify-101",
      host_uuid: "asset-verify-1",
      target_service: "nginx",
      migration_profile: "hybrid-tls13-mlkem-mldsa",
      target_kem: "X25519MLKEM768",
      target_signature: "ML-DSA-65",
      config_path: "/etc/nginx/nginx.conf",
      state: 6,
      dry_run: false,
      issued_at: "2026-06-04T12:00:00Z",
      updated_at: "2026-06-04T12:05:00Z",
      last_error: "",
      output: "Service reloaded successfully",
      observed_tls: {
        endpoint: "127.0.0.1:443",
        protocol: "TLSv1.3",
        tls_version: "TLSv1.3",
        cipher_suite: "TLS_AES_256_GCM_SHA384",
        named_group: "X25519MLKEM768",
        signature_algorithm: "SHA256-RSA",
        certificate_subject: "CN=localhost",
        certificate_issuer: "CN=localhost",
        certificate_not_after_unix: 1893456000,
        pqc_hybrid: true,
        cleartext: false
      }
    }
  ];

  test.beforeEach(async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: mockAssets });
    });
    await page.route("**/api/findings*", async (route) => {
      await route.fulfill({ status: 200, json: mockFindings });
    });
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/migrations", async (route) => {
      await route.fulfill({ status: 200, json: mockMigrations });
    });
  });

  test("AST-Aware Scanner: should render high vs low confidence ratings", async ({ page }) => {
    await page.goto("/");

    // Click high-confidence finding row to open drawer
    const highRow = page.locator('tr:has-text("RSA-1024 Weak Cryptography in Code")');
    await highRow.click();
    
    // Verify AST-Aware rating is displayed
    const confidenceRating = page.locator('[data-testid="confidence-rating"]');
    await expect(confidenceRating).toHaveText("90%");
    await expect(page.locator('text=AST-Aware (High Confidence)')).toBeVisible();

    // Close drawer by pressing Escape key
    await page.keyboard.press("Escape");

    // Click low-confidence finding row
    const lowRow = page.locator('tr:has-text("RSA-1024 Weak Cryptography in Comments")');
    await lowRow.click();

    // Verify low confidence pattern rating is displayed
    await expect(confidenceRating).toHaveText("30%");
    await expect(page.locator('text=Regex/Pattern (Low Confidence)')).toBeVisible();
  });

  test("Post-Migration Verification: should expand row and render verification details", async ({ page }) => {
    await page.goto("/");

    // Click Migrations tab
    await page.locator('button:has-text("Migrations")').click();

    // Expand the migration row
    const row = page.locator('[data-testid="migration-row-cmd-verify-101"]');
    await row.click();

    // Check transaction and active verification details
    await expect(page.locator('text=Active Verification Successful')).toBeVisible();
    await expect(page.locator('[data-testid="pqc-hybrid-badge"]')).toBeVisible();
    await expect(page.locator('p:has-text("KEM Group: X25519MLKEM768")')).toBeVisible();
    await expect(page.locator('p:has-text("Cipher Suite: TLS_AES_256_GCM_SHA384")')).toBeVisible();
    await expect(page.locator('p:has-text("Cert Subject: CN=localhost")')).toBeVisible();
  });
});
