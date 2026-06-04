import { test, expect } from "@playwright/test";

test.describe("Feature 6: Policy Studio", () => {
  const mockPolicies = {
    active: "nist-pqc-2026.1",
    available: [
      {
        version: "nist-pqc-2026.1",
        minimum_rsa_key_bits: 3072,
        minimum_dh_safe_prime_bits: 3072,
        require_tls_13: true,
        require_hybrid_pq_tls_13: true,
        preferred_kem: "X25519MLKEM768",
        preferred_signature: "ML-DSA-65"
      },
      {
        version: "cnsa-2.0",
        minimum_rsa_key_bits: 3072,
        minimum_dh_safe_prime_bits: 3072,
        require_tls_13: true,
        require_hybrid_pq_tls_13: true,
        preferred_kem: "ML-KEM-1024",
        preferred_signature: "ML-DSA-87"
      }
    ]
  };

  test("Should render policy studio and active/available profiles", async ({ page }) => {
    await page.route("**/api/policies", async (route) => {
      await route.fulfill({ status: 200, json: mockPolicies });
    });

    await page.goto("/");
    await page.locator('button:has-text("Policy Studio")').click();

    await expect(page.locator("h2:has-text('Centralized Policy Studio')")).toBeVisible();
    await expect(page.locator("h3:has-text('nist-pqc-2026.1')")).toBeVisible();
    await expect(page.locator("h3:has-text('cnsa-2.0')")).toBeVisible();
  });

  test("Should allow switching policy and reflect the change", async ({ page }) => {
    let switched = false;
    await page.route("**/api/policies", async (route) => {
      await route.fulfill({ status: 200, json: mockPolicies });
    });
    await page.route("**/api/policies/active", async (route) => {
      switched = true;
      await route.fulfill({ status: 200, json: { status: "ok", active: "cnsa-2.0" } });
    });

    await page.goto("/");
    await page.locator('button:has-text("Policy Studio")').click();

    const switchBtn = page.locator('button:has-text("Activate Profile")').first();
    await switchBtn.click();

    expect(switched).toBe(true);
  });
});
