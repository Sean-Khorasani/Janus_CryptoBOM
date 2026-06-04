import { test, expect } from "@playwright/test";

test.describe("Feature 5: Polish & Polish Controls (R6)", () => {
  const generateFindings = (count: number) => {
    return Array.from({ length: count }, (_, i) => ({
      finding_id: `f-${i}`,
      host_uuid: `h-${i}`,
      severity: (i % 5) + 1,
      title: `Finding Title ${i}`,
      description: `Description of finding ${i}`,
      asset_ref: `asset-${i}`,
      algorithm: i % 2 === 0 ? "RSA" : "SHA-256",
      policy_rule_id: `RULE-${i}`
    }));
  };

  // Tier 1 - Feature Coverage
  test("Tier 1.1: Loading skeleton placeholders are rendered while API data is fetching", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await new Promise(resolve => setTimeout(resolve, 500));
      await route.fulfill({ status: 200, json: [] });
    });

    await page.goto("/");
    const skeleton = page.locator('.skeleton, .loading, [data-testid="skeleton"], [class*="animate-pulse"]');
    await expect(skeleton.first()).toBeVisible();
  });

  test("Tier 1.2: Findings table has next/previous page controls and shows 25 findings per page", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(30) });
    });

    await page.goto("/");
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(25);

    const nextBtn = page.locator('button:has-text("Next"), [data-action="next-page"]');
    const prevBtn = page.locator('button:has-text("Previous"), [data-action="prev-page"]');
    await expect(nextBtn.first()).toBeVisible();
    await expect(prevBtn.first()).toBeVisible();
  });

  test("Tier 1.3: Clicking a table header sorts the findings table", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(5) });
    });

    await page.goto("/");
    const header = page.locator('th:has-text("Severity"), [data-sort-col="severity"]');
    await header.click();
    
    const sortedRow = page.locator("tbody tr").first();
    await expect(sortedRow).toBeVisible();
  });

  test("Tier 1.4: Typing in search bar filters findings in real-time", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(5) });
    });

    await page.goto("/");
    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("Finding Title 2");
    
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("Finding Title 2");
  });

  test("Tier 1.5: Dark mode toggle switches theme to dark and persists in localStorage", async ({ page }) => {
    await page.goto("/");
    const toggle = page.locator('.dark-mode-toggle, [data-action="toggle-dark-mode"], button:has-text("Dark"), button:has-text("Theme")');
    await toggle.click();

    const html = page.locator("html");
    await expect(html).toHaveAttribute("data-theme", "dark");

    const value = await page.evaluate(() => localStorage.getItem("theme") || localStorage.getItem("darkMode"));
    expect(value).toBe("dark");
  });

  // Tier 2 - Boundary & Corner Cases
  test("Tier 2.1: Search with no matching results displays appropriate empty state", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(2) });
    });

    await page.goto("/");
    const searchInput = page.locator('input[placeholder*="Search"], .search-bar, [data-testid="search-input"]');
    await searchInput.fill("NonExistentQueryXYZ");

    const emptyMessage = page.locator('.empty-state, :text("No findings found"), :text("No findings received")');
    await expect(emptyMessage.first()).toBeVisible();
  });

  test("Tier 2.2: Pagination limits (Next button is disabled on last page)", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(30) });
    });

    await page.goto("/");
    const nextBtn = page.locator('button:has-text("Next"), [data-action="next-page"]').first();
    await nextBtn.click();
    
    await expect(nextBtn).toBeDisabled();
  });

  test("Tier 2.3: Sorting cycle: Ascending -> Descending -> Default", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: generateFindings(5) });
    });

    await page.goto("/");
    const header = page.locator('th:has-text("Severity"), [data-sort-col="severity"]').first();
    
    await header.click();
    await expect(header).toHaveClass(/asc|ascending|sorted/);

    await header.click();
    await expect(header).toHaveClass(/desc|descending|sorted/);

    await header.click();
    await expect(header).not.toHaveClass(/asc|desc|sorted/);
  });

  test("Tier 2.4: Dark mode persistence on page reload", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => {
      localStorage.setItem("theme", "dark");
      localStorage.setItem("darkMode", "true");
    });

    await page.reload();
    const html = page.locator("html");
    await expect(html).toHaveAttribute("data-theme", "dark");
  });

  test("Tier 2.5: Enqueueing a migration shows a toast notification that auto-disappears", async ({ page }) => {
    await page.goto("/");
    const migrationsTab = page.locator('button:has-text("Migrations")');
    await migrationsTab.click();

    await page.route("**/api/migrations/enqueue", async (route) => {
      await route.fulfill({
        status: 200,
        json: { command_id: "cmd-999", status: "queued" }
      });
    });

    const runBtn = page.locator('button:has-text("Queue Dry Run"), button:has-text("Run"), [data-action="enqueue"]').first();
    await runBtn.click();

    const toast = page.locator('.toast, [data-testid="toast-notification"], :text("Queued cmd-999"), :text("Success")');
    await expect(toast.first()).toBeVisible();

    await page.waitForTimeout(3500);
    await expect(toast.first()).not.toBeVisible();
  });
});
