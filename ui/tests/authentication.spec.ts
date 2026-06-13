import { expect, test } from "@playwright/test";

test("dashboard remains hidden until login", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.removeItem("janus_token");
    localStorage.removeItem("janus_user");
    localStorage.removeItem("janus_role");
  });
  await page.goto("/");

  await expect(page.getByRole("dialog", { name: "Sign in to Janus Console" })).toBeVisible();
  await expect(page.locator("#main-content")).toHaveCount(0);
  await expect(page.getByRole("tab")).toHaveCount(0);
});
