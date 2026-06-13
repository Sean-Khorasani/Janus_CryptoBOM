import { expect, test } from "@playwright/test";

const agent = {
  host_uuid: "agent-1", hostname: "finance-linux-01", os_name: "Linux", os_version: "24.04",
  arch: "x86_64", execution_mode: 1, last_seen: "2026-06-11T00:00:00Z", scan_progress: 42,
  current_scan_path: "/srv/app", cpu_usage: 1, mem_usage: 20, status: "Scanning", total_files_scanned: 400,
  agent_version: "1.2.3", observed_ip: "10.0.0.7", dns_name: "finance-linux-01.example.test",
  first_registered_at: "2026-01-01T00:00:00Z", last_registered_at: "2026-06-11T00:00:00Z",
  last_scan_id: "scan-1", last_scan_finished: "2026-06-10T23:00:00Z", last_scan_severity: 5, open_findings: 12
};

test("fleet inventory uses server query controls and opens agent history", async ({ page }) => {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/overview") {
      return route.fulfill({ status: 200, json: { assets: 5000, components: 0, findings: 0, critical_findings: 0, high_findings: 0, open_migrations: 0, algorithm_histogram: {} } });
    }
    if (path === "/api/policies") {
      return route.fulfill({ status: 200, json: { active: "", available: [] } });
    }
    if (path === "/api/assets") {
      return route.fulfill({
        status: 200,
        headers: { "X-Total-Count": "5000" },
        json: [agent]
      });
    }
    if (path === "/api/agents/agent-1/scans") return route.fulfill({ status: 200, json: [{ scan_id: "scan-1", scan_finished: "2026-06-10T23:00:00Z", status: "completed", finding_count: 1, max_severity: 5 }] });
    if (path === "/api/agents/agent-1/connections") return route.fulfill({ status: 200, json: [] });
    if (path === "/api/reports/scan-1/findings") return route.fulfill({ status: 200, json: [{ finding_id: "finding-1", severity: 5, title: "Weak RSA key", description: "RSA-1024", asset_ref: "/srv/app/key.pem", algorithm: "RSA" }] });
    return route.fulfill({ status: 200, json: [] });
  });

  await page.goto("/");
  await page.waitForFunction(() => document.getElementById("tab-fleet") !== null);
  await page.evaluate(() => document.getElementById("tab-fleet")?.click());

  await expect(page.getByText("Agent Inventory")).toBeVisible();
  await expect(page.getByText("Showing 1 of 5000 agents.")).toBeVisible();
  await expect(page.getByText("finance-linux-01").first()).toBeVisible();
  await page.getByText("finance-linux-01").first().click();
  await expect(page.getByRole("dialog", { name: "Agent details finance-linux-01" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Latest Scan Findings" })).toBeVisible();
  await expect(page.getByText("Weak RSA key")).toBeVisible();
});

test("transient dashboard API failures preserve last known data", async ({ page }) => {
  let assetsRequests = 0;
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/overview") return route.fulfill({ status: 200, json: { assets: 1, components: 0, findings: 0, critical_findings: 0, high_findings: 0, open_migrations: 0, algorithm_histogram: {} } });
    if (path === "/api/assets") {
      assetsRequests++;
      return assetsRequests === 1
        ? route.fulfill({ status: 200, json: [agent] })
        : route.fulfill({ status: 503, body: "temporary failure" });
    }
    if (path === "/api/components" || path === "/api/findings" || path === "/api/migrations") return route.fulfill({ status: 200, json: [] });
    if (path === "/api/policies") return route.fulfill({ status: 200, json: { active: "", available: [] } });
    return route.fulfill({ status: 200, json: [] });
  });

  await page.goto("/");
  await expect(page.getByTestId("home-agent-agent-1")).toBeVisible();
  await expect.poll(() => assetsRequests, { timeout: 15000 }).toBeGreaterThan(1);
  await expect(page.getByTestId("home-agent-agent-1")).toBeVisible();
  await expect(page.getByText("1 dashboard request failed; showing last known data.")).toBeVisible();
});

test("overview shows actionable current agent status", async ({ page }) => {
  let scanRequested = false;
  let commandPolls = 0;
  let configSaved = false;
  await page.route("**/api/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/overview") {
      return route.fulfill({ status: 200, json: { assets: 1, components: 0, findings: 0, critical_findings: 0, high_findings: 0, open_migrations: 0, algorithm_histogram: {} } });
    }
    if (url.pathname === "/api/policies") return route.fulfill({ status: 200, json: { active: "", available: [] } });
    if (url.pathname === "/api/assets") return route.fulfill({ status: 200, headers: { "X-Total-Count": "1" }, json: [agent] });
    if (url.pathname === "/api/agents/agent-1") return route.fulfill({ status: 200, json: agent });
    if (url.pathname === "/api/agents/agent-1/commands") {
      scanRequested = true;
      return route.fulfill({ status: 202, json: { status: "queued", message: "Queued for delivery to the connected agent", command_id: "command-1" } });
    }
    if (url.pathname === "/api/agents/agent-1/commands/command-1") return route.fulfill({ status: 200, json: { status: ++commandPolls > 1 ? "completed" : "executing" } });
    if (url.pathname === "/api/agents/agent-1/config" && route.request().method() === "GET") return route.fulfill({ status: 200, json: { scan_roots: ["/srv/app"], exclude_dirs: [".git"], include_extensions: ["rs"], scan_interval_seconds: 300, max_file_bytes: 2097152, max_binary_bytes: 16777216, network_targets: [], configured: true } });
    if (url.pathname === "/api/scan-config/schema") return route.fulfill({ status: 200, json: { defaults: { scan_interval_seconds: 900, max_file_bytes: 2097152, max_binary_bytes: 16777216 }, limits: { scan_interval_seconds: { min: 10, max: 604800 }, scan_bytes: { min: 1024, max: 10737418240 } } } });
    if (url.pathname === "/api/agents/agent-1/config" && route.request().method() === "PUT") { configSaved = true; return route.fulfill({ status: 200, json: {} }); }
    return route.fulfill({ status: 200, json: [] });
  });

  await page.goto("/");
  const row = page.getByTestId("home-agent-agent-1");
  await expect(page.getByRole("heading", { name: "Agent Status" })).toBeVisible();
  await expect(row.getByText("finance-linux-01")).toBeVisible();
  await expect(row.getByText("Scanning", { exact: true }).first()).toBeVisible();
  await expect(row.getByText("/srv/app")).toBeVisible();
  await expect(row.getByText("12 open findings")).toBeVisible();
  await row.getByRole("button", { name: "Rescan" }).click();
  await expect(row.getByText("Scan completed")).toBeVisible();
  expect(scanRequested).toBeTruthy();

  await row.getByRole("button", { name: "Configure" }).click();
  await expect(page.getByRole("dialog", { name: "Configure finance-linux-01" })).toBeVisible();
  await page.getByRole("dialog", { name: "Configure finance-linux-01" }).locator('input[type="number"]').first().fill("600");
  await page.getByRole("button", { name: "Restore" }).click();
  await expect(page.getByText("Configuration restored to last saved values.")).toBeVisible();
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("Configuration applied successfully; the agent will use it before the next scan.")).toBeVisible();
  expect(configSaved).toBeTruthy();
  await page.getByRole("button", { name: "Close", exact: true }).click();

  await row.getByRole("button", { name: "Details" }).click();
  await expect(page.getByRole("dialog", { name: "Agent details finance-linux-01" })).toBeVisible();
});

test("authenticated reports open in populated new tabs without navigating the dashboard", async ({ page }) => {
  await page.route("**/api/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/overview") return route.fulfill({ status: 200, json: { assets: 1, components: 0, findings: 0, critical_findings: 0, high_findings: 0, open_migrations: 0, algorithm_histogram: {} } });
    if (url.pathname === "/api/policies") return route.fulfill({ status: 200, json: { active: "", available: [] } });
    if (url.pathname === "/api/assets") return route.fulfill({ status: 200, headers: { "X-Total-Count": "1" }, json: [agent] });
    if (url.pathname === "/api/agents/agent-1") return route.fulfill({ status: 200, json: agent });
    if (url.pathname === "/api/agents/agent-1/scans") return route.fulfill({ status: 200, json: [{ scan_id: "scan-1", scan_finished: "2026-06-10T23:00:00Z", status: "completed", finding_count: 1, max_severity: 5 }] });
    if (url.pathname === "/api/agents/agent-1/connections") return route.fulfill({ status: 200, json: [] });
    if (url.pathname === "/api/reports/scan-1/findings") return route.fulfill({ status: 200, json: [{ finding_id: "finding-1", title: "Weak RSA key" }] });
    if (url.pathname === "/api/report.html") return route.fulfill({ status: 200, contentType: "text/html", body: '<!doctype html><html><body><nav aria-label="Report navigation"><button>Back</button><a href="/">Home</a></nav><h1>Janus CryptoBOM Enterprise Report</h1></body></html>' });
    return route.fulfill({ status: 200, json: [] });
  });

  await page.goto("/");
  const dashboardURL = page.url();

  const htmlPopupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open HTML report (opens in new tab)" }).first().click();
  await htmlPopupPromise;
  await expect.poll(() => page.context().pages().length).toBe(2);
  await expect.poll(async () => (await Promise.all(page.context().pages().map(candidate => candidate.content()))).some(content => content.includes("Janus CryptoBOM Enterprise Report") && content.includes('href="/">Home</a>'))).toBeTruthy();
  expect(page.url()).toBe(dashboardURL);

  await page.getByTestId("home-agent-agent-1").getByRole("button", { name: "Details" }).click();
  const detailsURL = page.url();
  const jsonPopupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Findings JSON" }).click();
  await jsonPopupPromise;
  await expect.poll(() => page.context().pages().length).toBe(3);
  await expect.poll(async () => (await Promise.all(page.context().pages().map(candidate => candidate.content()))).some(content => content.includes("<h1>Findings JSON</h1>") && content.includes("Weak RSA key") && content.includes('href="/">Home</a>'))).toBeTruthy();
  expect(page.url()).toBe(detailsURL);
});
