import { test, expect } from "@playwright/test";

test.describe("Feature 1: Interactive Crypto Exposure Graph (R2)", () => {
  test.beforeEach(async ({ page }) => {
    // Default assets mock
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { host_uuid: "h1", hostname: "host-production-01", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" }
        ])
      });
    });

    // Default components mock
    await page.route("**/api/components", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { host_uuid: "h1", telemetry_id: "t1", bom_ref: "b1", name: "openssl-lib", version: "1.1.1", component_type: "library", file_path: "/usr/lib/libcrypto.so", algorithms: ["RSA"] },
          { host_uuid: "h1", telemetry_id: "t2", bom_ref: "b2", name: "other-lib", version: "1.0.0", component_type: "library", file_path: "/usr/lib/libother.so", algorithms: ["AES"] }
        ])
      });
    });

    // Default findings mock
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([])
      });
    });

    // Default overview mock
    await page.route("**/api/overview", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          assets: 1,
          components: 2,
          findings: 0,
          critical_findings: 0,
          high_findings: 0,
          open_migrations: 0,
          algorithm_histogram: { RSA: 1, AES: 1 }
        })
      });
    });
  });

  // Tier 1 - Feature Coverage
  test("Tier 1.1: Graph container is visible and renders an SVG element", async ({ page }) => {
    await page.goto("/");
    // Check for overview or graph tab/container
    const graphTab = page.locator('button:has-text("Graph")').or(page.locator('button:has-text("Overview")'));
    await graphTab.first().click();
    
    // Expect SVG graph to be present
    const graphContainer = page.locator(".crypto-graph-container, #crypto-graph, svg.crypto-graph");
    await expect(graphContainer.first()).toBeVisible();
  });

  test("Tier 1.2: Host nodes are rendered and labeled correctly", async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { host_uuid: "h1", hostname: "host-production-01", os_name: "Linux", os_version: "ubuntu", arch: "x86_64", execution_mode: 2, last_seen: "2026-06-03T12:00:00Z" }
        ])
      });
    });

    await page.goto("/");
    const hostNode = page.locator('rect.node-host, [data-node-type="host"]');
    await expect(hostNode.first()).toBeVisible();
    await expect(page.locator(':text("host-production-01"), [data-node-label="host-production-01"]')).toBeVisible();
  });

  test("Tier 1.3: Component nodes are rendered and labeled", async ({ page }) => {
    await page.route("**/api/components", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { host_uuid: "h1", telemetry_id: "t1", bom_ref: "b1", name: "openssl-lib", version: "1.1.1", component_type: "library", file_path: "/usr/lib/libcrypto.so", algorithms: ["RSA"] }
        ])
      });
    });

    await page.goto("/");
    const componentNode = page.locator('rect.node-component, [data-node-type="component"]');
    await expect(componentNode.first()).toBeVisible();
    await expect(page.locator(':text("openssl-lib"), [data-node-label="openssl-lib"]')).toBeVisible();
  });

  test("Tier 1.4: Algorithm nodes are rendered", async ({ page }) => {
    await page.route("**/api/components", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([
          { host_uuid: "h1", telemetry_id: "t1", bom_ref: "b1", name: "openssl-lib", version: "1.1.1", component_type: "library", file_path: "/usr/lib/libcrypto.so", algorithms: ["RSA", "SHA-1"] }
        ])
      });
    });

    await page.goto("/");
    const algoNode = page.locator('circle.node-algorithm, [data-node-type="algorithm"]');
    await expect(algoNode.first()).toBeVisible();
  });

  test("Tier 1.5: Edges are rendered as line/path elements connecting hosts to components and components to algorithms", async ({ page }) => {
    await page.goto("/");
    const edge = page.locator('line.graph-edge, path.graph-edge, [data-edge-type="connection"]');
    await expect(edge.first()).toBeVisible();
  });

  // Tier 2 - Boundary & Corner Cases
  test("Tier 2.1: Node rendering handles zero hosts/components gracefully without SVG crashes", async ({ page }) => {
    await page.route("**/api/assets", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });
    await page.route("**/api/components", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });

    await page.goto("/");
    const svgElement = page.locator("svg.crypto-graph, #crypto-graph");
    await expect(svgElement.first()).toBeVisible();
    const errorBox = page.locator(".error-boundary, :text('Crash'), :text('Error')");
    await expect(errorBox).not.toBeVisible();
  });

  test("Tier 2.2: Node color-coding is red when finding severity is critical", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({
        status: 200,
        json: [
          { finding_id: "f1", host_uuid: "h1", severity: 5, title: "Weak Key", description: "RSA 1024", asset_ref: "host-1", algorithm: "RSA", policy_rule_id: "JANUS-PQC-002" }
        ]
      });
    });

    await page.goto("/");
    const redNode = page.locator('.node-critical, [data-severity="critical"], rect[fill="#d33f49"], circle[fill="#d33f49"]');
    await expect(redNode.first()).toBeVisible();
  });

  test("Tier 2.3: Node color-coding is green when findings are all compliant", async ({ page }) => {
    await page.route("**/api/findings", async (route) => {
      await route.fulfill({ status: 200, json: [] });
    });

    await page.goto("/");
    const compliantNode = page.locator('.node-compliant, [data-status="compliant"], rect[fill="#11845b"], circle[fill="#11845b"]');
    await expect(compliantNode.first()).toBeVisible();
  });

  test("Tier 2.4: Clicking a node highlights connected edges and dims other edges", async ({ page }) => {
    await page.goto("/");
    const svg = page.locator("svg.crypto-graph");
    await expect(svg).toBeVisible();
    await page.waitForTimeout(500);

    const node = page.locator('[data-node-type="component"]').first();
    await node.click({ force: true });
    
    const highlightedEdge = page.locator('.edge-highlighted, [data-highlighted="true"]');
    await expect(highlightedEdge.first()).toBeVisible();
    
    const dimmedEdge = page.locator('.edge-dimmed, [data-dimmed="true"]');
    await expect(dimmedEdge.first()).toBeVisible();
  });

  test("Tier 2.5: Dragging/moving a node updates its SVG coordinates or updates layout dynamically", async ({ page }) => {
    await page.goto("/");
    const svg = page.locator("svg.crypto-graph");
    await expect(svg).toBeVisible();
    await page.waitForTimeout(500);

    const node = page.locator('[data-node-type="component"]').first();
    
    const boundingBoxBefore = await node.boundingBox();
    expect(boundingBoxBefore).not.toBeNull();
    
    if (boundingBoxBefore) {
      await page.mouse.move(boundingBoxBefore.x + 10, boundingBoxBefore.y + 10);
      await page.mouse.down();
      await page.mouse.move(boundingBoxBefore.x + 60, boundingBoxBefore.y + 60, { steps: 5 });
      await page.mouse.move(boundingBoxBefore.x + 110, boundingBoxBefore.y + 110, { steps: 5 });
      await page.mouse.up();
      
      await page.waitForTimeout(500);

      const nodeAfter = page.locator('[data-node-type="component"]').first();
      const boundingBoxAfter = await nodeAfter.boundingBox();
      expect(boundingBoxAfter).not.toBeNull();
      if (boundingBoxAfter) {
        expect(boundingBoxAfter.x).not.toBe(boundingBoxBefore.x);
      }
    }
  });
});
