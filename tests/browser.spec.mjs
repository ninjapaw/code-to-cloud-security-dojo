import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { createApp } from "../apps/control-portal/app.mjs";
import { MemoryEvidenceStore } from "../shared/evidence-store.mjs";
import { emptyReport } from "../shared/report.mjs";

test("authenticated browser consent, fixed test execution, report and logout", async () => {
  const config = {
    origin: "http://127.0.0.1",
    adminPassword: "local-test-only-".repeat(5),
    sessionKey: "local-session-only-".repeat(5),
    labId: "test-fixture",
    resourceGroup: "test-fixture",
    location: "centralus",
    source: {
      repository: "https://github.com/WebGoat/WebGoat.git",
      revision: "a".repeat(40),
    },
    dojoName: "dojo-123456789abc-app",
    dojoHost: "dojo-123456789abc-app.azurewebsites.net",
    dojoResourceId: "/subscriptions/test/target",
  };
  let testRequests = 0;
  const app = createApp({
    config,
    store: new MemoryEvidenceStore(),
    reportProvider: async (runs) => ({
      ...emptyReport(config, "test-fixture"),
      runs,
    }),
    fetcher: async () => {
      testRequests++;
      return { status: 200 };
    },
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  config.origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch(
    process.platform === "win32" ? { channel: "msedge" } : {},
  );
  try {
    const page = await browser.newPage({
      viewport: { width: 390, height: 844 },
    });
    await page.goto(config.origin);
    await page.locator("#login:not([hidden])").waitFor();
    await page.locator('input[name="password"]').fill(config.adminPassword);
    await page.locator("#login-form button").click();
    await page.locator("#workspace:not([hidden])").waitFor();
    await page.locator('[data-view="lab"]').click();
    await page.locator('[data-test="health"]').click();
    assert.equal(await page.locator("#execute").isDisabled(), true);
    await page.locator("#authorized").check();
    await page.locator("#execute").click();
    await page
      .locator("#runs")
      .getByText(/response-received/)
      .waitFor();
    assert.equal(testRequests, 1);
    assert.equal(
      (await page.request.get(`${config.origin}/api/report.json`)).status(),
      200,
    );
    await page.locator("#logout").click();
    await page.locator("#login:not([hidden])").waitFor();
    assert.equal(
      (await page.request.get(`${config.origin}/api/report`)).status(),
      401,
    );
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("desktop and mobile preview navigation, responsive layout and report export", async () => {
  const config = {
    labId: "training-preview",
    resourceGroup: "training-preview",
    location: "centralus",
    source: {
      repository: "https://github.com/WebGoat/WebGoat.git",
      revision: "a".repeat(40),
    },
  };
  const app = createApp({
    config,
    preview: true,
    store: new MemoryEvidenceStore(),
    reportProvider: async () => emptyReport(config, "read-only-preview"),
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const browser = await chromium.launch(
    process.platform === "win32" ? { channel: "msedge" } : {},
  );
  const output = fileURLToPath(new URL("../output/browser/", import.meta.url));
  await mkdir(output, { recursive: true });
  try {
    for (const viewport of [
      { width: 1440, height: 1000 },
      { width: 390, height: 844 },
    ]) {
      const page = await browser.newPage({ viewport });
      const errors = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      await page.locator("#workspace:not([hidden])").waitFor();
      await page.locator("#metrics .metric").first().waitFor();
      assert.equal(await page.title(), "Code to Cloud Security Dojo");
      assert.equal(
        await page.locator("#page-title").textContent(),
        "Code to Cloud Security Dojo",
      );
      assert.ok(
        await page.locator(".brand svg").count(),
        "Lucide visual assets rendered",
      );
      for (const view of [
        "overview",
        "story",
        "findings",
        "lab",
        "status",
        "reports",
      ]) {
        await page.locator(`[data-view="${view}"]`).click();
        assert.equal(
          await page.locator(`[data-panel="${view}"]`).isVisible(),
          true,
        );
        assert.equal(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= window.innerWidth,
          ),
          true,
          `${view} horizontal overflow at ${viewport.width}`,
        );
        if (view === "story") {
          await page.locator("#next").click();
          assert.equal(
            await page.locator("#story-number").textContent(),
            "STAGE 2 OF 6",
          );
        }
        if (view === "lab")
          assert.equal(
            await page.locator('[data-test="health"]').isDisabled(),
            true,
          );
        await page.screenshot({
          path: `${output}/${view}-${viewport.width}.png`,
          fullPage: true,
        });
      }
      const html = await page.request.get(
        `http://127.0.0.1:${server.address().port}/api/report.html`,
      );
      assert.equal(html.status(), 200);
      assert.match(await html.text(), /Not live-verified/);
      assert.deepEqual(errors, []);
      await page.close();
    }
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
