import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chromium } from "@playwright/test";
import { createDeploymentStatus } from "../scripts/lib/deployment-status.mjs";
import { createApp } from "../apps/control-portal/app.mjs";
import { MemoryEvidenceStore } from "../shared/evidence-store.mjs";
import { emptyReport } from "../shared/report.mjs";

test("deployment status stays readable on desktop and mobile", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-status-browser-"));
  const browser = await chromium.launch(
    process.platform === "win32" ? { channel: "msedge" } : {},
  );
  try {
    const status = await createDeploymentStatus(
      {
        labId: "training",
        subscriptionId: "test-subscription",
        resourceGroup: "code-to-cloud-training",
        location: "centralus",
      },
      output,
      "doctor",
    );
    await status.observe(
      "provision",
      "Foundation ARM deployed; Key Vault credentials not verified",
    );
    const artifacts = fileURLToPath(
      new URL("../output/browser/", import.meta.url),
    );
    await mkdir(artifacts, { recursive: true });
    for (const [name, width, height] of [
      ["desktop", 1440, 900],
      ["mobile", 390, 844],
    ]) {
      const page = await browser.newPage({ viewport: { width, height } });
      await page.goto(
        pathToFileURL(join(output, "deployment-status.html")).href,
      );
      assert.match(
        await page.locator("body").innerText(),
        /Foundation ARM deployed/,
      );
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
        true,
        `${name} deployment status must fit its viewport`,
      );
      await page.screenshot({
        path: join(artifacts, `deployment-status-${name}.png`),
        fullPage: true,
      });
      await page.close();
    }
    await status.finish();
  } finally {
    await browser.close();
    await rm(output, { recursive: true, force: true });
  }
});

test("authenticated browser consent, fixed test execution, report and logout", async () => {
  const config = {
    origin: "http://127.0.0.1",
    adminUsername: "workshop-admin",
    adminPassword: "local-test-only-".repeat(5),
    sessionKey: "local-session-only-".repeat(5),
    labId: "test-fixture",
    resourceGroup: "test-fixture",
    location: "centralus",
    drowsyDragonEnabled: true,
    nginxProxyEnabled: true,
    nginxProxyMode: "vulnerable",
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
    reportProvider: async (runs) => {
      const report = emptyReport(config, "test-fixture");
      report.runs = runs;
      Object.assign(report.drowsyDragon, {
        state: "observed",
        scanState: "observed",
        scannedAt: "2026-09-30T12:00:00Z",
        imageDigest: `sha256:${"b".repeat(64)}`,
        observedImage: `fixture.azurecr.io/drowsy-dragon@sha256:${"b".repeat(64)}`,
        imageFindingCount: 1,
        packages: report.drowsyDragon.trackedPackages.map((name) => ({
          name,
          version: "fixture-1.0",
        })),
        vulnerabilities: [
          {
            id: "TEST-DRAGON-UI",
            package: "tar",
            severity: "MEDIUM",
            installedVersion: "fixture-1.0",
            fixedVersion: "fixture-1.1",
          },
        ],
      });
      Object.assign(report.nginxProxy, {
        state: "observed",
        scanState: "observed",
        runtimeEvidenceState: "observed",
        scannedAt: "2026-09-30T12:00:00Z",
        imageDigest: `sha256:${"c".repeat(64)}`,
        observedImage: `fixture.azurecr.io/nginx-proxy@sha256:${"c".repeat(64)}`,
        imageFindingCount: 1,
        targetFindingObserved: true,
        packages: [{ name: "nginx", version: "1.30.3-1~noble" }],
        vulnerabilities: [
          {
            id: "CVE-2026-42533",
            package: "nginx",
            severity: "HIGH",
            installedVersion: "1.30.3-1~noble",
            fixedVersion: "1.30.4-1~noble",
          },
        ],
        runtime: {
          binaryVersion: "1.30.3",
          packageVersion: "1.30.3-1~noble",
          mapRegexEnabled: true,
        },
      });
      return report;
    },
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
    await page.locator('input[name="username"]').fill(config.adminUsername);
    await page.locator('input[name="password"]').fill(config.adminPassword);
    await page.locator("#login-form button").click();
    await page.locator("#workspace:not([hidden])").waitFor();
    await page
      .locator("#dragon-overview")
      .getByText("Enabled", { exact: true })
      .waitFor();
    await page.locator('[data-view="findings"]').click();
    await page.locator('[data-panel="findings"]').waitFor({ state: "visible" });
    await page
      .locator("#dragon-findings")
      .getByText("TEST-DRAGON-UI")
      .waitFor();
    await page.locator("#proxy-findings").getByText("CVE-2026-42533").waitFor();
    assert.match(
      await page.locator("#proxy-scan-status").textContent(),
      /association: reported/,
    );
    assert.match(
      await page.locator("#proxy-runtime").textContent(),
      /1\.30\.3/,
    );
    assert.match(
      await page.locator("#dragon-scan-status").textContent(),
      /1 tracked-package findings/,
    );
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
      true,
      "Populated Drowsy Dragon evidence must fit the mobile viewport",
    );
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
    const exported = await page.request.get(`${config.origin}/api/report.json`);
    assert.equal(exported.status(), 200);
    const after = await exported.json();
    const before = structuredClone(after);
    delete before.drowsyDragon;
    delete before.nginxProxy;
    await page.locator('[data-view="reports"]').click();
    await page.locator('[data-panel="reports"]').waitFor({ state: "visible" });
    await page.locator("#before").setInputFiles({
      name: "before.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(before)),
    });
    await page.locator("#after").setInputFiles({
      name: "after.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(after)),
    });
    await page
      .locator("#comparison")
      .getByText(/Drowsy Dragon tracked-package findings: not collected -> 1/)
      .waitFor();
    assert.match(
      await page.locator("#comparison").textContent(),
      /NGINX Proxy tracked-package findings: not collected -> 1/,
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
        await page
          .locator(`[data-panel="${view}"]`)
          .waitFor({ state: "visible" });
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
        if (view === "overview") {
          assert.match(
            await page.locator("#dragon-overview").textContent(),
            /Drowsy Dragon/,
          );
          assert.match(
            await page.locator("#dragon-overview").textContent(),
            /Disabled/,
          );
          assert.match(
            await page.locator("#proxy-overview").textContent(),
            /NGINX Proxy/,
          );
          assert.match(
            await page.locator("#proxy-overview").textContent(),
            /Disabled/,
          );
        }
        if (view === "findings") {
          assert.match(
            await page.locator("#dragon-scan-status").textContent(),
            /Missing evidence is not zero vulnerabilities/,
          );
          assert.match(
            await page.locator("#dragon-packages").textContent(),
            /libgcrypt20/,
          );
          assert.match(
            await page.locator("#dragon-findings").textContent(),
            /no clean result is implied/,
          );
          assert.match(
            await page.locator("#proxy-findings").textContent(),
            /no clean result is implied/,
          );
        }
        if (view === "lab")
          assert.equal(
            await page.locator('[data-test="health"]').isDisabled(),
            true,
          );
        assert.equal(
          await page.locator('[data-test="drowsy-dragon"]').count(),
          0,
        );
        assert.equal(
          await page.locator('[data-test="nginx-proxy"]').count(),
          0,
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
