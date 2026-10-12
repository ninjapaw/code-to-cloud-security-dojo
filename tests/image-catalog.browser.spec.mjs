import test from "node:test";
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { hashCatalogHtml } from "../scripts/lib/image-catalog.mjs";

test("detected SHA catalog copy controls select exact hashes/commands and report clipboard failures", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const catalog = {
    generatedAt: "2026-10-12T13:00:00Z",
    images: [{
      image: "portal",
      bases: [{
        argument: "RUNTIME_IMAGE",
        choices: [{ digest, statuses: ["current", "archived"], archives: [] }],
      }],
    }],
  };
  const browser = await chromium.launch(process.platform === "win32" ? { channel: "msedge" } : {});
  try {
    const page = await browser.newPage();
    await page.setContent(hashCatalogHtml(catalog, { resourceGroup: "code-to-cloud-training" }));
    await page.evaluate(() => {
      window.copiedValues = [];
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText: async (value) => { window.copiedValues.push(value); } },
      });
    });
    await page.getByRole("button", { name: "Copy SHA", exact: true }).click();
    assert.equal(await page.evaluate(() => window.copiedValues[0]), digest);
    assert.match(await page.getByRole("status").innerText(), /Copied/);
    await page.getByRole("button", { name: "Copy build command", exact: true }).focus();
    await page.keyboard.press("Enter");
    const command = await page.evaluate(() => window.copiedValues[1]);
    assert.ok(command.includes(`-f base-sha=${digest}`));
    assert.ok(command.includes("-f image=portal"));
    assert.ok(command.includes("-f operation=build-test"));
    assert.equal(await page.getByRole("link", { name: "Open manual workflow" }).getAttribute("href"),
      "https://github.com/ninjapaw/code-to-cloud-security-dojo/actions/workflows/image-experiments.yml");
    await page.evaluate(() => {
      navigator.clipboard.writeText = async () => { throw new DOMException("Denied", "NotAllowedError"); };
    });
    await page.getByRole("button", { name: "Copy SHA", exact: true }).click();
    assert.match(await page.getByRole("status").innerText(), /permission denied/);
  } finally {
    await browser.close();
  }
});
