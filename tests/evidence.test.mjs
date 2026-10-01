import test from "node:test";
import assert from "node:assert/strict";
import { mergePricing, reconcileProtection } from "../shared/protection.mjs";
import { AzureClient } from "../shared/azure.mjs";
import { pricingMatches } from "../shared/protection.mjs";
import { collectReport } from "../shared/report.mjs";
import { emptyReport, reportHtml, candidateAlerts } from "../shared/report.mjs";

test("preserves unrelated Defender extensions and properties", () => {
  const current = {
    properties: {
      pricingTier: "Free",
      enforce: "True",
      extensions: [
        {
          name: "Other",
          isEnabled: "True",
          additionalExtensionProperties: { key: "value" },
        },
      ],
    },
  };
  const merged = mergePricing(current, {
    pricingTier: "Standard",
    extensions: [{ name: "Wanted", isEnabled: "True" }],
  });
  assert.equal(merged.properties.extensions.length, 2);
  assert.equal(merged.properties.enforce, "True");
  assert.equal(current.properties.pricingTier, "Free");
});
test("Defender audit never writes; repeat apply is idempotent; failed readback fails", async () => {
  let writes = 0;
  let observed = { properties: { pricingTier: "Free" } };
  const client = {
    scope: "/subscriptions/test",
    request: async (_path, options) => {
      if (options) {
        writes++;
        observed = options.body;
      }
      return observed;
    },
  };
  const desired = { AppServices: { pricingTier: "Standard" } };
  await reconcileProtection(client, desired);
  assert.equal(writes, 0);
  await reconcileProtection(client, desired, { apply: true });
  await reconcileProtection(client, desired, { apply: true });
  assert.equal(writes, 1);
  await assert.rejects(
    reconcileProtection(
      {
        ...client,
        request: async () => ({ properties: { pricingTier: "Free" } }),
      },
      desired,
      { apply: true },
    ),
    /readback/,
  );
});
test("Defender partial-success extension is not reported enabled", () => {
  const desired = {
    pricingTier: "Standard",
    extensions: [{ name: "Registry", isEnabled: "True" }],
  };
  const actual = {
    properties: {
      ...desired,
      extensions: [
        { ...desired.extensions[0], operationStatus: { code: "Failed" } },
      ],
    },
  };
  assert.equal(pricingMatches(actual, desired), false);
  assert.equal(
    mergePricing(actual, desired).properties.extensions[0].operationStatus,
    undefined,
  );
  actual.properties.extensions[0].operationStatus.code = "Succeeded";
  assert.equal(pricingMatches(actual, desired), true);
});
test("Azure pagination rejects token exfiltration and loops", async () => {
  const client = new AzureClient(
    { subscriptionId: "test" },
    {
      credential: { getToken: async () => ({ token: "test-only" }) },
      fetcher: async () => ({
        ok: true,
        json: async () => ({
          value: [],
          nextLink: "https://attacker.example/subscriptions/test/items",
        }),
      }),
    },
  );
  await assert.rejects(client.list("/subscriptions/test/items"), /outside/);
  client.request = async () => ({
    value: [],
    nextLink: "/subscriptions/test/items",
  });
  await assert.rejects(client.list("/subscriptions/test/items"), /pagination/);
});
test("ARM empty DELETE responses do not require JSON bodies", async () => {
  const client = new AzureClient(
    { subscriptionId: "test" },
    {
      credential: { getToken: async () => ({ token: "test-only" }) },
      fetcher: async () => new Response(null, { status: 200 }),
    },
  );
  assert.equal(await client.request("/subscriptions/test/resources/example", { method: "DELETE" }), null);
});
test("collector preserves unknown read failures and reports observed image digests", async () => {
  const config = {
    labId: "training",
    subscriptionId: "test",
    resourceGroup: "training",
    source: {},
    protection: { AppServices: { pricingTier: "Standard" } },
  };
  const client = {
    scope: "/subscriptions/test",
    request: async (path) => {
      if (path.includes("pricings")) throw new Error("Access denied");
      return {
        properties: {
          linuxFxVersion: `DOCKER|registry/dojo@sha256:${"a".repeat(64)}`,
        },
      };
    },
    list: async () => [],
  };
  const report = await collectReport(config, client);
  assert.equal(
    report.checks.find((check) => check.id === "AppServices").state,
    "unknown",
  );
  assert.equal(
    report.checks.find((check) => check.id === "Assessments").state,
    "pending",
  );
  assert.match(report.release.dojoObservedImage, /@sha256:/);
  assert.match(reportHtml(report), /dojoObservedImage/);
});
test("report escapes untrusted findings and labels incomplete collection", () => {
  const report = emptyReport({
    source: {},
    labId: "<script>alert(1)</script>",
  });
  const html = reportHtml(report);
  assert.ok(!html.includes("<script>"));
  assert.match(html, /Not live-verified/);
});
test("alert correlation requires exact target and activity time", () => {
  const run = {
    targetResourceId: "/subscriptions/test/resource",
    startedAt: "2026-09-29T12:00:00Z",
  };
  const alert = {
    properties: {
      startTimeUtc: run.startedAt,
      resourceIdentifiers: [{ azureResourceId: run.targetResourceId }],
    },
  };
  assert.equal(candidateAlerts([alert], run).length, 1);
  assert.equal(
    candidateAlerts([alert], { ...run, targetResourceId: "/other" }).length,
    0,
  );
  assert.equal(
    candidateAlerts([alert], { ...run, startedAt: "2026-09-28T12:00:00Z" })
      .length,
    0,
  );
});
