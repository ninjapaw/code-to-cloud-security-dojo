import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDeploymentStatus, renderDeploymentStatus } from "../scripts/lib/deployment-status.mjs";
import {
  configHash,
  requireConfirmation,
  validateRelease,
} from "../scripts/lib/lifecycle.mjs";
import { confirmation } from "../shared/config.mjs";
import { isLabHostname, names } from "../shared/config.mjs";
import { ownedReaderAssignments } from "../scripts/lib/lifecycle.mjs";
const config = JSON.parse(
  await readFile(new URL("../config/deploy.config.json", import.meta.url)),
);
test("hostnames accept Azure-generated names but reject foreign sites and suffix attacks", () => {
  const name = "dojo-123456789abc-app";
  assert.equal(
    isLabHostname("dojo-123456789abc-portal.azurewebsites.net", name),
    false,
  );
  assert.equal(Object.hasOwn(names(config), "webgoat"), false);
  assert.match(names(config).dojo, /^dojo-[a-f0-9]{12}-app$/);
  assert.equal(isLabHostname(`${name}.azurewebsites.net`, name), true);
  assert.equal(
    isLabHostname(`${name}-hash.centralus-01.azurewebsites.net`, name),
    true,
  );
  assert.equal(
    isLabHostname(`${name}.azurewebsites.net.attacker.example`, name),
    false,
  );
  assert.equal(isLabHostname("169.254.169.254", name), false);
  assert.deepEqual(
    names({ ...config, subscriptionId: "ABC", resourceGroup: "GROUP" }),
    names({ ...config, subscriptionId: "abc", resourceGroup: "group" }),
  );
});
test("live deployment status persists progress, failures, retries and escaped HTML", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-status-"));
  const scope = { ...config, labId: "lab<test>", resourceGroup: "lab<test>" };
  try {
    const first = await createDeploymentStatus(scope, output, "provision");
    assert.match(first.url, /^file:\/\//);
    await first.update("Waiting for private vault <access>");
    let status = JSON.parse(await readFile(join(output, "deployment-status.json"), "utf8"));
    assert.equal(status.stages.find((stage) => stage.id === "provision").state, "in_progress");
    let html = await readFile(join(output, "deployment-status.html"), "utf8");
    assert.match(html, /http-equiv="refresh"/);
    assert.match(html, /Waiting for private vault &lt;access&gt;/);
    assert.doesNotMatch(html, /private vault <access>/);
    await first.observe("build", "Image history seen; scan not verified");
    status = JSON.parse(await readFile(join(output, "deployment-status.json"), "utf8"));
    assert.equal(status.stages.find((stage) => stage.id === "build").state, "observed");
    assert.match(renderDeploymentStatus(status), /scan not verified/);
    const retry = await createDeploymentStatus(scope, output, "provision");
    await retry.finish(true);
    await retry.observe("provision", "Do not replace a failed run");
    status = JSON.parse(await readFile(join(output, "deployment-status.json"), "utf8"));
    assert.equal(status.stages.find((stage) => stage.id === "provision").state, "failed");
    html = renderDeploymentStatus(status);
    assert.doesNotMatch(html, /http-equiv="refresh"/);
    assert.match(html, /lab&lt;test&gt;/);
    const success = await createDeploymentStatus(scope, output, "provision");
    await success.finish();
    await success.observe("provision", "Do not replace a completed run");
    status = JSON.parse(await readFile(join(output, "deployment-status.json"), "utf8"));
    assert.equal(status.stages.find((stage) => stage.id === "provision").state, "succeeded");
    assert.equal(status.stages.find((stage) => stage.id === "deploy").state, "pending");
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
test("private App Service workloads route through an Internet-denied subnet", async () => {
  const foundation = await readFile(
    new URL("../infra/foundation.bicep", import.meta.url),
    "utf8",
  );
  const main = await readFile(
    new URL("../infra/main.bicep", import.meta.url),
    "utf8",
  );
  const app = await readFile(
    new URL("../infra/modules/app.bicep", import.meta.url),
    "utf8",
  );
  assert.match(foundation, /name: 'DenyInternetOutbound'/);
  assert.match(foundation, /destinationAddressPrefix: 'Internet'/);
  assert.match(foundation, /name: 'workloads'/);
  assert.match(main, /resource workloads .*name: 'workloads'/);
  assert.match(main, /module dojo[\s\S]*?subnetId: workloads\.id/);
  assert.match(main, /module nginxProxy[\s\S]*?subnetId: workloads\.id/);
  assert.match(app, /vnetRouteAllEnabled: !empty\(subnetId\)/);
});
test("teardown removes only the owned subscription role for the exact principal", () => {
  const scope = `/subscriptions/${config.subscriptionId}`;
  const assignment = {
    id: `${scope}/providers/Microsoft.Authorization/roleAssignments/owned`,
    properties: {
      description: `CodeToCloud:${config.labId}`,
      scope,
      principalId: "portal",
      roleDefinitionId: `${scope}/providers/Microsoft.Authorization/roleDefinitions/39bc4728-0917-49c7-9d2c-d95423bc2eb4`,
    },
  };
  assert.deepEqual(ownedReaderAssignments(config, "portal", [assignment]), [
    assignment,
  ]);
  assert.deepEqual(
    ownedReaderAssignments(config, "different", [assignment]),
    [],
  );
  assert.deepEqual(
    ownedReaderAssignments(config, "portal", [
      {
        ...assignment,
        properties: {
          ...assignment.properties,
          description: "someone else's grant",
        },
      },
    ]),
    [],
  );
});
test("destructive confirmation is action and subscription bound", () => {
  requireConfirmation(
    config,
    "deprovision",
    confirmation(config, "deprovision"),
  );
  assert.throws(() => requireConfirmation(config, "deprovision", "yes"));
  assert.throws(() =>
    requireConfirmation(
      { ...config, subscriptionId: "other" },
      "deprovision",
      confirmation(config, "deprovision"),
    ),
  );
});
test("release must carry immutable digests, scan hashes and exact config provenance", () => {
  const release = {
    schemaVersion: 1,
    codeRevision: "0".repeat(40),
    configHash: configHash(config),
    source: {
      ...config.source,
      tree: "e".repeat(40),
      snapshotSha256: "f".repeat(64),
      files: 1,
    },
    images: {
      portal: {
        digest: `sha256:${"a".repeat(64)}`,
        imageId: `sha256:${"b".repeat(64)}`,
        scanHash: "c".repeat(64),
      },
      dojo: {
        digest: `sha256:${"d".repeat(64)}`,
        imageId: `sha256:${"e".repeat(64)}`,
        scanHash: "f".repeat(64),
      },
    },
  };
  validateRelease(config, release);
  assert.throws(() =>
    validateRelease(config, { ...release, codeRevision: undefined }),
  );
  assert.throws(
    () => validateRelease(config, { ...release, source: config.source }),
    /snapshot provenance/,
  );
  assert.throws(() =>
    validateRelease({ ...config, location: "other" }, release),
  );
  assert.throws(() =>
    validateRelease(config, {
      ...release,
      images: {
        ...release.images,
        portal: { ...release.images.portal, imageId: undefined },
      },
    }),
  );
  assert.throws(() => validateRelease(config, { ...release, images: {} }));
});
