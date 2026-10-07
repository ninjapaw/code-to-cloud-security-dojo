import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { names } from "../shared/config.mjs";
import {
  automaticContext,
  validateAutomaticPreview,
  updateRunnerAccess,
  withRunnerAccess,
  waitForRelease,
  checkPortalRevision,
  reconcileDragonScanTag,
  validateRolloutReport,
} from "../scripts/lib/automatic-rollout.mjs";

const config = {
  ...JSON.parse(await readFile(new URL("../config/deploy.config.json", import.meta.url))),
  tenantId: "11111111-1111-4111-8111-111111111111",
  subscriptionId: "22222222-2222-4222-8222-222222222222",
  operatorObjectId: "33333333-3333-4333-8333-333333333333",
  adminCidr: "203.0.113.10/32",
  drowsyDragonEnabled: true,
  nginxProxyEnabled: true,
};
const resourceNames = names(config);
const revision = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const scanHash = "c".repeat(64);
const release = {
  codeRevision: revision,
  images: Object.fromEntries(["dojo", "portal", "drowsyDragon", "nginxProxy"].map((key) =>
    [key, { digest, scanJsonHash: scanHash }])),
};
const environment = {
  GITHUB_ACTIONS: "true",
  GITHUB_EVENT_NAME: "push",
  GITHUB_REF: "refs/heads/dev",
  GITHUB_REPOSITORY: "ninjapaw/code-to-cloud-security-dojo",
  GITHUB_WORKFLOW_REF: "ninjapaw/code-to-cloud-security-dojo/.github/workflows/deploy.yml@refs/heads/dev",
  GITHUB_RUN_ID: "1234",
  GITHUB_RUN_ATTEMPT: "1",
  GITHUB_SHA: revision,
  DOJO_AUTOMATIC_ROLLOUT: "true",
  DOJO_ROLLOUT_RUNNER_IPV4: "203.0.113.11",
};
const group = `/subscriptions/${config.subscriptionId}/resourceGroups/${config.resourceGroup}`;

test("automatic rollout is explicit, same-revision and limited to the trusted dev workflow", () => {
  assert.equal(automaticContext(config, release, environment).ipAddress, "203.0.113.11/32");
  assert.equal(automaticContext(config, release, environment).name, "GitHubRollout-1234-1");
  assert.doesNotMatch(automaticContext(config, release, environment).description, /[;,]/);
  for (const changes of [
    { GITHUB_ACTIONS: "false" }, { GITHUB_REF: "refs/heads/main" },
    { GITHUB_EVENT_NAME: "pull_request" }, { GITHUB_EVENT_NAME: "pull_request_target" },
    { GITHUB_SHA: "d".repeat(40) }, { DOJO_AUTOMATIC_ROLLOUT: "false" },
    { GITHUB_WORKFLOW_REF: "other/workflow" }, { GITHUB_REPOSITORY: "other/repository" },
    { GITHUB_RUN_ID: "../1234" }, { DOJO_ROLLOUT_RUNNER_IPV4: "10.0.0.1" },
    { DOJO_ROLLOUT_RUNNER_IPV4: "203.0.113.11/24" },
  ])
    assert.throws(() => automaticContext(config, release, { ...environment, ...changes }));
  assert.throws(() => automaticContext({ ...config, resourceGroup: "production" }, release, environment));
});

test("automatic previews reject creates, deletes, failed previews and unrelated resource changes", () => {
  const change = {
    changeType: "Modify",
    resourceId: `${group}/providers/Microsoft.Web/sites/${resourceNames.dojo}`,
  };
  const preview = { status: "Succeeded", changes: [change] };
  assert.equal(validateAutomaticPreview(config, preview), preview);
  for (const changeType of ["Create", "Delete", "Deploy", "Unsupported"])
    assert.throws(() => validateAutomaticPreview(config, {
      ...preview, changes: [{ ...change, changeType }],
    }), /refuses/);
  for (const resourceId of [
    `${group}/providers/Microsoft.Web/sites/unrelated-app`,
    `${group}/providers/Microsoft.Web/serverfarms/${resourceNames.dojo}-plan`,
    `${group}/providers/Microsoft.KeyVault/vaults/${resourceNames.vault}`,
    `${group}/providers/Microsoft.Storage/storageAccounts/${resourceNames.storage}`,
    `${group}/providers/Microsoft.Authorization/roleAssignments/new-admin`,
    change.resourceId.replace(config.resourceGroup, "other-group"),
  ])
    assert.throws(() => validateAutomaticPreview(config, {
      ...preview, changes: [{ ...change, resourceId }],
    }), /refuses/);
  assert.throws(() => validateAutomaticPreview(config, { status: "Failed", changes: [] }), /successful/);
  assert.throws(() => validateAutomaticPreview(config, { status: "Succeeded" }), /complete/);
  assert.throws(() => validateAutomaticPreview(config, { ...preview, error: {} }), /successful/);
});

test("automatic preview allows only the existing registry pull role", () => {
  const properties = {
    roleDefinitionId: `/subscriptions/${config.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d`,
  };
  const role = {
    changeType: "Modify",
    resourceId: `${group}/providers/Microsoft.ContainerRegistry/registries/${resourceNames.registry}/providers/Microsoft.Authorization/roleAssignments/existing`,
    before: { properties }, after: { properties },
  };
  validateAutomaticPreview(config, { status: "Succeeded", changes: [role] });
  assert.throws(() => validateAutomaticPreview(config, {
    status: "Succeeded",
    changes: [{ ...role, after: { properties: { roleDefinitionId: "contributor" } } }],
  }), /refuses/);
});

function accessClient() {
  const properties = {
    ipSecurityRestrictionsDefaultAction: "Deny",
    scmIpSecurityRestrictionsDefaultAction: "Deny",
    ipSecurityRestrictions: [
      { name: "AuthorizedAdmin", ipAddress: config.adminCidr, action: "Allow", priority: 100 },
      { name: "Deny all", ipAddress: "Any", action: "Deny", priority: 2147483647 },
    ],
    linuxFxVersion: "unchanged",
  };
  const requests = [];
  return {
    properties, requests,
    request: async (path, options) => {
      assert.ok(path.includes(`/sites/${resourceNames.portal}/config/web?`));
      requests.push({ path, options });
      if (options) {
        assert.equal(options.method, "PATCH");
        assert.deepEqual(Object.keys(options.body.properties), ["ipSecurityRestrictions"]);
        Object.assign(properties, structuredClone(options.body.properties));
      }
      return { properties: structuredClone(properties) };
    },
  };
}

test("temporary runner access is a single /32, idempotent and cleaned on success or failure", async () => {
  for (const fail of [false, true]) {
    const client = accessClient();
    const before = structuredClone(client.properties);
    const callback = async () => {
      const rule = client.properties.ipSecurityRestrictions.find((item) => item.name === "GitHubRollout-1234-1");
      assert.equal(rule.ipAddress, "203.0.113.11/32");
      assert.equal(rule.action, "Allow");
      assert.equal(client.properties.ipSecurityRestrictionsDefaultAction, "Deny");
      await updateRunnerAccess(config, client, true, environment);
      if (fail) throw new Error("deployment failed");
      return "verified";
    };
    if (fail)
      await assert.rejects(withRunnerAccess(config, client, callback, environment), /deployment failed/);
    else assert.equal(await withRunnerAccess(config, client, callback, environment), "verified");
    assert.deepEqual(client.properties, before);
    assert.equal(client.requests.filter((request) => request.options).length, 2);
    await updateRunnerAccess(config, client, false, environment);
    assert.equal(client.requests.filter((request) => request.options).length, 2);
  }
});

test("runner access refuses permissive defaults and conflicting preexisting rule names", async () => {
  const client = accessClient();
  client.properties.ipSecurityRestrictionsDefaultAction = "Allow";
  await assert.rejects(updateRunnerAccess(config, client, true, environment), /deny-by-default/);
  client.properties.ipSecurityRestrictionsDefaultAction = "Deny";
  client.properties.ipSecurityRestrictions.push({
    name: "GitHubRollout-1234-1", ipAddress: "0.0.0.0/0", action: "Allow", priority: 101,
  });
  await assert.rejects(updateRunnerAccess(config, client, false, environment), /Conflicting/);
  assert.equal(client.requests.filter((request) => request.options).length, 0);
});

test("portal startup requires the image-baked revision and bounded readiness waits never report success early", async () => {
  const fetcher = async (url, options) => {
    assert.equal(url, `https://${resourceNames.portal}.azurewebsites.net/health`);
    assert.equal(options.redirect, "error");
    return Response.json({ status: "running", codeRevision: revision });
  };
  assert.equal((await checkPortalRevision(config, revision, fetcher)).ready, true);
  assert.equal((await checkPortalRevision(config, "d".repeat(40), fetcher)).ready, false);
  assert.equal((await checkPortalRevision(config, revision, async () => new Response(null, { status: 503 }))).ready, false);
  let checks = 0;
  assert.equal(await waitForRelease(async () => ({
    ready: ++checks === 2, detail: "starting", value: "ready",
  }), "test", { attempts: 2, pause: async () => {} }), "ready");
  await assert.rejects(waitForRelease(async () => ({ ready: false, detail: "wrong image" }),
    "test", { attempts: 2, pause: async () => {} }), /wrong image/);
  await assert.rejects(waitForRelease(async () => { throw new Error("read denied"); },
    "test", { attempts: 2, pause: async () => {} }), /read denied/);
});

test("ACI scan tags are reconciled only for the exact deployed release image", async () => {
  let writes = 0;
  const instance = {
    tags: { "dojo.scanHash": "old", retained: "yes" },
    properties: { containers: [{ properties: {
      image: `${resourceNames.registry}.azurecr.io/${resourceNames.drowsyDragon}@${digest}`,
    } }] },
  };
  const client = {
    request: async (path, options) => {
      if (options) {
        writes++;
        assert.ok(path.includes("/providers/Microsoft.Resources/tags/default"));
        assert.equal(options.method, "PATCH");
        assert.equal(options.body.operation, "Merge");
        Object.assign(instance.tags, options.body.properties.tags);
      }
      return structuredClone(instance);
    },
  };
  await reconcileDragonScanTag(config, release, client);
  assert.equal(writes, 1);
  assert.equal(instance.tags.retained, "yes");
  assert.equal(instance.tags["dojo.scanHash"], scanHash);
  await reconcileDragonScanTag(config, release, client);
  assert.equal(writes, 1);
  instance.properties.containers[0].properties.image = "other-image";
  await assert.rejects(reconcileDragonScanTag(config, release, client), /different.*image/);
  assert.equal(writes, 1);
});

test("rollout verification requires every image and receipt, with connector coverage explicitly separate", () => {
  const report = {
    release: Object.fromEntries(Object.keys(release.images).map((key) => [
      `${key}ObservedImage`,
      `${key === "drowsyDragon" ? "" : "DOCKER|"}${resourceNames.registry}.azurecr.io/${resourceNames[key]}@${digest}`,
    ])),
    drowsyDragon: { state: "observed", scanState: "observed" },
    nginxProxy: { state: "observed", scanState: "observed", runtimeEvidenceState: "observed" },
    checks: [{ id: "GitHub connector / native code coverage", state: "unknown" }],
  };
  assert.equal(validateRolloutReport(config, release, report).ready, true);
  for (const key of Object.keys(release.images)) {
    const invalid = structuredClone(report);
    invalid.release[`${key}ObservedImage`] = "older-image";
    assert.equal(validateRolloutReport(config, release, invalid).ready, false);
  }
  for (const key of ["drowsyDragon", "nginxProxy"]) {
    const invalid = structuredClone(report);
    invalid[key].scanState = "pending";
    assert.equal(validateRolloutReport(config, release, invalid).ready, false);
  }
  const invalid = structuredClone(report);
  invalid.checks.push({ id: "Private evidence", state: "unknown", detail: "denied" });
  assert.equal(validateRolloutReport(config, release, invalid).ready, false);
});
