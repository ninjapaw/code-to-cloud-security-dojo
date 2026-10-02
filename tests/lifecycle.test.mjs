import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDeploymentStatus,
  renderDeploymentStatus,
} from "../scripts/lib/deployment-status.mjs";
import {
  ensureBootstrapSecrets,
  stampBootstrapSecrets,
  startBootstrapHealth,
} from "../scripts/secret-bootstrap.mjs";
import {
  configHash,
  foundationParameters,
  releaseParameters,
  readHostedDojoHealth,
  readHostedEvidenceHealth,
  requireConfirmation,
  validateRelease,
  verifiedPrivateSecrets,
} from "../scripts/lib/lifecycle.mjs";
import { confirmation } from "../shared/config.mjs";
import { isLabHostname, names } from "../shared/config.mjs";
import { ownedReaderAssignments } from "../scripts/lib/lifecycle.mjs";
const config = JSON.parse(
  await readFile(new URL("../config/deploy.config.json", import.meta.url)),
);
function releaseFor(selected) {
  return {
    schemaVersion: 1,
    codeRevision: "0".repeat(40),
    configHash: configHash(selected),
    source: {
      ...selected.source,
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
}
test("hosted private HTTP health requires exact portal JSON", async () => {
  const url = `https://${names(config).portal}.azurewebsites.net/health/dojo`;
  const fetcher = async (target, options) => {
    assert.equal(target, url);
    assert.equal(options.redirect, "manual");
    return Response.json({ status: "healthy" });
  };
  assert.equal((await readHostedDojoHealth(config, fetcher)).state, "observed");
  assert.equal(
    (
      await readHostedDojoHealth(
        config,
        async () => new Response(null, { status: 503 }),
      )
    ).state,
    "gap",
  );
  assert.equal(
    (
      await readHostedDojoHealth(config, async () =>
        Response.redirect(url, 302),
      )
    ).state,
    "unknown",
  );
  assert.equal(
    (
      await readHostedDojoHealth(
        config,
        async () => new Response("<html>fallback</html>"),
      )
    ).state,
    "unknown",
  );
});
test("hosted private Blob health reveals only reachability", async () => {
  const url = `https://${names(config).portal}.azurewebsites.net/health/evidence`;
  assert.equal(
    (
      await readHostedEvidenceHealth(config, async (target) => {
        assert.equal(target, url);
        return Response.json({ status: "accessible" });
      })
    ).state,
    "observed",
  );
  assert.equal(
    (
      await readHostedEvidenceHealth(
        config,
        async () => new Response(null, { status: 503 }),
      )
    ).state,
    "gap",
  );
  assert.equal(
    (
      await readHostedEvidenceHealth(
        config,
        async () => new Response("<html>fallback</html>"),
      )
    ).state,
    "unknown",
  );
});
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
    let status = JSON.parse(
      await readFile(join(output, "deployment-status.json"), "utf8"),
    );
    assert.equal(
      status.stages.find((stage) => stage.id === "provision").state,
      "in_progress",
    );
    let html = await readFile(join(output, "deployment-status.html"), "utf8");
    assert.match(html, /http-equiv="refresh"/);
    assert.match(html, /Waiting for private vault &lt;access&gt;/);
    assert.doesNotMatch(html, /private vault <access>/);
    await first.observe("build", "Image history seen; scan not verified");
    status = JSON.parse(
      await readFile(join(output, "deployment-status.json"), "utf8"),
    );
    assert.equal(
      status.stages.find((stage) => stage.id === "build").state,
      "observed",
    );
    assert.match(renderDeploymentStatus(status), /scan not verified/);
    const retry = await createDeploymentStatus(scope, output, "provision");
    await retry.finish(true);
    await retry.observe("provision", "Do not replace a failed run");
    status = JSON.parse(
      await readFile(join(output, "deployment-status.json"), "utf8"),
    );
    assert.equal(
      status.stages.find((stage) => stage.id === "provision").state,
      "failed",
    );
    html = renderDeploymentStatus(status);
    assert.doesNotMatch(html, /http-equiv="refresh"/);
    assert.match(html, /lab&lt;test&gt;/);
    const success = await createDeploymentStatus(scope, output, "provision");
    await success.finish();
    await success.observe("provision", "Do not replace a completed run");
    status = JSON.parse(
      await readFile(join(output, "deployment-status.json"), "utf8"),
    );
    assert.equal(
      status.stages.find((stage) => stage.id === "provision").state,
      "succeeded",
    );
    assert.equal(
      status.stages.find((stage) => stage.id === "deploy").state,
      "pending",
    );
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
test("private credential bootstrap is idempotent and refuses implicit rotation", async () => {
  const values = new Map();
  const secrets = {
    async getSecret(name) {
      if (!values.has(name))
        throw Object.assign(new Error("Missing"), { statusCode: 404 });
      return values.get(name);
    },
    async setSecret(name, value, options) {
      assert.equal(value.length >= 43, true);
      assert.equal(options.tags.purpose, name);
      values.set(name, {
        value,
        properties: { enabled: true, expiresOn: options.expiresOn },
      });
    },
  };
  await ensureBootstrapSecrets(secrets);
  assert.deepEqual([...values.keys()], ["admin-password", "session-key"]);
  const original = values.get("admin-password").value;
  await ensureBootstrapSecrets(secrets);
  assert.equal(values.get("admin-password").value, original);
  values.get("admin-password").properties.enabled = false;
  await assert.rejects(ensureBootstrapSecrets(secrets), /explicit rotation/);
  assert.equal(values.get("admin-password").value, original);
});
test("private readback stamps both existing secrets without rotating values", async () => {
  const values = new Map(
    ["admin-password", "session-key"].map((name) => [
      name,
      {
        value: `existing-${name}`,
        properties: {
          version: "existing-version",
          tags: { managedBy: "code-to-cloud-security-dojo", purpose: name },
        },
      },
    ]),
  );
  const secrets = {
    async getSecret(name) {
      return values.get(name);
    },
    async updateSecretProperties(name, version, options) {
      assert.equal(version, "existing-version");
      values.get(name).properties.tags = options.tags;
    },
  };
  await stampBootstrapSecrets(secrets, "run-123");
  for (const [name, secret] of values) {
    assert.equal(secret.value, `existing-${name}`);
    assert.equal(secret.properties.tags.bootstrapRunId, "run-123");
    assert.equal(secret.properties.tags.purpose, name);
  }
});
test("ARM proof requires fresh enabled metadata for both exact secrets", async () => {
  const vaultPath =
    "/subscriptions/test/resourceGroups/training/providers/Microsoft.KeyVault/vaults/training-vault";
  const metadata = new Map(
    ["admin-password", "session-key"].map((name) => [
      name,
      {
        id: `${vaultPath}/secrets/${name}`,
        tags: {
          managedBy: "code-to-cloud-security-dojo",
          purpose: name,
          bootstrapRunId: "run-123",
        },
        properties: {
          attributes: {
            enabled: true,
            exp: Math.floor(Date.now() / 1000) + 86400,
          },
        },
      },
    ]),
  );
  const client = {
    scope: "/subscriptions/test",
    async request(path) {
      return metadata.get(path.split("/secrets/")[1].split("?")[0]);
    },
  };
  const scope = { resourceGroup: "training" };
  assert.equal(
    await verifiedPrivateSecrets(client, scope, "training-vault", "run-123"),
    true,
  );
  metadata.get("session-key").tags.bootstrapRunId = "another-run";
  assert.equal(
    await verifiedPrivateSecrets(client, scope, "training-vault", "run-123"),
    false,
  );
  metadata.get("session-key").tags.bootstrapRunId = "run-123";
  metadata.get("session-key").properties.attributes.exp = 0;
  assert.equal(
    await verifiedPrivateSecrets(client, scope, "training-vault", "run-123"),
    false,
  );
  metadata.get("session-key").properties.attributes.exp =
    Math.floor(Date.now() / 1000) + 86400;
  metadata.get("session-key").id = `${vaultPath}/secrets/wrong`;
  assert.equal(
    await verifiedPrivateSecrets(client, scope, "training-vault", "run-123"),
    false,
  );
});
test("private bootstrap health listener answers App Service warmup", async () => {
  const server = startBootstrapHealth(0, "127.0.0.1");
  try {
    await new Promise((resolve) => server.once("listening", resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/`);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "ready");
  } finally {
    server.close();
  }
});
test("temporary credential worker is private, VNet-integrated and vault-scoped", async () => {
  const worker = await readFile(
    new URL("../infra/secret-bootstrap.bicep", import.meta.url),
    "utf8",
  );
  const lifecycle = await readFile(
    new URL("../scripts/bootstrap-secrets.mjs", import.meta.url),
    "utf8",
  );
  assert.match(worker, /publicNetworkAccess: 'Disabled'/);
  assert.match(
    worker,
    /resource plan 'Microsoft\.Web\/serverfarms@2024-11-01' existing/,
  );
  assert.match(
    worker,
    /resource restoredPlan 'Microsoft\.Web\/serverfarms@2024-11-01' = if \(restorePlan\) \{[\s\S]*?name: '\$\{portalName\}-plan'[\s\S]*?sku: \{ name: appServiceSku, capacity: 1 \}/,
  );
  assert.match(worker, /dependsOn: \[pull, writeSecrets, restoredPlan\]/);
  assert.match(worker, /virtualNetworkSubnetId: subnet\.id/);
  assert.match(
    worker,
    /virtualNetworkSubnetId: subnet\.id\s+outboundVnetRouting: \{ applicationTraffic: true \}\s+siteConfig: \{/,
  );
  assert.doesNotMatch(worker, /vnetRouteAllEnabled/);
  assert.match(worker, /alwaysOn: true/);
  assert.match(worker, /name: 'WEBSITES_PORT', value: '8080'/);
  assert.match(
    worker,
    /applicationLogs: \{ fileSystem: \{ level: 'Information' \} \}/,
  );
  assert.match(worker, /logAnalyticsDestinationType: 'Dedicated'/);
  assert.match(
    worker,
    /guid\(vault\.id, identity\.id, 'KeyVaultSecretsOfficer'\)[\s\S]*?scope: vault[\s\S]*?b86a8fe4-44ce-4948-aee5-eccb2c155cd7/,
  );
  assert.match(
    worker,
    /guid\(registry\.id, identity\.id, 'AcrPull'\)[\s\S]*?scope: registry[\s\S]*?7f951dda-4ed3-4680-a7ca-43fe172d538d/,
  );
  assert.match(worker, /scmIpSecurityRestrictionsDefaultAction: 'Deny'/);
  assert.doesNotMatch(worker, /(?:adminIpv4Address|clientSecret|password):/);
  assert.match(lifecycle, /"webapp",\s*"delete"[\s\S]*?"--keep-empty-plan"/);
});
test("network settings reach only their intended deployment templates", () => {
  for (const keyVaultPublicAccess of [false, true]) {
    for (const keyVaultRestrictToAdminIp of [false, true]) {
      for (const dojoPublicAccess of [false, true]) {
        for (const dojoRestrictToAdminIp of [false, true]) {
          const selected = {
            ...config,
            adminCidr: "203.0.113.10/32",
            keyVaultPublicAccess,
            keyVaultRestrictToAdminIp,
            keyVaultPublicAccessTags: keyVaultPublicAccess
              ? { NetworkException: "ApprovedForTraining" }
              : {},
            dojoPublicAccess,
            dojoRestrictToAdminIp,
          };
          const foundation = foundationParameters(selected);
          const release = releaseParameters(selected, releaseFor(selected));
          assert.equal(foundation.keyVaultPublicAccess, keyVaultPublicAccess);
          assert.equal(foundation.keyVaultRestrictToAdminIp, keyVaultRestrictToAdminIp);
          assert.deepEqual(foundation.keyVaultPublicAccessTags, selected.keyVaultPublicAccessTags);
          assert.equal(foundation.adminIpv4Address, "203.0.113.10");
          assert.equal(release.dojoPublicAccess, dojoPublicAccess);
          assert.equal(release.dojoRestrictToAdminIp, dojoRestrictToAdminIp);
          for (const key of ["dojoPublicAccess", "dojoRestrictToAdminIp"])
            assert.equal(Object.hasOwn(foundation, key), false);
          for (const key of [
            "keyVaultPublicAccess",
            "keyVaultRestrictToAdminIp",
            "keyVaultPublicAccessTags",
          ])
            assert.equal(Object.hasOwn(release, key), false);
        }
      }
    }
  }
});
test("vault network choices preserve RBAC and resource-only policy tags", async () => {
  const foundation = await readFile(
    new URL("../infra/foundation.bicep", import.meta.url),
    "utf8",
  );
  const vault = foundation.match(
    /resource vault 'Microsoft\.KeyVault\/vaults@[^']+' = \{[\s\S]*?\n\}/,
  )?.[0];
  assert.ok(vault, "the training vault must be declared");
  assert.match(foundation, /param keyVaultPublicAccess bool = true/);
  assert.match(foundation, /param keyVaultRestrictToAdminIp bool = false/);
  assert.match(
    foundation,
    /param keyVaultPublicAccessTags object = \{ SecurityControl: 'Ignore' \}/,
  );
  assert.match(
    vault,
    /tags: union\(keyVaultPublicAccess \? keyVaultPublicAccessTags : \{\}, tags\)/,
  );
  assert.match(
    vault,
    /publicNetworkAccess: keyVaultPublicAccess \? 'Enabled' : 'Disabled'/,
  );
  assert.match(
    vault,
    /defaultAction: keyVaultPublicAccess && !keyVaultRestrictToAdminIp \? 'Allow' : 'Deny'/,
  );
  assert.match(vault, /bypass: 'None'/);
  assert.match(
    vault,
    /ipRules: keyVaultPublicAccess && keyVaultRestrictToAdminIp \? \[\{ value: '\$\{adminIpv4Address\}\/32' \}\] : \[\]/,
  );
  assert.match(vault, /enableRbacAuthorization: true/);
  assert.match(vault, /enableSoftDelete: true/);
  assert.match(vault, /enablePurgeProtection: true/);

  const otherResources = foundation
    .slice(foundation.indexOf("resource registry"))
    .replace(vault, "");
  assert.doesNotMatch(otherResources, /SecurityControl|keyVaultPublicAccessTags/);
  assert.match(
    otherResources,
    /module vaultEndpoint[\s\S]*?targetId: vault\.id, groupId: 'vault'/,
  );
  assert.match(
    otherResources,
    /resource storage[\s\S]*?networkAcls: \{ defaultAction: 'Deny'/,
  );
  assert.match(otherResources, /allowBlobPublicAccess: false/);
  assert.match(otherResources, /allowSharedKeyAccess: false/);
});
test("configurable WebGoat ingress preserves portal, optional workload and publishing restrictions", async () => {
  const main = await readFile(
    new URL("../infra/main.bicep", import.meta.url),
    "utf8",
  );
  const app = await readFile(
    new URL("../infra/modules/app.bicep", import.meta.url),
    "utf8",
  );
  const dojo = main.match(
    /module dojo 'modules\/app\.bicep' = \{[\s\S]*?\n\}/,
  )?.[0];
  const portal = main.match(
    /module portal 'modules\/app\.bicep' = \{[\s\S]*?\n\}/,
  )?.[0];
  const nginxProxy = main.match(
    /module nginxProxy 'modules\/app\.bicep' = if \(nginxProxyEnabled\) \{[\s\S]*?\n\}/,
  )?.[0];
  assert.ok(dojo);
  assert.ok(portal);
  assert.ok(nginxProxy);
  assert.match(main, /param dojoPublicAccess bool = true/);
  assert.match(main, /param dojoRestrictToAdminIp bool = false/);
  assert.match(dojo, /publicAccess: dojoPublicAccess/);
  assert.match(dojo, /restrictToAdminIp: dojoRestrictToAdminIp/);
  assert.match(dojo, /healthCheckPath: '\/WebGoat\/actuator\/health'/);
  assert.match(
    main,
    /output dojoUrl string = 'https:\/\/\$\{dojo\.outputs\.hostName\}\/WebGoat\/'/,
  );
  assert.match(portal, /publicAccess: true/);
  assert.match(portal, /restrictToAdminIp: true/);
  assert.match(nginxProxy, /publicAccess: false/);
  assert.match(app, /param restrictToAdminIp bool = true/);
  assert.match(
    app,
    /publicNetworkAccess: publicAccess \? 'Enabled' : 'Disabled'/,
  );
  assert.match(
    app,
    /ipSecurityRestrictionsDefaultAction: publicAccess && !restrictToAdminIp \? 'Allow' : 'Deny'/,
  );
  assert.match(
    app,
    /ipSecurityRestrictions: publicAccess && restrictToAdminIp \? \[\{ name: 'AuthorizedAdmin', ipAddress: '\$\{adminIpv4Address\}\/32', action: 'Allow', priority: 100 \}\] : \[\]/,
  );
  assert.match(app, /scmIpSecurityRestrictionsDefaultAction: 'Deny'/);
  assert.match(app, /scmIpSecurityRestrictionsUseMain: false/);
  assert.match(app, /scmIpSecurityRestrictions: \[\]/);
  assert.match(app, /httpsOnly: true/);
  assert.match(app, /ftpsState: 'Disabled'/);
  assert.match(app, /name: 'ftp'[\s\S]*?properties: \{ allow: false \}/);
  assert.match(app, /name: 'scm'[\s\S]*?properties: \{ allow: false \}/);
});
test("App Service workloads retain their Internet-denied outbound subnet", async () => {
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
  assert.match(
    app,
    /virtualNetworkSubnetId: empty\(subnetId\) \? null : subnetId\s+outboundVnetRouting: \{ applicationTraffic: !empty\(subnetId\) \}/,
  );
  assert.doesNotMatch(app, /vnetRouteAllEnabled/);
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
  const release = releaseFor(config);
  validateRelease(config, release);
  assert.throws(
    () => releaseParameters({ ...config, dojoPublicAccess: false }, release),
    /different configuration/,
  );
  assert.throws(
    () => releaseParameters({ ...config, keyVaultPublicAccessTags: {} }, release),
    /different configuration/,
  );
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
