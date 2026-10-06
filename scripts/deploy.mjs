import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { createHash } from "node:crypto";
import { AzureCliCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";
import { ensureManagedSecrets } from "../shared/credentials.mjs";
import {
  loadConfig,
  root,
  names,
  assertContext,
  assertOwned,
  accessSettings,
} from "../shared/config.mjs";
import { AzureClient } from "../shared/azure.mjs";
import { reconcileProtection } from "../shared/protection.mjs";
import { collectReport, reportHtml } from "../shared/report.mjs";
import { BlobEvidenceStore } from "../shared/evidence-store.mjs";
import { drowsyDragon } from "../shared/drowsy-dragon.mjs";
import { nginxProxy, nginxMode } from "../shared/nginx-proxy.mjs";
import { publishImageReceipt } from "../shared/receipt-publishing.mjs";
import { withPortalSession } from "./lib/portal-client.mjs";
import { buildNginxProxy, readNginxReceipt } from "./lib/nginx-proxy.mjs";
import { buildDrowsyDragon, readDragonReceipt } from "./lib/drowsy-dragon.mjs";
import { createDeploymentStatus } from "./lib/deployment-status.mjs";
import {
  synchronizeSource,
  verifySource,
  prepareDojoImage,
} from "./lib/dojo-source.mjs";
import {
  az,
  run,
  foundationParameters,
  configHash,
  requireConfirmation,
  validateRelease,
  ownedReaderAssignments,
  releaseParameters,
  requireReleaseCostApproval,
  verifiedPrivateSecrets,
  readHostedDojoHealth,
  readHostedEvidenceHealth,
} from "./lib/lifecycle.mjs";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    confirm: { type: "string" },
    "accept-costs": { type: "boolean" },
    "evidence-exported": { type: "boolean" },
    release: { type: "string" },
    audit: { type: "boolean" },
    "via-portal": { type: "boolean" },
  },
});
const action = positionals[0] || "plan";
const allowed = [
  "plan",
  "source-sync",
  "source-check",
  "source-upstream",
  "doctor",
  "provision",
  "protection",
  "build",
  "what-if",
  "deploy",
  "repair",
  "verify",
  "report",
  "rotate",
  "inventory",
  "deprovision",
];
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
let deploymentStatus;
const updateStatus = async (detail) => {
  if (!deploymentStatus) return;
  await deploymentStatus.update(detail);
  console.log(`Deployment status: ${detail}`);
};

async function main() {
  if (!allowed.includes(action) || positionals.length > 1)
    throw new Error(`Action must be one of: ${allowed.join(", ")}`);
  if (values["via-portal"] && !["deploy", "repair", "verify", "report", "what-if"].includes(action))
    throw new Error("--via-portal is supported only for deployment and evidence collection");
  const config = await loadConfig({
    offline: action === "plan" || action.startsWith("source-") || values.audit,
  });
  const resourceNames = names(config);
  const access = accessSettings(config);
  const dojoAccess = !access.dojoPublicAccess
    ? "private network only"
    : access.dojoRestrictToAdminIp
      ? "admin IP only"
      : "public internet";
  const output = fileURLToPath(
    new URL(`../output/${config.labId}/`, import.meta.url),
  );
  if (action === "plan" || values.audit) {
    console.log(
      JSON.stringify(
        {
          action,
          audit: true,
          config,
          names: resourceNames,
          access,
          drowsyDragon: {
            ...drowsyDragon,
            enabled: config.drowsyDragonEnabled === true,
            runtime:
              "Azure Container Instances; no public ingress or HTTP tests",
          },
          nginxProxy: {
            ...nginxProxy,
            ...nginxMode(config.nginxProxyMode),
            enabled: config.nginxProxyEnabled === true,
            runtime:
              "Separate private App Service; NGINX proxies only its own training dashboard",
          },
          stages: allowed,
          warning:
            `No Azure calls or writes. WebGoat website access: ${dojoAccess}; it is deliberately vulnerable, so use only disposable training accounts and data. The admin portal remains IP-restricted. Two default app plans, optional NGINX Proxy plan/private endpoint, storage, logs, Key Vault, optional Drowsy Dragon ACI and subscription-wide Defender charges require approval. GitHub tenant consent is interactive; not auto-granted.`,
        },
        null,
        2,
      ),
    );
    return;
  }
  const sourceHome = fileURLToPath(new URL("apps/dojo/", root));
  if (action === "source-sync") {
    console.log(
      JSON.stringify(
        await synchronizeSource(sourceHome, config.source),
        null,
        2,
      ),
    );
    return;
  }
  if (action === "source-check") {
    console.log(
      JSON.stringify(await verifySource(sourceHome, config.source), null, 2),
    );
    return;
  }
  if (action === "source-upstream") {
    console.log(
      `Current approved pin: ${config.source.revision}\nUpstream refs (no local changes):`,
    );
    console.log(
      run("git", [
        "ls-remote",
        config.source.repository,
        "HEAD",
        "refs/tags/*",
      ]),
    );
    return;
  }
  deploymentStatus = await createDeploymentStatus(config, output, action);
  console.log(`Live deployment report: ${deploymentStatus.url}`);
  await updateStatus("Verifying Azure context and lab ownership");
  const account = az(config, ["account", "show"], { json: true });
  assertContext(config, account);
  console.log(
    `Context verified: ${account.name} / ${config.subscriptionId} / tenant ${config.tenantId}`,
  );
  const client = new AzureClient(config);
  const groupPath = `${client.scope}/resourceGroups/${config.resourceGroup}`;
  let group;
  try {
    group = await client.request(`${groupPath}?api-version=2021-04-01`);
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  if (group) assertOwned(config, group);

  if (action === "doctor") {
    await updateStatus(
      "Checking tools, providers and current Defender coverage",
    );
    for (const command of ["git", "docker", "trivy"])
      run(command, ["--version"]);
    const providers = az(config, ["provider", "list"], { json: true });
    if (group) {
      try {
        const foundation = await client.request(
          `${groupPath}/providers/Microsoft.Resources/deployments/dojo-foundation?api-version=2022-09-01`,
        );
        if (foundation.properties.provisioningState === "Succeeded")
          await deploymentStatus.observe(
            "provision",
            "Foundation ARM deployment observed; Key Vault credentials not verified",
          );
      } catch (error) {
        if (error.status !== 404) throw error;
      }
    }
    const protection = await reconcileProtection(client, config.protection);
    if (protection.length && protection.every((item) => item.state === "found"))
      await deploymentStatus.observe(
        "protection",
        "Configured Defender plans observed at their approved settings",
      );
    const required = [
      "Microsoft.Web",
      "Microsoft.Network",
      "Microsoft.ContainerRegistry",
      "Microsoft.KeyVault",
      "Microsoft.Storage",
      "Microsoft.OperationalInsights",
      "Microsoft.Insights",
      "Microsoft.ManagedIdentity",
      "Microsoft.Security",
      ...(config.drowsyDragonEnabled ? ["Microsoft.ContainerInstance"] : []),
    ];
    console.log(
      JSON.stringify(
        {
          group: group ? "owned" : "not provisioned",
          providers: providers
            .filter((provider) => required.includes(provider.namespace))
            .map((provider) => ({
              namespace: provider.namespace,
              state: provider.registrationState,
            })),
          protection,
          requiredRoles: [
            "Infrastructure identity: group Contributor, conditioned RBAC, AcrPush, Key Vault Secrets Officer and Blob Data Contributor",
            "Infrastructure identity: subscription Defender pricing read",
            "Protection identity: subscription Defender pricing read/write",
            "Portal identity: subscription Security Reader and scoped group/data roles",
          ],
          note: "Role availability, region/SKU capacity and policy must still pass what-if and live validation.",
        },
        null,
        2,
      ),
    );
    return;
  }
  if (action === "protection") {
    requireConfirmation(config, action, values.confirm);
    if (!values["accept-costs"])
      throw new Error(
        "Paid subscription-wide Defender changes require --accept-costs",
      );
    await updateStatus(
      "Comparing approved Defender plans with subscription readback",
    );
    await mkdir(output, { recursive: true });
    const before = await reconcileProtection(client, config.protection);
    await writeFile(
      join(output, `protection-before-${Date.now()}.json`),
      JSON.stringify(before, null, 2),
    );
    await updateStatus(
      "Reconciling approved Defender plans and verifying readback",
    );
    console.log(
      JSON.stringify(
        await reconcileProtection(client, config.protection, { apply: true }),
        null,
        2,
      ),
    );
    return;
  }
  const deployTemplate = async (template, parameters, operation = "create") => {
    await mkdir(output, { recursive: true });
    const path = join(output, `${template}.parameters.json`);
    await writeFile(
      path,
      JSON.stringify({
        $schema:
          "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        contentVersion: "1.0.0.0",
        parameters: Object.fromEntries(
          Object.entries(parameters).map(([key, value]) => [key, { value }]),
        ),
      }),
    );
    await updateStatus(
      `${operation === "what-if" ? "Previewing" : "Applying"} ${template} Bicep in ${config.resourceGroup}`,
    );
    return az(
      config,
      [
        "deployment",
        "group",
        operation,
        "--name",
        `dojo-${template}`,
        "--resource-group",
        config.resourceGroup,
        "--template-file",
        `infra/${template}.bicep`,
        "--parameters",
        `@${path}`,
        ...(operation === "what-if" ? ["--no-pretty-print"] : []),
        ...(operation === "create" ? ["--mode", "Incremental"] : []),
      ],
      { json: true },
    );
  };
  if (action === "provision") {
    requireConfirmation(config, action, values.confirm);
    if (!values["accept-costs"])
      throw new Error("Provisioning requires --accept-costs");
    await updateStatus(
      "Checking provider registration and foundation prerequisites",
    );
    for (const namespace of [
      "Microsoft.Web",
      "Microsoft.Network",
      "Microsoft.ContainerRegistry",
      "Microsoft.KeyVault",
      "Microsoft.Storage",
      "Microsoft.OperationalInsights",
      "Microsoft.Insights",
      "Microsoft.ManagedIdentity",
      "Microsoft.Security",
      ...(config.drowsyDragonEnabled ? ["Microsoft.ContainerInstance"] : []),
    ]) {
      const state = az(config, ["provider", "show", "--namespace", namespace], {
        json: true,
      }).registrationState;
      if (state !== "Registered")
        throw new Error(
          `Provider ${namespace} is not registered; run npm run setup:github-oidc with --apply`,
        );
    }
    if (!group) {
      group = await client.request(`${groupPath}?api-version=2021-04-01`, {
        method: "PUT",
        body: {
          location: config.location,
          tags: {
            "dojo.labId": config.labId,
            "dojo.managedBy": "code-to-cloud-security-dojo",
          },
        },
      });
      assertOwned(config, group);
    }
    const parameters = foundationParameters(config);
    console.log(
      JSON.stringify(
        await deployTemplate("foundation", parameters, "what-if"),
        null,
        2,
      ),
    );
    await deployTemplate("foundation", parameters);
    await updateStatus(
      "Creating or verifying admin username, password and session key in Key Vault",
    );
    await ensureSecrets(client, resourceNames.vault, false);
    console.log(
      "Foundation provisioned. Subscription Defender activation is a separate protection action. Build, review scans, then deploy.",
    );
    return;
  }
  if (!group && action === "deprovision") {
    console.log(
      "Resource group already absent; retained subscription controls are unchanged.",
    );
    return;
  }
  if (!group)
    throw new Error(
      "Run provision first; the configured resource group does not exist",
    );
  if (action === "rotate") {
    requireConfirmation(config, action, values.confirm);
    await updateStatus(
      "Rotating Key Vault credentials and refreshing references",
    );
    await ensureSecrets(client, resourceNames.vault, true);
    await client.request(
      `${groupPath}/providers/Microsoft.Web/sites/${resourceNames.portal}/config/configreferences/appsettings/refresh?api-version=2024-11-01`,
      { method: "POST" },
    );
    az(config, [
      "webapp",
      "restart",
      "--resource-group",
      config.resourceGroup,
      "--name",
      resourceNames.portal,
    ]);
    console.log(
      "New Key Vault versions created; references refreshed and portal restart requested. Existing sessions become invalid after refresh. Verify before distributing access.",
    );
    return;
  }
  if (action === "build") {
    requireConfirmation(config, action, values.confirm);
    if (run("git", ["status", "--porcelain"]))
      throw new Error(
        "Commit reviewed lab changes before a release build. This tool never creates commits.",
      );
    run("docker", ["version"]);
    run("trivy", ["--version"]);
    await updateStatus(
      "Verifying pinned source and preparing the image recipe",
    );
    await mkdir(output, { recursive: true });
    const prepared = await prepareDojoImage(sourceHome, config.source, output);
    const { contextPath, dockerfile: recipe } = prepared;
    const tag = `training-${Date.now()}`;
    const release = {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      codeRevision: run("git", ["rev-parse", "HEAD"]),
      configHash: configHash(config),
      source: {
        ...config.source,
        tree: prepared.manifest.tree,
        snapshotSha256: prepared.manifest.sha256,
        files: prepared.manifest.files,
      },
      images: {},
    };
    for (const [key, repository, context, dockerfile] of [
      ["dojo", "dojo", contextPath, recipe],
      [
        "portal",
        "control-portal",
        fileURLToPath(root),
        "apps/control-portal/Dockerfile",
      ],
    ]) {
      const image = `${resourceNames.registry}.azurecr.io/${repository}:${tag}`;
      await updateStatus(`Building ${key} image for linux/amd64`);
      run(
        "docker",
        [
          "build",
          "--platform",
          "linux/amd64",
          "--label",
          `org.opencontainers.image.source=${key === "dojo" ? config.source.repository.replace(/\.git$/, "") : "https://github.com/ninjapaw/code-to-cloud-security-dojo"}`,
          "--label",
          `org.opencontainers.image.revision=${key === "dojo" ? config.source.revision : run("git", ["rev-parse", "HEAD"])}`,
          "-f",
          dockerfile,
          "-t",
          image,
          context,
        ],
        { inherit: true },
      );
      const scanPath = join(output, `${key}-${tag}.sarif`);
      await updateStatus(`Scanning ${key} image and retaining SARIF evidence`);
      run(
        "trivy",
        [
          "image",
          "--format",
          "sarif",
          "--output",
          scanPath,
          "--severity",
          "HIGH,CRITICAL",
          "--exit-code",
          key === "portal" ? "1" : "0",
          image,
        ],
        { inherit: true },
      );
      release.images[key] = {
        repository,
        image,
        imageId: run("docker", [
          "image",
          "inspect",
          image,
          "--format",
          "{{.Id}}",
        ]),
        scanPath: relative(fileURLToPath(root), scanPath),
        scanHash: sha(await readFile(scanPath)),
      };
    }
    if (config.drowsyDragonEnabled) {
      release.images.drowsyDragon = await buildDrowsyDragon(
        `${resourceNames.registry}.azurecr.io/drowsy-dragon:${tag}`,
        join(output, `drowsy-dragon-${tag}`),
      );
    }
    if (config.nginxProxyEnabled) {
      release.images.nginxProxy = await buildNginxProxy(
        `${resourceNames.registry}.azurecr.io/nginx-proxy:${tag}`,
        join(output, `nginx-proxy-${tag}`),
        config.nginxProxyMode,
      );
    }
    for (const entry of Object.values(release.images)) {
      for (const key of Object.keys(entry)) {
        if (key.endsWith("Path") && resolve(entry[key]) === entry[key])
          entry[key] = relative(fileURLToPath(root), entry[key]);
      }
    }
    await verifySource(sourceHome, config.source);
    await updateStatus("Pushing scanned images to ACR by immutable digest");
    az(config, ["acr", "login", "--name", resourceNames.registry]);
    for (const entry of Object.values(release.images)) {
      if (
        run("docker", [
          "image",
          "inspect",
          entry.image,
          "--format",
          "{{.Id}}",
        ]) !== entry.imageId
      )
        throw new Error(
          `${entry.repository} image changed after scanning; rebuild before pushing`,
        );
      run("docker", ["push", entry.image], { inherit: true });
      entry.digest = az(
        config,
        [
          "acr",
          "manifest",
          "show-metadata",
          "--registry",
          resourceNames.registry,
          "--name",
          `${entry.repository}:${tag}`,
          "--query",
          "digest",
        ],
        { json: true },
      );
    }
    validateRelease(config, release);
    await updateStatus("Writing the reviewed release manifest");
    await writeFile(
      join(output, "release.json"),
      JSON.stringify(release, null, 2),
    );
    console.log(
      "Built and scanned. Review SARIF, then run what-if to obtain a state-bound deployment confirmation. No running app was changed.",
    );
    return;
  }
  if (["deploy", "repair", "what-if"].includes(action)) {
    await updateStatus(
      "Verifying release provenance, scan hashes and registry digests",
    );
    const release = validateRelease(
      config,
      JSON.parse(
        await readFile(
          resolve(values.release || join(output, "release.json")),
          "utf8",
        ),
      ),
    );
    if (run("git", ["rev-parse", "HEAD"]) !== release.codeRevision)
      throw new Error(
        "Release was built from a different Git revision; rebuild and review it",
      );
    const imageReceipts = [];
    if (config.drowsyDragonEnabled)
      imageReceipts.push(await readDragonReceipt(release.images.drowsyDragon));
    if (config.nginxProxyEnabled)
      imageReceipts.push(await readNginxReceipt(release.images.nginxProxy));
    for (const entry of Object.values(release.images)) {
      if (sha(await readFile(entry.scanPath)) !== entry.scanHash)
        throw new Error("Scan artifact hash mismatch");
      const manifest = az(
        config,
        [
          "acr",
          "manifest",
          "show-metadata",
          "--registry",
          resourceNames.registry,
          "--name",
          `${entry.repository}@${entry.digest}`,
        ],
        { json: true },
      );
      if (manifest.digest !== entry.digest)
        throw new Error("Registry digest verification failed");
    }
    const parameters = releaseParameters(config, release);
    const whatIf = await deployTemplate("main", parameters, "what-if");
    console.log(JSON.stringify(whatIf, null, 2));
    const deploymentHash = sha(JSON.stringify({ release, whatIf }));
    await writeFile(
      join(output, `what-if-${deploymentHash}.json`),
      JSON.stringify(
        { codeRevision: release.codeRevision, deploymentHash, whatIf },
        null,
        2,
      ),
    );
    console.log(
      `Required confirmation: deploy:${deploymentHash}:${config.subscriptionId}:${config.resourceGroup}`,
    );
    if (action === "what-if") return;
    requireConfirmation(config, `deploy:${deploymentHash}`, values.confirm);
    requireReleaseCostApproval(config, values["accept-costs"]);
    await updateStatus(
      "Checking Defender coverage and private Key Vault credentials",
    );
    const coverage = await reconcileProtection(client, config.protection);
    if (coverage.some((item) => item.state !== "found"))
      throw new Error(
        "Required Defender coverage missing. Review doctor and run separately approved protection action.",
      );
    await verifyPrivateCredentials(client, config, output, resourceNames);
    if (imageReceipts.length) {
      await updateStatus(
        "Recording optional image evidence in private Blob storage",
      );
      if (values["via-portal"]) {
        await withPortalSession(config, client.credential, async (portal) => {
          for (const receipt of imageReceipts) await portal.publish(receipt);
        });
      } else {
        const store = new BlobEvidenceStore(resourceNames.storage, client.credential);
        for (const receipt of imageReceipts) await publishImageReceipt(store, receipt);
      }
    }
    await deployTemplate("main", parameters);
    await writeFile(
      join(output, `release-deployed-${Date.now()}.json`),
      JSON.stringify(release, null, 2),
    );
    console.log(
      `Release applied. Portal: https://${resourceNames.portal}.azurewebsites.net. WebGoat (${dojoAccess}): https://${resourceNames.dojo}.azurewebsites.net/WebGoat/. Use separate disposable lesson accounts, not portal credentials. Run verify and sign in to validate private connectivity. Do not infer runtime health from deployment success.`,
    );
    return;
  }
  if (["verify", "report"].includes(action)) {
    await updateStatus("Collecting scoped Azure and Blob evidence");
    let report;
    let evidenceError;
    if (values["via-portal"]) {
      report = await withPortalSession(config, client.credential, (portal) => portal.report());
    } else {
      const store = new BlobEvidenceStore(resourceNames.storage, client.credential);
      let runs = [];
      try {
        runs = await store.list("runs/");
      } catch (error) {
        evidenceError = error.message;
      }
      report = await collectReport(config, client, runs, store);
    }
    await updateStatus(
      "Checking deployed sites and writing the evidence report",
    );
    if (evidenceError)
      report.checks.push({
        id: "Run evidence",
        state: "unknown",
        detail: evidenceError,
      });
    for (const name of [
      resourceNames.portal,
      resourceNames.dojo,
      ...(config.nginxProxyEnabled ? [resourceNames.nginxProxy] : []),
    ]) {
      try {
        const site = await client.request(
          `${groupPath}/providers/Microsoft.Web/sites/${name}?api-version=2024-11-01`,
        );
        report.checks.push({
          id: name,
          state: site.properties.state === "Running" ? "observed" : "gap",
          detail: `Platform state ${site.properties.state}; HTTP application health still requires portal validation`,
        });
      } catch (error) {
        report.checks.push({
          id: name,
          state: "unknown",
          detail: error.message,
        });
      }
    }
    try {
      report.checks.push({
        id: "Dojo private HTTP",
        ...(await readHostedDojoHealth(config)),
      });
    } catch {
      report.checks.push({
        id: "Dojo private HTTP",
        state: "unknown",
        detail: "Portal-originated private health check unavailable",
      });
    }
    try {
      report.checks.push({
        id: "Evidence storage via portal",
        ...(await readHostedEvidenceHealth(config)),
      });
    } catch {
      report.checks.push({
        id: "Evidence storage via portal",
        state: "unknown",
        detail: "Portal-originated private evidence check unavailable",
      });
    }
    await mkdir(output, { recursive: true });
    const stamp = Date.now();
    await writeFile(
      join(output, `report-${stamp}.json`),
      JSON.stringify(report, null, 2),
    );
    await writeFile(join(output, `report-${stamp}.html`), reportHtml(report));
    console.log(
      `Report written to ${output}. Evidence may contain identifiers; keep exports private.`,
    );
    if (report.checks.some((item) => ["gap", "unknown"].includes(item.state)))
      process.exitCode = 2;
    return;
  }
  if (["inventory", "deprovision"].includes(action)) {
    await updateStatus(
      "Enumerating owned resources and retained subscription controls",
    );
    const resources = await client.list(
      `${groupPath}/resources?api-version=2021-04-01`,
    );
    const inventory = resources.map((item) => item.id).sort();
    const inventoryHash = sha(JSON.stringify(inventory));
    console.log(
      JSON.stringify(
        {
          deleting: inventory,
          inventoryHash,
          retained: [
            "Subscription Defender plans",
            "GitHub connector consent",
            "Soft-deleted purge-protected Key Vault for at least 7 days",
          ],
          scope: groupPath,
        },
        null,
        2,
      ),
    );
    console.log(
      `Required confirmation: deprovision:${inventoryHash}:${config.subscriptionId}:${config.resourceGroup}`,
    );
    if (action === "inventory") return;
    requireConfirmation(config, `deprovision:${inventoryHash}`, values.confirm);
    if (!values["evidence-exported"])
      throw new Error(
        "Export portal reports and Blob evidence first, then pass --evidence-exported",
      );
    await updateStatus("Removing only the approved owned lab resources");
    assertOwned(
      config,
      await client.request(`${groupPath}?api-version=2021-04-01`),
    );
    let identity;
    try {
      identity = await client.request(
        `${groupPath}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${resourceNames.portal}-identity?api-version=2024-11-30`,
      );
    } catch (error) {
      if (error.status !== 404) throw error;
      console.log(
        "Portal identity is absent after partial provisioning; no subscription assignments will be removed. Review retained assignments separately.",
      );
    }
    const assignments = await client.list(
      `${client.scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()`,
    );
    for (const assignment of ownedReaderAssignments(
      config,
      identity?.properties.principalId || "absent-principal",
      assignments,
    )) {
      await client.request(`${assignment.id}?api-version=2022-04-01`, {
        method: "DELETE",
      });
    }
    az(config, ["group", "delete", "--name", config.resourceGroup, "--yes"]);
    console.log(
      "Resource group deletion completed. Verify retained subscription controls, billing and Key Vault retention separately.",
    );
  }
}

async function ensureSecrets(client, vaultName, rotate) {
  const secrets = new SecretClient(
    `https://${vaultName}.vault.azure.net`,
    new AzureCliCredential({ tenantId: client.config.tenantId }),
  );
  await ensureManagedSecrets(secrets, { rotate });
  console.log(
    "Credentials are managed in Key Vault. Retrieve admin-username and admin-password through an authorized Key Vault session; no values were printed or saved locally. Rotate within 90 days.",
  );
}

async function verifyPrivateCredentials(client, config, output, resourceNames) {
  let proof;
  try {
    proof = JSON.parse(
      await readFile(join(output, "private-bootstrap-proof.json"), "utf8"),
    );
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await ensureSecrets(client, resourceNames.vault, false);
    return;
  }
  if (
    proof.codeRevision !== run("git", ["rev-parse", "HEAD"]) ||
    proof.configHash !== configHash(config) ||
    !/^[a-f0-9-]{36}$/.test(proof.runId || "") ||
    !Number.isFinite(Date.parse(proof.observedAt)) ||
    Date.now() - Date.parse(proof.observedAt) > 60 * 60 * 1000 ||
    Date.parse(proof.observedAt) > Date.now()
  )
    throw new Error(
      "Private vault bootstrap proof is stale or does not match this release",
    );
  const groupPath = `${client.scope}/resourceGroups/${config.resourceGroup}`;
  const workerPath = `${groupPath}/providers/Microsoft.Web/sites/${resourceNames.portal}-bootstrap`;
  const identityPath = `${groupPath}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${resourceNames.portal}-bootstrap-identity`;
  for (const [path, version] of [
    [workerPath, "2024-11-01"],
    [identityPath, "2024-11-30"],
  ]) {
    try {
      await client.request(`${path}?api-version=${version}`);
      throw new Error(
        "Privileged bootstrap resources must be removed before release",
      );
    } catch (error) {
      if (error.status !== 404) throw error;
    }
  }
  if (
    !(await verifiedPrivateSecrets(
      client,
      config,
      resourceNames.vault,
      proof.runId,
    ))
  )
    throw new Error(
      "Private vault credential proof no longer matches all required secret versions",
    );
  console.log("Private vault credentials verified by temporary VNet worker");
}

main()
  .then(async () => {
    if (!deploymentStatus) return;
    await deploymentStatus.finish(Boolean(process.exitCode));
    console.log(
      `Deployment status: ${action} ${process.exitCode ? "failed" : "completed"}`,
    );
  })
  .catch(async (error) => {
    console.error(error.message);
    process.exitCode = 1;
    if (deploymentStatus) {
      try {
        await deploymentStatus.finish(true);
        console.log(`Deployment status: ${action} failed`);
      } catch (statusError) {
        console.error(
          `Could not update deployment status: ${statusError.message}`,
        );
      }
    }
  });
