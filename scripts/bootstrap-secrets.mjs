import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  loadConfig,
  root,
  names,
  assertContext,
  assertOwned,
} from "../shared/config.mjs";
import { AzureClient } from "../shared/azure.mjs";
import { az, run, configHash, requireConfirmation } from "./lib/lifecycle.mjs";
import { createDeploymentStatus } from "./lib/deployment-status.mjs";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: { confirm: { type: "string" }, audit: { type: "boolean" } },
});
const action = positionals[0];
if (!["prepare", "apply"].includes(action) || positionals.length !== 1)
  throw new Error(
    "Use prepare or apply with an explicit state-bound confirmation",
  );
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const config = await loadConfig({ offline: values.audit });
const resourceNames = names(config);
if (values.audit) {
  console.log(JSON.stringify({
    action, audit: true,
    scope: { subscriptionId: config.subscriptionId, resourceGroup: config.resourceGroup, location: config.location },
    worker: `${resourceNames.portal}-bootstrap`,
    note: "No image push, Azure request, Key Vault write or file output performed",
  }, null, 2));
  process.exit(0);
}
if (action === "prepare") {
  requireConfirmation(config, "bootstrap-build", values.confirm);
  if (run("git", ["status", "--porcelain"]))
    throw new Error("Commit reviewed bootstrap changes before building or pushing the worker image");
}
const output = fileURLToPath(
  new URL(`../output/${config.labId}/`, import.meta.url),
);
const groupPath = `/subscriptions/${config.subscriptionId}/resourceGroups/${config.resourceGroup}`;
const workerName = `${resourceNames.portal}-bootstrap`;
const workerPath = `${groupPath}/providers/Microsoft.Web/sites/${workerName}`;
const identityPath = `${groupPath}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${workerName}-identity`;
const vaultPath = `${groupPath}/providers/Microsoft.KeyVault/vaults/${resourceNames.vault}`;
const registryPath = `${groupPath}/providers/Microsoft.ContainerRegistry/registries/${resourceNames.registry}`;
const manifestPath = join(output, "secret-bootstrap.json");
const parametersPath = join(output, "secret-bootstrap.parameters.json");
const account = az(config, ["account", "show"], { json: true });
assertContext(config, account);
const client = new AzureClient(config);
const group = await client.request(`${groupPath}?api-version=2021-04-01`);
assertOwned(config, group);
const status = await createDeploymentStatus(config, output, "bootstrap");
console.log(`Live deployment report: ${status.url}`);

async function resource(path, version) {
  try {
    return await client.request(`${path}?api-version=${version}`);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function remove(path, version) {
  try {
    await client.request(`${path}?api-version=${version}`, {
      method: "DELETE",
    });
  } catch (error) {
    if (error.status !== 404) throw error;
  }
}

async function cleanup() {
  await status.update("Removing temporary bootstrap grants and site");
  const identity = await resource(identityPath, "2024-11-30");
  if (identity) {
    for (const [scope, role] of [
      [vaultPath, "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"],
      [registryPath, "7f951dda-4ed3-4680-a7ca-43fe172d538d"],
    ]) {
      const assignments = await client.list(
        `${scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`,
      );
      for (const assignment of assignments) {
        if (
          assignment.properties.principalId?.toLowerCase() ===
            identity.properties.principalId.toLowerCase() &&
          assignment.properties.scope?.toLowerCase() === scope.toLowerCase() &&
          assignment.properties.roleDefinitionId
            ?.toLowerCase()
            .endsWith(`/${role}`)
        )
          await remove(assignment.id, "2022-04-01");
      }
      const remaining = await client.list(
        `${scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01`,
      );
      if (
        remaining.some(
          (item) =>
            item.properties.principalId?.toLowerCase() ===
            identity.properties.principalId.toLowerCase(),
        )
      )
        throw new Error("Bootstrap identity retains a scoped role assignment");
    }
  }
  if (await resource(workerPath, "2024-11-01"))
    az(config, ["webapp", "delete", "--resource-group", config.resourceGroup, "--name", workerName, "--keep-empty-plan"]);
  if (identity) {
    for (let attempt = 0; attempt < 30; attempt++) {
      if (!(await resource(workerPath, "2024-11-01"))) break;
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    if (await resource(workerPath, "2024-11-01"))
      throw new Error("Temporary worker deletion not confirmed");
    await remove(identityPath, "2024-11-30");
  }
}

async function main() {
  if (await resource(workerPath, "2024-11-01"))
    throw new Error(
      "Temporary bootstrap site already exists; review and remove it before retrying",
    );
  await mkdir(output, { recursive: true });
  let manifest;
  if (action === "prepare") {
    await status.update("Building and scanning a private credential worker");
    const image = `${resourceNames.registry}.azurecr.io/secret-bootstrap:${Date.now()}`;
    run(
      "docker",
      [
        "build",
        "--platform",
        "linux/amd64",
        "-f",
        "scripts/Dockerfile.secret-bootstrap",
        "-t",
        image,
        fileURLToPath(root),
      ],
      { inherit: true },
    );
    const imageId = run("docker", [
      "image",
      "inspect",
      image,
      "--format",
      "{{.Id}}",
    ]);
    const scanPath = join(output, "secret-bootstrap.sarif");
    run(
      "trivy",
      [
        "image",
        "--scanners",
        "vuln",
        "--format",
        "sarif",
        "--output",
        scanPath,
        "--severity",
        "HIGH,CRITICAL",
        "--exit-code",
        "1",
        image,
      ],
      { inherit: true },
    );
    await status.update("Pushing scanned worker image to the owned registry");
    az(config, ["acr", "login", "--name", resourceNames.registry]);
    if (
      run("docker", ["image", "inspect", image, "--format", "{{.Id}}"]) !==
      imageId
    )
      throw new Error("Worker image changed after scan");
    run("docker", ["push", image], { inherit: true });
    const digest = az(
      config,
      [
        "acr",
        "manifest",
        "show-metadata",
        "--registry",
        resourceNames.registry,
        "--name",
        image.split("/").at(-1),
        "--query",
        "digest",
      ],
      { json: true },
    );
    manifest = {
      runId: randomUUID(),
      codeRevision: run("git", ["rev-parse", "HEAD"]),
      configHash: configHash(config),
      imageId,
      digest,
      scanHash: hash(await readFile(scanPath)),
    };
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  } else {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (
      manifest.codeRevision !== run("git", ["rev-parse", "HEAD"]) ||
      manifest.configHash !== configHash(config) ||
      manifest.scanHash !==
        hash(await readFile(join(output, "secret-bootstrap.sarif"))) ||
      !/^[a-f0-9-]{36}$/.test(manifest.runId) ||
      !/^sha256:[a-f0-9]{64}$/.test(manifest.digest)
    )
      throw new Error(
        "Bootstrap manifest no longer matches reviewed code, configuration, or scan",
      );
  }
  const parameters = {
    labId: config.labId,
    location: config.location,
    portalName: resourceNames.portal,
    appServiceSku: config.appServiceSku,
    registryName: resourceNames.registry,
    vaultName: resourceNames.vault,
    imageDigest: manifest.digest,
    runId: manifest.runId,
  };
  await writeFile(
    parametersPath,
    JSON.stringify(
      {
        $schema:
          "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        contentVersion: "1.0.0.0",
        parameters: Object.fromEntries(
          Object.entries(parameters).map(([key, value]) => [key, { value }]),
        ),
      },
      null,
      2,
    ),
  );
  await status.update(
    "Validating the isolated worker deployment with ARM what-if",
  );
  const command = [
    "deployment",
    "group",
    "what-if",
    "--name",
    "dojo-secret-bootstrap",
    "--resource-group",
    config.resourceGroup,
    "--template-file",
    "infra/secret-bootstrap.bicep",
    "--parameters",
    `@${parametersPath}`,
    "--no-pretty-print",
  ];
  const preview = az(config, command, { json: true });
  const changes = preview.changes.filter(
    (item) => !["Ignore", "NoChange"].includes(item.changeType),
  );
  if (
    !changes.length ||
    changes.some(
      (item) =>
        item.changeType !== "Create" ||
        (![workerPath.toLowerCase(), identityPath.toLowerCase(), `${groupPath}/providers/Microsoft.Web/serverFarms/${resourceNames.portal}-plan`.toLowerCase()].some((path) =>
          item.resourceId.toLowerCase().startsWith(path),
        ) &&
          ![vaultPath.toLowerCase(), registryPath.toLowerCase()].some((path) =>
            item.resourceId
              .toLowerCase()
              .startsWith(
                `${path}/providers/microsoft.authorization/roleassignments/`,
              ),
          )),
    )
  )
    throw new Error("Bootstrap what-if includes unexpected changes");
  const previewHash = hash(JSON.stringify({ manifest, preview }));
  await writeFile(
    join(output, "secret-bootstrap-what-if.json"),
    `${JSON.stringify({ previewHash, changes }, null, 2)}\n`,
  );
  const confirmation = `bootstrap:${previewHash}:${config.subscriptionId}:${config.resourceGroup}`;
  console.log(`Required confirmation: ${confirmation}`);
  if (action === "prepare") return;
  if (values.confirm !== confirmation)
    throw new Error(
      "State-bound bootstrap confirmation does not match fresh what-if",
    );
  let attempted = false;
  try {
    attempted = true;
    await status.update("Starting private VNet-integrated worker");
    az(
      config,
      [
        "deployment",
        "group",
        "create",
        "--name",
        "dojo-secret-bootstrap",
        "--resource-group",
        config.resourceGroup,
        "--template-file",
        "infra/secret-bootstrap.bicep",
        "--parameters",
        `@${parametersPath}`,
        "--mode",
        "Incremental",
      ],
      { json: true },
    );
    const workspace = az(
      config,
      [
        "monitor",
        "log-analytics",
        "workspace",
        "show",
        "--resource-group",
        config.resourceGroup,
        "--workspace-name",
        `${config.labId}-logs`,
        "--query",
        "customerId",
      ],
      { json: true },
    );
    const marker = `DOJO_BOOTSTRAP_READY ${manifest.runId}`;
    const query = `AppServiceConsoleLogs | where _ResourceId =~ '${workerPath}' and ResultDescription contains '${marker}' | project ResultDescription | take 1`;
    await status.update("Waiting for private vault completion marker");
    let observed = false;
    for (let attempt = 0; attempt < 90; attempt++) {
      try {
        const rows = az(
          config,
          [
            "monitor",
            "log-analytics",
            "query",
            "--workspace",
            workspace,
            "--analytics-query",
            query,
            "--timespan",
            "PT1H",
          ],
          { json: true },
        );
        if (rows.some((row) => row.ResultDescription?.includes(marker))) {
          observed = true;
          break;
        }
      } catch (error) {
        if (!error.message.includes("Failed to resolve table")) throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
    if (!observed)
      throw new Error("Private vault bootstrap completion was not observed");
  } finally {
    if (attempted) await cleanup();
  }
  await writeFile(
    join(output, "private-bootstrap-proof.json"),
    `${JSON.stringify(
      {
        runId: manifest.runId,
        codeRevision: manifest.codeRevision,
        configHash: manifest.configHash,
        observedAt: new Date().toISOString(),
      },
      null,
      2,
    )}\n`,
  );
  console.log(
    "Private vault credentials verified; temporary worker and grants removed",
  );
}

try {
  await main();
  await status.finish();
} catch (error) {
  console.error(error.message);
  await status.finish(true);
  process.exitCode = 1;
}
