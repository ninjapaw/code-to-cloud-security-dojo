import { createHash } from "node:crypto";
import spawn from "cross-spawn";
import { fileURLToPath } from "node:url";
import { root, names, confirmation } from "../../shared/config.mjs";
import { drowsyDragon } from "../../shared/drowsy-dragon.mjs";
import { nginxProxy, nginxMode } from "../../shared/nginx-proxy.mjs";

export function run(
  command,
  args,
  { cwd = fileURLToPath(root), json = false, inherit = false } = {},
) {
  const result = spawn.sync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: inherit ? "inherit" : "pipe",
    timeout: 30 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
    env: { ...process.env, AZURE_CORE_ONLY_SHOW_ERRORS: "true" },
  });
  if (result.error || result.status !== 0)
    throw new Error(
      `${command} failed (${result.status ?? result.error?.code}). ${inherit ? "See command output." : String(result.stderr || "").slice(0, 1500)}`,
    );
  return json ? JSON.parse(result.stdout) : (result.stdout || "").trim();
}

export function az(config, args, options = {}) {
  return run(
    "az",
    [
      ...args,
      "--subscription",
      config.subscriptionId,
      "--only-show-errors",
      "--output",
      options.json ? "json" : "none",
    ],
    options,
  );
}

export function configHash(config) {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

export function ownedReaderAssignments(config, principalId, assignments) {
  const scope = `/subscriptions/${config.subscriptionId}`.toLowerCase();
  return assignments.filter(
    (item) =>
      item.id
        ?.toLowerCase()
        .startsWith(
          `${scope}/providers/microsoft.authorization/roleassignments/`,
        ) &&
      item.properties?.description === `CodeToCloud:${config.labId}` &&
      item.properties?.scope?.toLowerCase() === scope &&
      item.properties?.principalId?.toLowerCase() ===
        principalId.toLowerCase() &&
      item.properties?.roleDefinitionId?.endsWith(
        "/39bc4728-0917-49c7-9d2c-d95423bc2eb4",
      ),
  );
}

export function requireConfirmation(config, action, value) {
  const expected = confirmation(config, action);
  if (value !== expected)
    throw new Error(`Explicit approval required. Pass --confirm "${expected}"`);
}

export function baseParameters(config) {
  const resourceNames = names(config);
  return {
    labId: config.labId,
    location: config.location,
    adminIpv4Address: config.adminCidr.split("/")[0],
    registryName: resourceNames.registry,
    vaultName: resourceNames.vault,
    storageName: resourceNames.storage,
    portalName: resourceNames.portal,
    dojoName: resourceNames.dojo,
    nginxProxyEnabled: config.nginxProxyEnabled === true,
    nginxProxyName: resourceNames.nginxProxy,
  };
}

export function validateRelease(config, release) {
  if (
    !/^[a-f0-9]{64}$/.test(release.source?.snapshotSha256) ||
    !/^[a-f0-9]{40}$/.test(release.source?.tree) ||
    !Number.isInteger(release.source?.files) ||
    release.source.files < 1
  )
    throw new Error(
      "Release lacks verified WebGoat source snapshot provenance; rebuild it",
    );
  if (
    release.schemaVersion !== 1 ||
    !/^[a-f0-9]{40}$/.test(release.codeRevision || "") ||
    release.configHash !== configHash(config) ||
    release.source.revision !== config.source.revision ||
    release.source.repository !== config.source.repository
  )
    throw new Error("Release was built for a different configuration/source");
  const requiredImages = [
    "dojo",
    "portal",
    ...(config.drowsyDragonEnabled ? ["drowsyDragon"] : []),
    ...(config.nginxProxyEnabled ? ["nginxProxy"] : []),
  ];
  if (!config.drowsyDragonEnabled && release.images?.drowsyDragon)
    throw new Error("Drowsy Dragon is not enabled for this release");
  if (!config.nginxProxyEnabled && release.images?.nginxProxy)
    throw new Error("NGINX Proxy is not enabled for this release");
  for (const image of requiredImages) {
    if (
      !/^sha256:[a-f0-9]{64}$/.test(release.images?.[image]?.digest) ||
      !/^sha256:[a-f0-9]{64}$/.test(release.images[image].imageId) ||
      !/^[a-f0-9]{64}$/.test(release.images[image].scanHash)
    )
      throw new Error(`Missing digest, image ID or scan evidence: ${image}`);
  }
  if (config.drowsyDragonEnabled) {
    const entry = release.images.drowsyDragon;
    if (
      entry.repository !== drowsyDragon.id ||
      entry.baseImage !== drowsyDragon.baseImage ||
      !entry.image?.startsWith(
        `${names(config).registry}.azurecr.io/drowsy-dragon:`,
      ) ||
      !/^sha256:[a-f0-9]{64}$/.test(entry.imageId || "") ||
      !/^[a-f0-9]{40}$/.test(entry.sourceRevision || "") ||
      !Number.isFinite(Date.parse(entry.scannedAt)) ||
      ["dockerfileHash", "inventoryHash", "scanJsonHash"].some(
        (key) => !/^[a-f0-9]{64}$/.test(entry[key] || ""),
      ) ||
      ["scanPath", "inventoryPath", "scanJsonPath"].some(
        (key) => typeof entry[key] !== "string" || !entry[key],
      )
    )
      throw new Error(
        "Drowsy Dragon requires pinned provenance and package/scan evidence",
      );
  }
  if (config.nginxProxyEnabled) {
    const entry = release.images.nginxProxy;
    if (
      entry.repository !== nginxProxy.id ||
      entry.mode !== nginxMode(config.nginxProxyMode).mode ||
      entry.dockerfileHash !== nginxProxy.dockerfileHash ||
      entry.sourceSnapshotHash !== nginxProxy.source.sha256 ||
      !entry.image?.startsWith(
        `${names(config).registry}.azurecr.io/nginx-proxy:`,
      ) ||
      !/^sha256:[a-f0-9]{64}$/.test(entry.imageId || "") ||
      !/^[a-f0-9]{40}$/.test(entry.sourceRevision || "") ||
      !Number.isFinite(Date.parse(entry.scannedAt)) ||
      ["sourceLockHash", "inventoryHash", "scanJsonHash"].some(
        (key) => !/^[a-f0-9]{64}$/.test(entry[key] || ""),
      ) ||
      ["sourceLockPath", "scanPath", "inventoryPath", "scanJsonPath"].some(
        (key) => typeof entry[key] !== "string" || !entry[key],
      )
    )
      throw new Error(
        "NGINX Proxy requires its approved mode, source pin and package/scan evidence",
      );
  }
  return release;
}

export function releaseParameters(config, release) {
  validateRelease(config, release);
  return {
    ...baseParameters(config),
    portalDigest: release.images.portal.digest,
    dojoDigest: release.images.dojo.digest,
    sourceRepository: config.source.repository,
    sourceRevision: config.source.revision,
    protection: config.protection,
    drowsyDragonEnabled: config.drowsyDragonEnabled === true,
    drowsyDragonName: names(config).drowsyDragon,
    drowsyDragonDigest: release.images.drowsyDragon?.digest || "",
    drowsyDragonScanHash: release.images.drowsyDragon?.scanJsonHash || "",
    nginxProxyMode: nginxMode(config.nginxProxyMode).mode,
    nginxProxyDigest: release.images.nginxProxy?.digest || "",
    nginxProxyScanHash: release.images.nginxProxy?.scanJsonHash || "",
  };
}

export function requireReleaseCostApproval(config, accepted) {
  if (
    (config.drowsyDragonEnabled || config.nginxProxyEnabled) &&
    accepted !== true
  )
    throw new Error(
      "Optional image demos incur recurring Azure charges; deploy requires --accept-costs",
    );
}
