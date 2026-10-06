import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { existsSync } from "node:fs";
import { nginxMode } from "./nginx-proxy.mjs";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const root = new URL("../", import.meta.url);
const localConfig = new URL("../config/deploy.local.json", import.meta.url);
export const configPath =
  process.env.DOJO_CONFIG ||
  (existsSync(localConfig)
    ? localConfig
    : new URL("../config/deploy.config.json", import.meta.url));

export function validateConfig(config, { offline = false } = {}) {
  if (config.schemaVersion !== 1)
    throw new Error("Unsupported configuration schema");
  if (!/^[a-z][a-z0-9-]{2,35}$/.test(config.labId))
    throw new Error("Invalid labId");
  if (!/^[a-zA-Z0-9_-]{3,64}$/.test(config.resourceGroup))
    throw new Error("Invalid resourceGroup");
  if (!/^[a-z]+[0-9]?$/.test(config.location))
    throw new Error("Invalid Azure location");
  for (const key of ["tenantId", "subscriptionId", "operatorObjectId"]) {
    if (offline && !config[key]) continue;
    if (!uuid.test(config[key]) || /^0{8}-/.test(config[key]))
      throw new Error(`Set an explicit ${key}`);
  }
  if (!offline || config.adminCidr) {
    const [address, prefix] = (config.adminCidr || "").split("/");
    if (
      isIP(address) !== 4 ||
      prefix !== "32" ||
      config.adminCidr !== `${address}/32` ||
      /^(0|10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01])|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])|22[4-9]|23\d|24\d|25[0-5])\./.test(
        address,
      )
    ) {
      throw new Error(
        "adminCidr must be one authorized public IPv4 address with /32",
      );
    }
  }
  if (!["B2", "B3", "P1v3"].includes(config.appServiceSku))
    throw new Error("Unsupported App Service SKU");
  accessSettings(config);
  if (
    config.drowsyDragonEnabled !== undefined &&
    typeof config.drowsyDragonEnabled !== "boolean"
  )
    throw new Error("drowsyDragonEnabled must be a boolean");
  if (
    config.nginxProxyEnabled !== undefined &&
    typeof config.nginxProxyEnabled !== "boolean"
  )
    throw new Error("nginxProxyEnabled must be a boolean");
  nginxMode(config.nginxProxyMode);
  if (
    !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git$/.test(
      config.source?.repository,
    ) ||
    !/^[a-f0-9]{40}$/.test(config.source?.revision)
  )
    throw new Error("Pin a GitHub source repository and full commit SHA");
  const allowedPlans = [
    "CloudPosture",
    "Containers",
    "AppServices",
    "KeyVaults",
  ];
  if (
    Object.keys(config.protection || {}).some(
      (name) => !allowedPlans.includes(name),
    )
  )
    throw new Error("Unsupported Defender plan");
  for (const name of allowedPlans) {
    if (config.protection?.[name]?.pricingTier !== "Standard")
      throw new Error(`Required Defender plan: ${name}`);
  }
  for (const [plan, extension] of [
    ["CloudPosture", "AgentlessServerlessPosture"],
    ["Containers", "ContainerRegistriesVulnerabilityAssessments"],
  ]) {
    if (
      !config.protection[plan].extensions?.some(
        (item) => item.name === extension && item.isEnabled === "True",
      )
    )
      throw new Error(`Required Defender extension: ${extension}`);
  }
  return config;
}

export function accessSettings(config) {
  const settings = {};
  for (const [key, fallback] of [
    ["keyVaultPublicAccess", true],
    ["keyVaultRestrictToAdminIp", false],
    ["dojoPublicAccess", true],
    ["dojoRestrictToAdminIp", false],
    ["evidencePublicAccess", true],
  ]) {
    const value = config[key] === undefined ? fallback : config[key];
    if (typeof value !== "boolean")
      throw new Error(`${key} must be a boolean`);
    settings[key] = value;
  }
  const tags =
    config.keyVaultPublicAccessTags === undefined
      ? { SecurityControl: "Ignore" }
      : config.keyVaultPublicAccessTags;
  if (
    !tags ||
    typeof tags !== "object" ||
    Array.isArray(tags) ||
    Object.entries(tags).some(
      ([key, value]) =>
        !key.trim() ||
        typeof value !== "string" ||
        /^dojo\.(labId|managedBy)$/i.test(key),
    )
  )
    throw new Error(
      "keyVaultPublicAccessTags must be an object of nonempty tag names and string values, without dojo.labId or dojo.managedBy overrides",
    );
  return { ...settings, keyVaultPublicAccessTags: { ...tags } };
}

export async function loadConfig(options) {
  return validateConfig(
    JSON.parse(await readFile(configPath, "utf8")),
    options,
  );
}

export function booleanSetting(value, name, fallback = false) {
  if (value === undefined) return fallback === true;
  if (typeof value !== "string" || !/^(true|false)$/i.test(value))
    throw new Error(`${name} must be true or false`);
  return value.toLowerCase() === "true";
}

export function names(config) {
  const suffix = createHash("sha256")
    .update(
      `${(config.subscriptionId || "").toLowerCase()}/${config.resourceGroup.toLowerCase()}/${config.labId}`,
    )
    .digest("hex")
    .slice(0, 12);
  return {
    registry: `dojo${suffix}`,
    vault: `dojo-${suffix}`,
    storage: `dojo${suffix}`,
    portal: `dojo-${suffix}-portal`,
    dojo: `dojo-${suffix}-app`,
    drowsyDragon: `dojo-${suffix}-dragon`,
    nginxProxy: `dojo-${suffix}-proxy`,
  };
}

export function assertContext(config, account) {
  if (
    account.id?.toLowerCase() !== config.subscriptionId.toLowerCase() ||
    account.tenantId?.toLowerCase() !== config.tenantId.toLowerCase() ||
    account.state !== "Enabled" ||
    account.environmentName !== "AzureCloud"
  )
    throw new Error(
      "Azure commercial cloud/tenant/subscription mismatch or subscription disabled",
    );
}

export function assertOwned(config, group) {
  if (
    group.name?.toLowerCase() !== config.resourceGroup.toLowerCase() ||
    group.tags?.["dojo.labId"] !== config.labId ||
    group.tags?.["dojo.managedBy"] !== "code-to-cloud-security-dojo"
  )
    throw new Error("Refusing an unowned resource group");
}

export function confirmation(config, action) {
  return `${action}:${config.subscriptionId}:${config.resourceGroup}`;
}

export function isLabHostname(host, appName) {
  if (!/^dojo-[a-f0-9]{12}-(app|portal|proxy)$/.test(appName || "")) return false;
  return new RegExp(
    `^${appName}(?:-[a-z0-9]+(?:\\.[a-z0-9-]+)?)?\\.azurewebsites\\.net$`,
  ).test(host || "");
}
