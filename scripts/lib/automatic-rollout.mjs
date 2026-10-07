import { setTimeout as delay } from "node:timers/promises";
import { names, validateConfig, accessSettings } from "../../shared/config.mjs";
import { readJsonResponse } from "../../shared/http-json.mjs";
import { withPortalSession } from "./portal-client.mjs";

const webVersion = "2024-11-01";
const groupPath = (config) =>
  `/subscriptions/${config.subscriptionId}/resourceGroups/${config.resourceGroup}`;
const sitePath = (config, name) =>
  `${groupPath(config)}/providers/Microsoft.Web/sites/${name}`;
const imageReference = (config, release, key) =>
  `${names(config).registry}.azurecr.io/${names(config)[key]}@${release.images[key].digest}`;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

export function automaticContext(config, release, environment = process.env) {
  requireValue(
    environment.GITHUB_ACTIONS === "true" &&
      environment.GITHUB_REF === "refs/heads/dev" &&
      ["push", "workflow_dispatch"].includes(environment.GITHUB_EVENT_NAME) &&
      environment.GITHUB_REPOSITORY === "ninjapaw/code-to-cloud-security-dojo" &&
      environment.GITHUB_WORKFLOW_REF ===
        `${environment.GITHUB_REPOSITORY}/.github/workflows/deploy.yml@refs/heads/dev` &&
      environment.DOJO_AUTOMATIC_ROLLOUT === "true" &&
      /^\d+$/.test(environment.GITHUB_RUN_ID || "") &&
      /^\d+$/.test(environment.GITHUB_RUN_ATTEMPT || "") &&
      /^[a-f0-9]{40}$/.test(environment.GITHUB_SHA || "") &&
      (!release || environment.GITHUB_SHA === release.codeRevision) &&
      config.labId === "code-to-cloud-training" &&
      config.resourceGroup === config.labId,
    "Automatic rollout requires the explicitly enabled, same-revision dev GitHub workflow",
  );
  const ip = environment.DOJO_ROLLOUT_RUNNER_IPV4;
  validateConfig({ ...config, adminCidr: `${ip}/32` });
  return {
    name: `GitHubRollout-${environment.GITHUB_RUN_ID}-${environment.GITHUB_RUN_ATTEMPT}`,
    ipAddress: `${ip}/32`,
    priority: 101,
    action: "Allow",
    description: "Temporary authenticated GitHub rollout; removed on completion",
  };
}

export function validateAutomaticPreview(config, preview) {
  requireValue(
    preview?.status === "Succeeded" && !preview.error &&
      Array.isArray(preview.changes),
    "Automatic rollout requires a successful complete ARM preview",
  );
  const resourceNames = names(config);
  const group = groupPath(config).toLowerCase();
  const allowed = new Set();
  for (const name of [resourceNames.dojo, resourceNames.portal, ...(config.nginxProxyEnabled ? [resourceNames.nginxProxy] : [])]) {
    const site = `${group}/providers/microsoft.web/sites/${name}`;
    allowed.add(site);
    allowed.add(`${site}/basicpublishingcredentialspolicies/ftp`);
    allowed.add(`${site}/basicpublishingcredentialspolicies/scm`);
    allowed.add(`${site}/providers/microsoft.insights/diagnosticsettings/lab-evidence`);
  }
  for (const name of [resourceNames.dojo, ...(config.nginxProxyEnabled ? [resourceNames.nginxProxy] : [])]) {
    const endpoint = `${group}/providers/microsoft.network/privateendpoints/${name}-pe`;
    allowed.add(endpoint);
    allowed.add(`${endpoint}/privatednszonegroups/default`);
  }
  const zone = `${group}/providers/microsoft.network/privatednszones/privatelink.azurewebsites.net`;
  allowed.add(zone);
  allowed.add(`${zone}/virtualnetworklinks/${resourceNames.dojo}-pe-link`);
  if (config.drowsyDragonEnabled) {
    allowed.add(`${group}/providers/microsoft.containerinstance/containergroups/${resourceNames.drowsyDragon}`);
    allowed.add(`${group}/providers/microsoft.managedidentity/userassignedidentities/${resourceNames.drowsyDragon}-identity`);
  }
  for (const change of preview.changes) {
    if (["Ignore", "NoChange"].includes(change.changeType)) continue;
    const id = change.resourceId?.toLowerCase();
    const registryRole = `${group}/providers/microsoft.containerregistry/registries/${resourceNames.registry}/providers/microsoft.authorization/roleassignments/`;
    const existingPull = config.drowsyDragonEnabled && id?.startsWith(registryRole) &&
      change.before?.properties?.roleDefinitionId?.endsWith("/7f951dda-4ed3-4680-a7ca-43fe172d538d") &&
      change.after?.properties?.roleDefinitionId === change.before.properties.roleDefinitionId;
    requireValue(
      change.changeType === "Modify" && (allowed.has(id) || existingPull),
      `Automatic rollout refuses ${change.changeType} for ${change.resourceId}`,
    );
  }
  return preview;
}

export async function updateRunnerAccess(config, client, enabled, environment = process.env) {
  const rule = automaticContext(config, undefined, environment);
  const path = `${sitePath(config, names(config).portal)}/config/web?api-version=${webVersion}`;
  const before = (await client.request(path)).properties;
  requireValue(
    before?.ipSecurityRestrictionsDefaultAction === "Deny" &&
      before.scmIpSecurityRestrictionsDefaultAction === "Deny" &&
      Array.isArray(before.ipSecurityRestrictions),
    "Automatic runner access requires deny-by-default portal and SCM restrictions",
  );
  const current = before.ipSecurityRestrictions.filter((item) => item.name === rule.name);
  requireValue(current.length <= 1 && current.every((item) =>
    item.ipAddress === rule.ipAddress && item.action === "Allow" && item.priority === rule.priority),
  "Conflicting rollout access rule; refusing to replace it");
  if ((enabled && current.length) || (!enabled && !current.length)) return;
  const restrictions = before.ipSecurityRestrictions.filter((item) => item.name !== rule.name);
  await client.request(path, {
    method: "PATCH",
    body: { properties: { ipSecurityRestrictions: enabled ? [...restrictions, rule] : restrictions } },
  });
  const after = (await client.request(path)).properties;
  requireValue(
    after.ipSecurityRestrictionsDefaultAction === "Deny" &&
      after.scmIpSecurityRestrictionsDefaultAction === "Deny" &&
      after.ipSecurityRestrictions.some((item) =>
        item.name === rule.name && item.ipAddress === rule.ipAddress && item.action === "Allow") === enabled &&
      restrictions.every((item) => after.ipSecurityRestrictions.some((observed) =>
        observed.name === item.name && observed.ipAddress === item.ipAddress && observed.action === item.action)),
    "Portal runner-access readback did not preserve the expected restrictions",
  );
}

export async function withRunnerAccess(config, client, callback, environment = process.env) {
  try {
    await updateRunnerAccess(config, client, true, environment);
    return await callback();
  } finally {
    await updateRunnerAccess(config, client, false, environment);
  }
}

export async function waitForRelease(check, label, { attempts = 40, pause = () => delay(15000) } = {}) {
  let detail = "not ready";
  for (let attempt = 0; attempt < attempts; attempt++) {
    const result = await check();
    if (result.ready) return result.value;
    detail = result.detail;
    if (attempt + 1 < attempts) await pause();
  }
  throw new Error(`${label} did not become ready: ${detail}`);
}

export async function checkPortalRevision(config, revision, fetcher = fetch) {
  let response;
  try {
    response = await fetcher(`https://${names(config).portal}.azurewebsites.net/health`, {
      redirect: "error", signal: AbortSignal.timeout(15000),
    });
  } catch (error) {
    if (error.name !== "TimeoutError" &&
        !["ECONNRESET", "ECONNREFUSED", "ENOTFOUND", "UND_ERR_SOCKET", "UND_ERR_CONNECT_TIMEOUT"].includes(error.cause?.code))
      throw error;
    return { ready: false, detail: `Portal startup connection: ${error.cause?.code || error.name}` };
  }
  if ([403, 429, 502, 503, 504].includes(response.status)) {
    await response.body?.cancel();
    return { ready: false, detail: `Portal startup HTTP ${response.status}` };
  }
  const health = await readJsonResponse(response, 4096, "Portal revision health");
  return {
    ready: health.status === "running" && health.codeRevision === revision,
    detail: "Portal has not started the requested source revision",
    value: health,
  };
}

export async function prepareAutomaticPortal(config, release, client) {
  const path = `${sitePath(config, names(config).portal)}/config/web?api-version=${webVersion}`;
  const expected = `DOCKER|${imageReference(config, release, "portal")}`;
  if ((await client.request(path)).properties.linuxFxVersion !== expected) {
    await client.request(path, { method: "PATCH", body: { properties: { linuxFxVersion: expected } } });
    requireValue((await client.request(path)).properties.linuxFxVersion === expected,
      "Portal bootstrap image configuration did not match the verified release");
  }
  await waitForRelease(
    () => checkPortalRevision(config, release.codeRevision),
    "Portal bootstrap",
  );
}

export async function reconcileDragonScanTag(config, release, client) {
  if (!config.drowsyDragonEnabled) return;
  const path = `${groupPath(config)}/providers/Microsoft.ContainerInstance/containerGroups/${names(config).drowsyDragon}`;
  const instance = await client.request(`${path}?api-version=2023-05-01`);
  requireValue(
    instance.properties?.containers?.length === 1 &&
      instance.properties.containers[0].properties?.image === imageReference(config, release, "drowsyDragon"),
    "Refusing to reconcile scan metadata for a different Drowsy Dragon image",
  );
  const hash = release.images.drowsyDragon.scanJsonHash;
  if (instance.tags?.["dojo.scanHash"] !== hash)
    await client.request(`${path}/providers/Microsoft.Resources/tags/default?api-version=2021-04-01`, {
      method: "PATCH", body: { operation: "Merge", properties: { tags: { "dojo.scanHash": hash } } },
    });
  requireValue((await client.request(`${path}?api-version=2023-05-01`)).tags?.["dojo.scanHash"] === hash,
    "Drowsy Dragon scan tag did not match the verified receipt after reconciliation");
}

export function validateRolloutReport(config, release, report) {
  const failures = [];
  for (const key of Object.keys(release.images)) {
    const expected = `${key === "drowsyDragon" ? "" : "DOCKER|"}${imageReference(config, release, key)}`;
    if (report.release?.[`${key}ObservedImage`] !== expected) failures.push(`${key} running image digest`);
  }
  for (const key of ["drowsyDragon", "nginxProxy"].filter((key) => release.images[key])) {
    if (report[key]?.state !== "observed") failures.push(`${key} runtime`);
    if (report[key]?.scanState !== "observed") failures.push(`${key} scan receipt`);
  }
  if (config.nginxProxyEnabled && report.nginxProxy?.runtimeEvidenceState !== "observed")
    failures.push("NGINX private startup evidence");
  if (!Array.isArray(report.checks)) failures.push("Missing report checks");
  for (const check of report.checks || []) {
    if (["gap", "unknown"].includes(check.state) &&
        !(check.id === "GitHub connector / native code coverage" && check.state === "unknown"))
      failures.push(`${check.id}: ${check.detail}`);
  }
  return {
    ready: failures.length === 0,
    detail: failures.join("; "),
    value: report,
  };
}

export async function verifyAutomaticRelease(config, release, client) {
  const resourceNames = names(config);
  const access = accessSettings(config);
  for (const key of ["dojo", "portal", ...(config.nginxProxyEnabled ? ["nginxProxy"] : [])]) {
    const path = sitePath(config, resourceNames[key]);
    const site = await client.request(`${path}?api-version=${webVersion}`);
    const web = (await client.request(`${path}/config/web?api-version=${webVersion}`)).properties;
    requireValue(
      site.properties?.state === "Running" && site.properties.httpsOnly === true &&
        web.linuxFxVersion === `DOCKER|${imageReference(config, release, key)}` &&
        web.acrUseManagedIdentityCreds === true &&
        site.properties.publicNetworkAccess ===
          (key === "nginxProxy" || (key === "dojo" && !access.dojoPublicAccess) ? "Disabled" : "Enabled"),
      `Runtime image, state or access boundary did not match: ${key}`,
    );
    if (key === "portal")
      requireValue(web.ipSecurityRestrictionsDefaultAction === "Deny" &&
        web.scmIpSecurityRestrictionsDefaultAction === "Deny", "Portal access restrictions changed");
  }
  const storage = await client.request(
    `${groupPath(config)}/providers/Microsoft.Storage/storageAccounts/${resourceNames.storage}?api-version=2023-05-01`,
  );
  requireValue(storage.properties?.allowSharedKeyAccess === false &&
    storage.properties.allowBlobPublicAccess === false &&
    (access.evidencePublicAccess || storage.properties.publicNetworkAccess === "Disabled"),
  "Evidence storage access boundary changed");
  await waitForRelease(() => checkPortalRevision(config, release.codeRevision), "Portal release");
  for (const [path, expected] of [["dojo", "healthy"], ["evidence", "accessible"]]) {
    await waitForRelease(async () => {
      const response = await fetch(`https://${resourceNames.portal}.azurewebsites.net/health/${path}`, {
        redirect: "error", signal: AbortSignal.timeout(15000),
      });
      if (response.status === 503) {
        await response.body?.cancel();
        return { ready: false, detail: `${path} private connectivity is not ready` };
      }
      const health = await readJsonResponse(response, 4096, `${path} private health`);
      return { ready: health.status === expected, detail: `${path} private health response mismatch` };
    }, `${path} private connectivity`);
  }
  return waitForRelease(async () => {
    const report = await withPortalSession(config, (portal) => portal.report());
    return validateRolloutReport(config, release, report);
  }, "Runtime images and private scan evidence", { attempts: 12, pause: () => delay(20000) });
}
