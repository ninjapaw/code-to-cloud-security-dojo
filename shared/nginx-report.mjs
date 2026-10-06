import { isLabHostname, names } from "./config.mjs";
import { imageEvidenceKey } from "./image-evidence.mjs";
import { nginxProxy, summarizeNginxReceipt, validateNginxRuntime } from "./nginx-proxy.mjs";
import { readJsonResponse } from "./http-json.mjs";

export async function readNginxRuntime(host, expectedName, mode, fetcher = fetch) {
  if (!isLabHostname(host, expectedName))
    throw new Error("NGINX Proxy evidence hostname is outside the configured lab");
  const response = await fetcher(`https://${host}/api/status`, {
    redirect: "error",
    signal: AbortSignal.timeout(8000),
  });
  return validateNginxRuntime(
    await readJsonResponse(response, 65536, "NGINX Proxy evidence"), mode,
  );
}

export async function collectNginxStory({ config, client, report, collect, evidenceStore, fetcher }) {
  const proxy = report.nginxProxy;
  const resourceNames = names(config);
  const target = `${client.scope}/resourceGroups/${config.resourceGroup}/providers/Microsoft.Web/sites/${resourceNames.nginxProxy}`;
  const sitePresent = report.resources.some(
    (resource) => resource.id?.toLowerCase() === target.toLowerCase(),
  );
  const group = `${client.scope}/resourceGroups/${config.resourceGroup}`;
  const retainedIds = new Set([
    target,
    `${group}/providers/Microsoft.Web/serverfarms/${resourceNames.nginxProxy}-plan`,
    `${group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${resourceNames.nginxProxy}-identity`,
    `${group}/providers/Microsoft.Network/privateEndpoints/${resourceNames.nginxProxy}-pe`,
  ].map((id) => id.toLowerCase()));
  const present = report.resources.some((resource) => retainedIds.has(resource.id?.toLowerCase()));
  if (!proxy.enabled && !present) return null;
  if (!proxy.enabled && !sitePresent) {
    proxy.state = "retained";
    report.checks.push({
      id: "NGINX Proxy retained resources", state: "gap",
      detail: "NGINX hosting resources remain after disabling the option, even though no site was returned. The plan can still incur charges; use approved lab cleanup.",
    });
    return target;
  }
  proxy.state = "unknown";
  proxy.scanState = "unknown";
  proxy.runtimeEvidenceState = "unknown";
  let digest;
  let scanHash;
  let host;
  let deployedMode;
  await collect("NGINX Proxy deployment", async () => {
    const [site, web] = await Promise.all([
      client.request(`${target}?api-version=2024-11-01`),
      client.request(`${target}/config/web?api-version=2024-11-01`),
    ]);
    const properties = site.properties || {};
    const image = web.properties?.linuxFxVersion;
    const prefix = `DOCKER|${resourceNames.registry}.azurecr.io/${resourceNames.nginxProxy}@`;
    if (typeof image === "string" && image.startsWith(prefix) &&
      /^sha256:[a-f0-9]{64}$/.test(image.slice(prefix.length)))
      digest = image.slice(prefix.length);
    host = properties.defaultHostName;
    scanHash = site.tags?.["dojo.scanHash"];
    deployedMode = site.tags?.["dojo.mode"];
    proxy.observedImage = image || "Not returned";
    proxy.privateAccessObserved = properties.publicNetworkAccess === "Disabled";
    proxy.platformState = properties.state || "Not returned";
    proxy.deployedMode = deployedMode || "Not returned";
    report.release.nginxProxyObservedImage = proxy.observedImage;
    proxy.state = !proxy.enabled ? "retained" :
      digest && (!config.nginxProxyDigest || digest === config.nginxProxyDigest) &&
      deployedMode === proxy.requestedMode && proxy.privateAccessObserved &&
      proxy.platformState === "Running" ? "observed" : "gap";
    report.checks.push({
      id: "NGINX Proxy deployment",
      state: proxy.state === "observed" ? "observed" : "gap",
      detail: !proxy.enabled
        ? "Disabled in configuration but still deployed. Export evidence and use approved lab cleanup; disabling does not stop billing."
        : `Platform: ${proxy.platformState}; public access disabled: ${proxy.privateAccessObserved}; mode tag: ${proxy.deployedMode}; image: ${proxy.observedImage}. Startup measurements and scans are separate checks.`,
    });
  });
  await collect("NGINX Proxy runtime evidence", async () => {
    proxy.runtime = await readNginxRuntime(
      host, resourceNames.nginxProxy, proxy.requestedMode, fetcher,
    );
    proxy.runtimeEvidenceState = proxy.runtime.matchesExpectedMode ? "observed" : "gap";
    report.checks.push({
      id: "NGINX Proxy runtime evidence",
      state: proxy.runtimeEvidenceState,
      detail: `Reported startup binary: ${proxy.runtime.binaryVersion}; package: ${proxy.runtime.packageVersion}; map/regex: ${proxy.runtime.mapRegexEnabled}. Matches requested mode: ${proxy.runtime.matchesExpectedMode}. This is not exploitability, a live binary re-probe, or a Defender finding.`,
    });
  });
  await collect("NGINX Proxy scan evidence", async () => {
    if (!digest || !evidenceStore) {
      proxy.scanState = "pending";
      report.checks.push({
        id: "NGINX Proxy scan evidence", state: "pending",
        detail: "An observed ACR digest and its evidence store are required; no clean scan is inferred.",
      });
      return;
    }
    const receipt = await evidenceStore.get(imageEvidenceKey(nginxProxy.id, digest, scanHash));
    if (!receipt) {
      proxy.scanState = "pending";
      report.checks.push({
        id: "NGINX Proxy scan evidence", state: "pending",
        detail: "The deployed NGINX image's scan receipt has not been collected; missing evidence is not zero vulnerabilities.",
      });
      return;
    }
    if (receipt.mode !== deployedMode)
      throw new Error("NGINX Proxy scan receipt does not match the deployed mode tag");
    Object.assign(proxy, summarizeNginxReceipt(receipt, digest, scanHash));
    proxy.scanState = "observed";
    report.checks.push({
      id: "NGINX Proxy scan evidence", state: "observed",
      detail: `Trivy snapshot ${proxy.scannedAt}: ${proxy.vulnerabilities.length} NGINX findings; ${proxy.imageFindingCount} total image findings. ${proxy.targetCve} association: ${proxy.targetFindingObserved ? "reported" : "not returned"}. Defender findings and target-CVE remediation require independent verification.`,
    });
  });
  return target;
}
