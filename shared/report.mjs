import { names } from "./config.mjs";
import { pricingMatches } from "./protection.mjs";
import { nginxProxy, nginxMode } from "./nginx-proxy.mjs";
import { collectNginxStory } from "./nginx-report.mjs";
import {
  drowsyDragon,
  drowsyDragonEvidenceKey,
  summarizeDragonReceipt,
} from "./drowsy-dragon.mjs";

export const story = [
  {
    id: "source",
    title: "01 / Source",
    text: "Compare three image stories: pinned WebGoat Java source; Drowsy Dragon's prebuilt DHI .NET SDK base; and the original NinjaPaws NGINX proxy imported from a reviewed commit. Both source snapshots are hash-verified. Native discovery still requires a healthy connector and supported scanners.",
  },
  {
    id: "build",
    title: "02 / Build & Assess",
    text: "Build and scan every enabled image before any push. Portal HIGH/CRITICAL findings block release. Drowsy Dragon and NGINX retain package versions, full Trivy JSON/SARIF and digest-bound receipts. NGINX 1.30.3 is the target-CVE affected mode; scanner association must still be observed, never assumed.",
  },
  {
    id: "posture",
    title: "03 / Cloud Posture",
    text: "Independently read Defender plans, extensions and assessments. Enabled is not assessed. Use ACR image assessment for all three training workloads. Trivy results are separate from Defender observations; no ACI sensor or native repository-to-runtime edge is promised. The legacy NGINX dashboard's coverage flags are configuration only.",
  },
  {
    id: "runtime",
    title: "04 / Runtime Validation",
    text: "HTTP test buttons remain WebGoat-only. Drowsy Dragon sleeps without ingress. NGINX proxies only its own private dashboard, not WebGoat or the admin portal. Collect its binary/package and map/regex startup measurements through the fixed private evidence endpoint. None of these observations proves exploitation or Defender detection.",
  },
  {
    id: "remediate",
    title: "05 / Remediate & Compare",
    text: "Choose a reviewed WebGoat fix, a reviewed Drowsy Dragon base digest, or NGINX's target-CVE remediated mode (1.30.4 with map/regex removed). Rebuild, rescan and compare individual findings, package versions, configurations and immutable digests. Fixing one NGINX CVE is not a claim that the image has no other vulnerabilities.",
  },
  {
    id: "retire",
    title: "06 / Report & Retire",
    text: "Export evidence before removing the tagged lab group. Subscription Defender settings and GitHub consent remain in place. Purge-protected Key Vaults retain deleted credentials until retention expires.",
  },
];

export const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );

export function emptyReport(config, mode = "not-collected") {
  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    mode,
    scope: {
      labId: config.labId,
      subscriptionId: config.subscriptionId || "Not selected",
      tenantId: config.tenantId || "Not selected",
      resourceGroup: config.resourceGroup,
      location: config.location,
    },
    source: config.source,
    release: {},
    drowsyDragon: {
      id: drowsyDragon.id,
      title: drowsyDragon.title,
      baseImage: drowsyDragon.baseImage,
      trackedPackages: drowsyDragon.packages,
      enabled: config.drowsyDragonEnabled === true,
      state: config.drowsyDragonEnabled ? "not-collected" : "disabled",
      scanState: "not-collected",
      packages: [],
      vulnerabilities: [],
    },
    nginxProxy: {
      id: nginxProxy.id,
      title: nginxProxy.title,
      targetCve: nginxProxy.targetCve,
      advisory: nginxProxy.advisory,
      upstream: nginxProxy.source,
      trackedPackages: nginxProxy.packages,
      requestedMode: nginxMode(config.nginxProxyMode).mode,
      expectedVersion: nginxMode(config.nginxProxyMode).version,
      enabled: config.nginxProxyEnabled === true,
      state: config.nginxProxyEnabled ? "not-collected" : "disabled",
      runtimeEvidenceState: "not-collected",
      scanState: "not-collected",
      packages: [],
      vulnerabilities: [],
    },
    checks: [],
    resources: [],
    findings: [],
    alerts: [],
    runs: [],
    limitations: [
      "Plan enablement is not evidence of assessment or detection.",
      "No alert is not proof of prevention.",
      "GitHub connector consent, repository discovery and native scanner coverage require independent verification.",
      "Network access does not establish serverless vulnerability assessment eligibility; inspect ACR assessments and service prerequisites.",
      "Costs are not estimated: review regional pricing and subscription-wide Defender charges before applying.",
      "Drowsy Dragon is an image/package assessment demo, not an HTTP exploit lab. Trivy snapshots do not prove Defender assessment, exploitability or runtime protection.",
      "NGINX runtime evidence is a container-reported startup snapshot, not a new binary probe. Private connectivity is required; configured vulnerability badges and requested coverage are not observed findings.",
      "No live collection has been performed.",
    ],
  };
}

export function alertTargets(alert, resourceId) {
  const properties = alert.properties || {};
  const ids = [
    ...(properties.resourceIdentifiers || []).map(
      (item) => item.azureResourceId,
    ),
    ...(properties.entities || []).map(
      (item) => item.azureID || item.resourceId,
    ),
  ];
  return ids.some(
    (value) =>
      typeof value === "string" &&
      value.toLowerCase() === resourceId.toLowerCase(),
  );
}

export function candidateAlerts(alerts, run) {
  return alerts.filter(
    (alert) =>
      alertTargets(alert, run.targetResourceId) &&
      Date.parse(alert.properties?.startTimeUtc) >=
        Date.parse(run.startedAt) - 60000 &&
      Date.parse(alert.properties?.startTimeUtc) <=
        Date.parse(run.startedAt) + 15 * 60000,
  );
}

export async function collectReport(config, client, runs = [], evidenceStore, { fetcher = fetch } = {}) {
  const report = emptyReport(config, "live");
  report.limitations.pop();
  const group = `${client.scope}/resourceGroups/${config.resourceGroup}`;
  const target = `${group}/providers/Microsoft.Web/sites/${names(config).dojo}`;
  const dragonTarget = `${group}/providers/Microsoft.ContainerInstance/containerGroups/${names(config).drowsyDragon}`;
  const collect = async (id, callback) => {
    try {
      await callback();
    } catch (error) {
      report.checks.push({ id, state: "unknown", detail: error.message });
    }
  };
  for (const [name, desired] of Object.entries(config.protection)) {
    await collect(name, async () => {
      const actual = await client.request(
        `${client.scope}/providers/Microsoft.Security/pricings/${name}?api-version=2024-01-01`,
      );
      report.checks.push({
        id: name,
        state: pricingMatches(actual, desired) ? "enabled" : "gap",
        detail: JSON.stringify(actual.properties),
      });
    });
  }
  await collect("Resources", async () => {
    report.resources = (
      await client.list(`${group}/resources?api-version=2021-04-01`)
    ).map((resource) => ({
      id: resource.id,
      name: resource.name,
      type: resource.type,
      location: resource.location,
    }));
    report.checks.push({
      id: "Resources",
      state: "observed",
      detail: `${report.resources.length} resources returned`,
    });
  });
  await collect("Assessments", async () => {
    report.findings = (
      await client.list(
        `${group}/providers/Microsoft.Security/assessments?api-version=2021-06-01`,
      )
    ).map((item) => ({
      id: item.id,
      title: item.properties?.displayName,
      state: item.properties?.status?.code,
      description: item.properties?.status?.description,
    }));
    report.checks.push({
      id: "Assessments",
      state: report.findings.length ? "observed" : "pending",
      detail: `${report.findings.length} assessments; ingestion and applicability vary`,
    });
  });
  for (const [key, name] of Object.entries({
    dojo: names(config).dojo,
    portal: names(config).portal,
  })) {
    await collect(`${key} image`, async () => {
      const siteConfig = await client.request(
        `${group}/providers/Microsoft.Web/sites/${name}/config/web?api-version=2024-11-01`,
      );
      const image = siteConfig.properties?.linuxFxVersion;
      report.release[`${key}ObservedImage`] = image || "Not returned";
      report.checks.push({
        id: `${key} image`,
        state: /@sha256:[a-f0-9]{64}$/.test(image || "") ? "observed" : "gap",
        detail: image || "No image reference returned",
      });
    });
  }
  const dragon = report.drowsyDragon;
  const dragonPresent = report.resources.some(
    (resource) => resource.id?.toLowerCase() === dragonTarget.toLowerCase(),
  );
  if (dragon.enabled || dragonPresent) {
    dragon.state = "unknown";
    dragon.scanState = "unknown";
    let digest;
    let scanHash;
    await collect("Drowsy Dragon runtime", async () => {
      const instance = await client.request(
        `${dragonTarget}?api-version=2023-05-01`,
      );
      const properties = instance.properties || {};
      const containers = properties.containers || [];
      const container = containers.find((item) => item.name === drowsyDragon.id);
      const image = container?.properties?.image;
      const prefix = `${names(config).registry}.azurecr.io/drowsy-dragon@`;
      if (
        typeof image === "string" &&
        image.startsWith(prefix) &&
        /^sha256:[a-f0-9]{64}$/.test(image.slice(prefix.length))
      )
        digest = image.slice(prefix.length);
      scanHash = instance.tags?.["dojo.scanHash"];
      dragon.observedImage = image || "Not returned";
      dragon.provisioningState = properties.provisioningState || "Not returned";
      dragon.runtimeState = container?.properties?.instanceView?.currentState?.state || "Not returned";
      dragon.groupState = properties.instanceView?.state || "Not returned";
      dragon.noIngressObserved = !properties.ipAddress &&
        containers.length === 1 && !container?.properties?.ports?.length;
      report.release.drowsyDragonObservedImage = dragon.observedImage;
      const matched = digest &&
        (!config.drowsyDragonDigest || digest === config.drowsyDragonDigest);
      dragon.state = !dragon.enabled ? "retained" :
        matched && dragon.noIngressObserved &&
        dragon.provisioningState === "Succeeded" &&
        dragon.runtimeState === "Running" && dragon.groupState === "Running"
          ? "observed" : "gap";
      report.checks.push({
        id: "Drowsy Dragon runtime",
        state: dragon.state === "observed" ? "observed" : "gap",
        detail: !dragon.enabled
          ? "Disabled in configuration but still deployed. Incremental releases do not delete it; use approved lab cleanup."
          : `Provisioning: ${dragon.provisioningState}; group: ${dragon.groupState}; container: ${dragon.runtimeState}; no ingress observed: ${dragon.noIngressObserved}; image: ${dragon.observedImage}. Runtime state is not vulnerability or detection evidence.`,
      });
    });
    await collect("Drowsy Dragon scan evidence", async () => {
      if (!digest || !evidenceStore) {
        dragon.scanState = "pending";
        report.checks.push({
          id: "Drowsy Dragon scan evidence",
          state: "pending",
          detail: "A matching observed ACR image and release evidence store are required. No vulnerability result is inferred.",
        });
        return;
      }
      const receipt = await evidenceStore.get(
        drowsyDragonEvidenceKey(digest, scanHash),
      );
      if (!receipt) {
        dragon.scanState = "pending";
        report.checks.push({
          id: "Drowsy Dragon scan evidence",
          state: "pending",
          detail: "The deployed image's scan receipt has not been collected. Missing evidence is not zero vulnerabilities.",
        });
        return;
      }
      Object.assign(dragon, summarizeDragonReceipt(receipt, digest, scanHash));
      dragon.scanState = "observed";
      report.checks.push({
        id: "Drowsy Dragon scan evidence",
        state: "observed",
        detail: `Trivy snapshot ${dragon.scannedAt}: ${dragon.vulnerabilities.length} findings across the four tracked packages; ${dragon.imageFindingCount} total image findings. Matched image digest and evidence hashes. Defender assessment remains separate.`,
      });
    });
  }
  const nginxTarget = await collectNginxStory({
    config, client, report, collect, evidenceStore, fetcher,
  });
  await collect("Alerts", async () => {
    const alerts = await client.list(
      `${client.scope}/providers/Microsoft.Security/alerts?api-version=2022-01-01`,
    );
    const scoped = alerts.filter((alert) =>
      alertTargets(alert, target) ||
      ((dragon.enabled || dragonPresent) && alertTargets(alert, dragonTarget)) ||
      (nginxTarget && alertTargets(alert, nginxTarget)),
    );
    report.alerts = scoped.map((alert) => ({
      id: alert.name,
      title: alert.properties?.alertDisplayName,
      severity: alert.properties?.severity,
      time: alert.properties?.startTimeUtc,
      state: alert.properties?.status,
    }));
    report.runs = runs.map((run) => ({
      ...run,
      candidateAlertIds: candidateAlerts(scoped, run).map(
        (alert) => alert.name,
      ),
      attribution:
        "Resource/time candidates only; causation and prevention unverified",
    }));
    report.checks.push({
      id: "Alerts",
      state: scoped.length ? "observed" : "pending",
      detail: `${scoped.length} target-scoped alerts; no alert is not proof of prevention`,
    });
  });
  if (!report.runs.length) report.runs = runs;
  report.checks.push({
    id: "GitHub connector / native code coverage",
    state: "unknown",
    detail:
      "Verify tenant consent, repository discovery, connector health and scanner support in Defender for Cloud.",
  });
  return report;
}

function imageStoryHtml(demo) {
  const source = demo.baseImage
    ? `<p>Approved base image: <code>${escapeHtml(demo.baseImage)}</code></p>`
    : `<p>Imported source: ${escapeHtml(demo.upstream.repository)} / <code>${escapeHtml(demo.upstream.revision)}</code></p>`;
  const target = demo.targetCve
    ? `<p>Target CVE: ${escapeHtml(demo.targetCve)}. Requested mode: ${escapeHtml(demo.requestedMode)} / ${escapeHtml(demo.expectedVersion)}. Trivy association: ${demo.scanState === "observed" ? demo.targetFindingObserved ? "reported" : "not returned" : "not collected"}.</p><p>Startup evidence: ${escapeHtml(demo.runtimeEvidenceState)}. Binary: ${escapeHtml(demo.runtime?.binaryVersion || "Not collected")}. Reported map/regex: ${typeof demo.runtime?.mapRegexEnabled === "boolean" ? String(demo.runtime.mapRegexEnabled) : "Not collected"}. A target-CVE fix does not establish a vulnerability-free image.</p>`
    : "";
  return `<h2>${escapeHtml(demo.title)} / Package Vulnerability Demo</h2><p>Deployment: ${escapeHtml(demo.state)}. Trivy evidence: ${escapeHtml(demo.scanState)}. ${demo.scanState === "observed" ? `${demo.vulnerabilities.length} tracked-package findings in the snapshot at ${escapeHtml(demo.scannedAt)}; this is not a Defender assessment or proof of exploitability.` : "Package findings have not been collected; no clean result is implied."}</p>${source}${target}<p>Observed runtime image: <code>${escapeHtml(demo.observedImage || "Not collected")}</code></p><table><tr><th>Tracked package</th><th>Installed version</th></tr>${demo.trackedPackages.map((name) => `<tr><td>${escapeHtml(name)}</td><td>${escapeHtml(demo.packages.find((pkg) => pkg.name === name)?.version || "Not collected")}</td></tr>`).join("")}</table>`;
}

export function reportHtml(report) {
  const rows = report.checks
    .map(
      (check) =>
        `<tr><td>${escapeHtml(check.id)}</td><td>${escapeHtml(check.state)}</td><td>${escapeHtml(check.detail)}</td></tr>`,
    )
    .join("");
  const gaps = report.checks.filter((check) =>
    ["gap", "unknown", "pending"].includes(check.state),
  ).length;
  const imageSections = [report.drowsyDragon, report.nginxProxy]
    .filter(Boolean).map(imageStoryHtml).join("");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Code to Cloud Security Dojo / Executive Report</title><style>body{font:16px 'Segoe UI',sans-serif;max-width:1100px;margin:32px auto;padding:24px;color:#201f1e}h1{font-size:30px}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{padding:12px;border-bottom:1px solid #ccc;text-align:left;overflow-wrap:anywhere}pre,code{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#555}@media print{body{margin:0;padding:0}tr{break-inside:avoid}}</style><h1>Code to Cloud Security Dojo Review</h1><p>Executive evidence report / ${escapeHtml(report.generatedAt)}</p><p><strong>Outcome: ${report.mode !== "live" ? "Not live-verified" : gaps ? "Coverage gaps or verification pending" : "Observed configuration only; efficacy not proven"}</strong></p><p>${gaps} unresolved checks. ${report.findings.length} assessments. ${report.alerts.length} target alerts. ${report.runs.length} recorded test runs.</p><h2>Scope & Accountability</h2><pre>${escapeHtml(JSON.stringify(report.scope, null, 2))}</pre>${imageSections}<h2>Coverage & Status</h2><table><tr><th>Control</th><th>Status</th><th>Evidence</th></tr>${rows}</table><h2>Executive Actions</h2><ol><li>Resolve unknown and missing coverage before presenting this lab as protected.</li><li>Review high-severity findings; compare remediation snapshots and immutable image digests.</li><li>Confirm recurring subscription charges and export evidence before teardown.</li></ol><h2>Limitations</h2><ul>${report.limitations.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul><h2>Technical Evidence</h2><pre>${escapeHtml(JSON.stringify({ source: report.source, release: report.release, drowsyDragon: report.drowsyDragon, nginxProxy: report.nginxProxy, resources: report.resources, findings: report.findings, alerts: report.alerts, runs: report.runs }, null, 2))}</pre><small>Independent training environment. Not a compliance certification or a production security assurance.</small></html>`;
}
