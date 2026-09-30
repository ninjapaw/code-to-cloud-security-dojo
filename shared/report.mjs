import { names } from "./config.mjs";
import { pricingMatches } from "./protection.mjs";

export const story = [
  {
    id: "source",
    title: "01 / Source",
    text: "WebGoat Java source is imported into this repository from a reviewed upstream commit. A source lock records its Git tree and content hash; image builds verify that snapshot. Native discovery still requires the GitHub connector and supported scanners that include the imported directory.",
  },
  {
    id: "build",
    title: "02 / Build & Assess",
    text: "Build and scan both images before deployment. Dojo workload findings are expected training evidence, not a production exception. Deploy only the reviewed immutable digests.",
  },
  {
    id: "posture",
    title: "03 / Cloud Posture",
    text: "Independently read Defender plans, extensions and assessments. Enabled is not the same as assessed. Private Dojo workload is ineligible for serverless vulnerability assessment; use ACR image assessment.",
  },
  {
    id: "runtime",
    title: "04 / Runtime Validation",
    text: "Run fixed authorized tests against the private lab target. An HTTP response confirms only delivery. Defender alerts can arrive hours later; time/resource matches remain candidates, not proven causation.",
  },
  {
    id: "remediate",
    title: "05 / Remediate & Compare",
    text: "Pin a reviewed remediation commit, rebuild, rescan and compare exported snapshots. Preserve before/after digests and timestamps. Do not infer prevention from the existence of an alert.",
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
    checks: [],
    resources: [],
    findings: [],
    alerts: [],
    runs: [],
    limitations: [
      "Plan enablement is not evidence of assessment or detection.",
      "No alert is not proof of prevention.",
      "GitHub connector consent, repository discovery and native scanner coverage require independent verification.",
      "Private Dojo workload serverless vulnerability assessment is not applicable; inspect ACR assessments.",
      "Costs are not estimated: review regional pricing and subscription-wide Defender charges before applying.",
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

export async function collectReport(config, client, runs = []) {
  const report = emptyReport(config, "live");
  report.limitations.pop();
  const group = `${client.scope}/resourceGroups/${config.resourceGroup}`;
  const target = `${group}/providers/Microsoft.Web/sites/${names(config).dojo}`;
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
  await collect("Alerts", async () => {
    const alerts = await client.list(
      `${client.scope}/providers/Microsoft.Security/alerts?api-version=2022-01-01`,
    );
    const scoped = alerts.filter((alert) => alertTargets(alert, target));
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
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Code to Cloud Security Dojo / Executive Report</title><style>body{font:16px 'Segoe UI',sans-serif;max-width:1100px;margin:32px auto;padding:24px;color:#201f1e}h1{font-size:30px}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{padding:12px;border-bottom:1px solid #ccc;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#555}@media print{body{margin:0;padding:0}tr{break-inside:avoid}}</style><h1>Code to Cloud Security Dojo Review</h1><p>Executive evidence report / ${escapeHtml(report.generatedAt)}</p><p><strong>Outcome: ${report.mode !== "live" ? "Not live-verified" : gaps ? "Coverage gaps or verification pending" : "Observed configuration only; efficacy not proven"}</strong></p><p>${gaps} unresolved checks. ${report.findings.length} assessments. ${report.alerts.length} target alerts. ${report.runs.length} recorded test runs.</p><h2>Scope & Accountability</h2><pre>${escapeHtml(JSON.stringify(report.scope, null, 2))}</pre><h2>Coverage & Status</h2><table><tr><th>Control</th><th>Status</th><th>Evidence</th></tr>${rows}</table><h2>Executive Actions</h2><ol><li>Resolve unknown and missing coverage before presenting this lab as protected.</li><li>Review high-severity findings; compare remediation snapshots and immutable image digests.</li><li>Confirm recurring subscription charges and export evidence before teardown.</li></ol><h2>Limitations</h2><ul>${report.limitations.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul><h2>Technical Evidence</h2><pre>${escapeHtml(JSON.stringify({ source: report.source, release: report.release, resources: report.resources, findings: report.findings, alerts: report.alerts, runs: report.runs }, null, 2))}</pre><small>Independent training environment. Not a compliance certification or a production security assurance.</small></html>`;
}
