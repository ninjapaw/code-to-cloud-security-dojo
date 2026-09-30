import { readFile } from "node:fs/promises";
import { createApp } from "./app.mjs";
import { names, isLabHostname } from "../../shared/config.mjs";
import { AzureClient } from "../../shared/azure.mjs";
import {
  BlobEvidenceStore,
  MemoryEvidenceStore,
} from "../../shared/evidence-store.mjs";
import { collectReport, emptyReport } from "../../shared/report.mjs";

const preview = process.argv.includes("--preview");
const base = JSON.parse(
  await readFile(new URL("../../config/deploy.config.json", import.meta.url)),
);
const config = {
  ...base,
  labId: process.env.DOJO_LAB_ID || base.labId,
  tenantId: process.env.DOJO_TENANT_ID,
  subscriptionId: process.env.DOJO_SUBSCRIPTION_ID,
  resourceGroup: process.env.DOJO_RESOURCE_GROUP || base.resourceGroup,
  location: process.env.DOJO_LOCATION || base.location,
  source: {
    repository: process.env.DOJO_SOURCE_REPOSITORY || base.source.repository,
    revision: process.env.DOJO_SOURCE_REVISION || base.source.revision,
  },
};
const resourceNames = names(config);
config.protection = process.env.DOJO_PROTECTION_CONFIG
  ? JSON.parse(process.env.DOJO_PROTECTION_CONFIG)
  : base.protection;
Object.assign(config, {
  origin: process.env.WEBSITE_HOSTNAME
    ? `https://${process.env.WEBSITE_HOSTNAME}`
    : process.env.DOJO_ORIGIN,
  adminPassword: process.env.DOJO_ADMIN_PASSWORD,
  sessionKey: process.env.DOJO_SESSION_KEY,
  dojoHost: process.env.DOJO_TARGET_HOST,
  dojoName: resourceNames.dojo,
  dojoDigest: process.env.DOJO_IMAGE_DIGEST,
  portalDigest: process.env.DOJO_PORTAL_DIGEST,
  dojoResourceId: `/subscriptions/${config.subscriptionId}/resourceGroups/${config.resourceGroup}/providers/Microsoft.Web/sites/${resourceNames.dojo}`,
});
if (
  !preview &&
  (!config.origin?.startsWith("https://") ||
    !isLabHostname(config.dojoHost, resourceNames.dojo) ||
    !isLabHostname(new URL(config.origin).hostname, resourceNames.portal) ||
    !config.subscriptionId ||
    !config.tenantId)
)
  throw new Error(
    "Hosted tenant, subscription, HTTPS origin and fixed target must be configured",
  );
const client = preview ? null : new AzureClient(config, { hosted: true });
const store = preview
  ? new MemoryEvidenceStore()
  : new BlobEvidenceStore(process.env.DOJO_STORAGE_NAME, client.credential);
const app = createApp({
  config,
  store,
  preview,
  reportProvider: preview
    ? async () => emptyReport(config, "read-only-preview")
    : (runs) => collectReport(config, client, runs),
});
const port = Number(process.env.PORT || 4397);
const host = preview ? "127.0.0.1" : process.env.HOST || "0.0.0.0";
const server = app.listen(port, host, () =>
  console.log(
    `Code to Cloud Security Dojo portal: http://${host}:${port} (${preview ? "read-only preview; no Azure calls" : "hosted"})`,
  ),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => server.close());
