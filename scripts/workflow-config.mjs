import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { booleanSetting, validateConfig } from "../shared/config.mjs";

export function workflowConfig(base, environment) {
  const config = { ...base };
  for (const [variable, key] of [
    ["DOJO_TENANT_ID", "tenantId"],
    ["DOJO_SUBSCRIPTION_ID", "subscriptionId"],
    ["DOJO_RESOURCE_GROUP", "resourceGroup"],
    ["DOJO_LOCATION", "location"],
    ["DOJO_OPERATOR_OBJECT_ID", "operatorObjectId"],
    ["DOJO_ADMIN_CIDR", "adminCidr"],
    ["DOJO_NGINX_PROXY_MODE", "nginxProxyMode"],
  ]) {
    if (environment[variable] !== undefined && environment[variable] !== "")
      config[key] = environment[variable];
  }
  for (const [variable, key] of [
    ["DOJO_DROWSY_DRAGON_ENABLED", "drowsyDragonEnabled"],
    ["DOJO_NGINX_PROXY_ENABLED", "nginxProxyEnabled"],
    ["DOJO_EVIDENCE_PUBLIC_ACCESS", "evidencePublicAccess"],
  ]) {
    if (environment[variable] !== undefined && environment[variable] !== "")
      config[key] = booleanSetting(environment[variable], variable);
  }
  return validateConfig(config);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 3)
      throw new Error("Pass the private workflow configuration output path");
    const base = JSON.parse(await readFile(
      new URL("../config/deploy.config.json", import.meta.url), "utf8",
    ));
    await writeFile(
      process.argv[2],
      `${JSON.stringify(workflowConfig(base, process.env), null, 2)}\n`,
      { mode: 0o600, flag: "wx" },
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
