import { SecretClient } from "@azure/keyvault-secrets";
import { AzureCliCredential } from "@azure/identity";
import { names } from "../../shared/config.mjs";
import { validCredentialValue } from "../../shared/credentials.mjs";
import { readJsonResponse } from "../../shared/http-json.mjs";
import {
  imageReceiptLimit,
  imageReceiptMetadata,
} from "../../shared/receipt-publishing.mjs";

export async function withPortalSession(
  config,
  callback,
  { fetcher = fetch, secrets } = {},
) {
  const resourceNames = names(config);
  const origin = `https://${resourceNames.portal}.azurewebsites.net`;
  const vault = secrets || new SecretClient(
    `https://${resourceNames.vault}.vault.azure.net`,
    new AzureCliCredential({ tenantId: config.tenantId }),
  );
  const username = (await vault.getSecret("admin-username")).value;
  const password = (await vault.getSecret("admin-password")).value;
  if (
    !validCredentialValue("admin-username", username) ||
    !validCredentialValue("admin-password", password)
  )
    throw new Error("Resolved Key Vault portal credentials are required");
  const headers = { origin, "content-type": "application/json" };
  const login = await fetcher(`${origin}/api/login`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers,
    body: JSON.stringify({ username, password }),
  });
  const session = await readJsonResponse(login, 4096, "Portal sign-in");
  const cookie = login.headers.getSetCookie()
    .find((value) => value.startsWith("dojo_session="))?.split(";")[0];
  if (
    session?.user !== username ||
    !/^[A-Za-z0-9_-]+$/.test(session?.csrf || "") ||
    !/^dojo_session=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(cookie || "")
  )
    throw new Error("Portal sign-in did not return a valid authenticated session");
  const request = async (path, body, limit = imageReceiptLimit) => {
    const response = await fetcher(`${origin}${path}`, {
      method: body === undefined ? "GET" : "POST",
      redirect: "error",
      signal: AbortSignal.timeout(120000),
      headers: { ...headers, cookie, "x-csrf-token": session.csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return readJsonResponse(response, limit, `Portal ${path}`);
  };
  try {
    return await callback({
      async publish(receipt) {
        const expected = imageReceiptMetadata(receipt);
        const observed = await request("/api/image-evidence", receipt, 4096);
        if (Object.entries(expected).some(([key, value]) => observed?.[key] !== value))
          throw new Error("Portal image receipt acknowledgement does not match");
        return observed;
      },
      async report() {
        const report = await request("/api/report");
        if (
          report?.schemaVersion !== 1 ||
          report.mode !== "live" ||
          !Array.isArray(report.checks) ||
          !Array.isArray(report.runs) ||
          !Number.isFinite(Date.parse(report.generatedAt)) ||
          Math.abs(Date.now() - Date.parse(report.generatedAt)) > 5 * 60000 ||
          ["labId", "subscriptionId", "tenantId", "resourceGroup", "location"].some(
            (key) => report.scope?.[key] !== config[key],
          ) ||
          report.source?.revision !== config.source.revision ||
          report.source?.repository !== config.source.repository ||
          report.drowsyDragon?.enabled !== (config.drowsyDragonEnabled === true) ||
          report.nginxProxy?.enabled !== (config.nginxProxyEnabled === true) ||
          report.nginxProxy?.requestedMode !== (config.nginxProxyMode || "vulnerable")
        )
          throw new Error("Portal report is stale or does not match the configured deployment");
        return report;
      },
    });
  } finally {
    const logout = await request("/api/logout", {}, 4096);
    if (logout?.signedOut !== true)
      throw new Error("Portal did not confirm verification-session revocation");
  }
}
