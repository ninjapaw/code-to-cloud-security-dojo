import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { SecretClient } from "@azure/keyvault-secrets";
import { ManagedIdentityCredential } from "@azure/identity";

export async function ensureBootstrapSecrets(secrets) {
  for (const name of ["admin-password", "session-key"]) {
    try {
      const current = await secrets.getSecret(name);
      if (
        !current.properties.enabled ||
        !current.value ||
        current.value.length < 43 ||
        (current.properties.expiresOn &&
          current.properties.expiresOn < new Date())
      )
        throw new Error("Existing credential requires explicit rotation");
    } catch (error) {
      if (error.statusCode !== 404) throw error;
      await secrets.setSecret(name, randomBytes(48).toString("base64url"), {
        expiresOn: new Date(Date.now() + 90 * 86400000),
        contentType: "text/plain",
        tags: { managedBy: "code-to-cloud-security-dojo", purpose: name },
      });
    }
  }
}

export async function stampBootstrapSecrets(secrets, runId) {
  for (const name of ["admin-password", "session-key"]) {
    const current = await secrets.getSecret(name);
    await secrets.updateSecretProperties(name, current.properties.version, {
      tags: { ...current.properties.tags, bootstrapRunId: runId },
    });
    const verified = await secrets.getSecret(name);
    if (
      verified.properties.tags?.bootstrapRunId !== runId ||
      verified.value !== current.value
    )
      throw new Error("Private credential metadata readback failed");
  }
}

export function startBootstrapHealth(port = 8080, host = "0.0.0.0") {
  return createServer((request, response) => {
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end("ready");
  }).listen(port, host);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const vaultName = process.env.DOJO_BOOTSTRAP_VAULT;
  const clientId = process.env.AZURE_CLIENT_ID;
  const runId = process.env.DOJO_BOOTSTRAP_RUN_ID;
  if (
    !/^[a-z0-9-]{3,24}$/.test(vaultName || "") ||
    !clientId ||
    !/^[a-f0-9-]{36}$/.test(runId || "")
  )
    throw new Error("Bootstrap scope, identity and run ID are required");
  const secrets = new SecretClient(
    `https://${vaultName}.vault.azure.net`,
    new ManagedIdentityCredential({ clientId }),
  );
  try {
    await ensureBootstrapSecrets(secrets);
    await ensureBootstrapSecrets(secrets);
    await stampBootstrapSecrets(secrets, runId);
    const readyMarker = `DOJO_BOOTSTRAP_READY ${runId}`;
    console.log(readyMarker);
    startBootstrapHealth();
    setInterval(() => console.log(readyMarker), 30_000).unref();
  } catch (error) {
    console.error(
      `Private vault bootstrap failed (${error.statusCode || "unavailable"})`,
    );
    process.exitCode = 1;
  }
}
