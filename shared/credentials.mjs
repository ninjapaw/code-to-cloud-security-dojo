import { randomBytes } from "node:crypto";

export const credentialSecretNames = Object.freeze([
  "admin-username",
  "admin-password",
  "session-key",
]);

export function validCredentialValue(name, value) {
  if (!credentialSecretNames.includes(name))
    throw new Error("Unknown managed credential");
  if (typeof value !== "string" || value.startsWith("@Microsoft.KeyVault"))
    return false;
  return name === "admin-username"
    ? /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/.test(value)
    : value.length >= 43;
}

export async function ensureManagedSecrets(secrets, { rotate = false } = {}) {
  for (const name of credentialSecretNames) {
    let current;
    if (!rotate || name === "admin-username") {
      try {
        current = await secrets.getSecret(name);
      } catch (error) {
        if (error.statusCode !== 404) throw error;
      }
    }
    if (current && !rotate) {
      if (
        !current.properties.enabled ||
        !validCredentialValue(name, current.value) ||
        (current.properties.expiresOn &&
          current.properties.expiresOn < new Date())
      )
        throw new Error(
          `Existing credential ${name} requires explicit rotation or correction`,
        );
      continue;
    }
    if (
      name === "admin-username" &&
      current &&
      !validCredentialValue(name, current.value)
    )
      throw new Error("Correct admin-username explicitly before rotation");
    const value =
      name === "admin-username"
        ? current?.value ?? "admin"
        : randomBytes(48).toString("base64url");
    await secrets.setSecret(name, value, {
      expiresOn: new Date(Date.now() + 90 * 86400000),
      contentType: "text/plain",
      tags: { managedBy: "code-to-cloud-security-dojo", purpose: name },
    });
  }
}
