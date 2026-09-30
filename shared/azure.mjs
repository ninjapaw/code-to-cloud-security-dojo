import { AzureCliCredential, ManagedIdentityCredential } from "@azure/identity";

export class AzureClient {
  constructor(config, { hosted = false, credential, fetcher = fetch } = {}) {
    this.config = config;
    this.credential =
      credential ||
      (hosted
        ? new ManagedIdentityCredential({
            clientId: process.env.AZURE_CLIENT_ID,
          })
        : new AzureCliCredential({
            tenantId: config.tenantId,
            subscription: config.subscriptionId,
          }));
    this.fetcher = fetcher;
    this.scope = `/subscriptions/${config.subscriptionId}`;
  }

  async request(path, { method = "GET", body } = {}) {
    const url = new URL(path, "https://management.azure.com");
    if (
      url.origin !== "https://management.azure.com" ||
      !url.pathname.toLowerCase().startsWith(`${this.scope.toLowerCase()}/`)
    )
      throw new Error("ARM request outside configured subscription");
    const token = await this.credential.getToken(
      "https://management.azure.com/.default",
    );
    for (let attempt = 0; attempt < 3; attempt++) {
      const response = await this.fetcher(url, {
        method,
        redirect: "error",
        signal: AbortSignal.timeout(30000),
        headers: {
          Authorization: `Bearer ${token.token}`,
          "Content-Type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.ok)
        return [202, 204].includes(response.status) ? null : response.json();
      if (
        (response.status === 429 || response.status >= 500) &&
        attempt < 2 &&
        method === "GET"
      ) {
        await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt));
        continue;
      }
      const error = new Error(
        `Azure ${method} failed (${response.status}) for ${url.pathname}`,
      );
      error.status = response.status;
      throw error;
    }
  }

  async list(path) {
    const result = [];
    const visited = new Set();
    while (path) {
      if (visited.has(path) || visited.size >= 100)
        throw new Error("Incomplete Azure pagination");
      visited.add(path);
      const page = await this.request(path);
      if (!Array.isArray(page.value))
        throw new Error("Invalid Azure collection response");
      result.push(...page.value);
      path = page.nextLink;
    }
    return result;
  }
}
