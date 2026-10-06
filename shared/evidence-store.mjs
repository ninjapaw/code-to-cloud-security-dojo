import { BlobServiceClient } from "@azure/storage-blob";

export class BlobEvidenceStore {
  constructor(accountName, credential) {
    if (!/^[a-z0-9]{3,24}$/.test(accountName))
      throw new Error("Invalid evidence storage account");
    this.container = new BlobServiceClient(
      `https://${accountName}.blob.core.windows.net`,
      credential,
      { retryOptions: { maxTries: 1, tryTimeoutInMs: 10000 } },
    ).getContainerClient("evidence");
  }
  async probe() {
    await this.container.getProperties({
      abortSignal: AbortSignal.timeout(10000),
    });
  }
  async get(name) {
    try {
      return JSON.parse(
        (
          await this.container
            .getBlockBlobClient(name)
            .downloadToBuffer(0, undefined, {
              abortSignal: AbortSignal.timeout(10000),
            })
        ).toString("utf8"),
      );
    } catch (error) {
      if (error.statusCode === 404) return null;
      throw error;
    }
  }
  async put(name, value, { ifAbsent = false } = {}) {
    const data = Buffer.from(JSON.stringify(value));
    await this.container.getBlockBlobClient(name).uploadData(data, {
      abortSignal: AbortSignal.timeout(10000),
      blobHTTPHeaders: { blobContentType: "application/json" },
      conditions: ifAbsent ? { ifNoneMatch: "*" } : undefined,
    });
  }
  async list(prefix, limit = 100) {
    const results = [];
    for await (const item of this.container.listBlobsFlat({ prefix })) {
      results.push(item.name);
      if (results.length > 10000)
        throw new Error(
          "Evidence index exceeds collection limit; export/archive evidence before continuing",
        );
    }
    return Promise.all(
      results
        .sort()
        .reverse()
        .slice(0, limit)
        .map((name) => this.get(name)),
    );
  }
  async withLock(callback) {
    const blob = this.container.getBlockBlobClient("locks/tests");
    try {
      await blob.uploadData(Buffer.from("{}"), {
        conditions: { ifNoneMatch: "*" },
      });
    } catch (error) {
      if (error.statusCode !== 409 && error.statusCode !== 412) throw error;
    }
    const lease = blob.getBlobLeaseClient();
    try {
      await lease.acquireLease(60);
    } catch {
      throw Object.assign(new Error("Another test is active"), { status: 409 });
    }
    try {
      const state = await this.get("locks/tests");
      if (Date.now() - (state?.lastRun || 0) < 60000)
        throw Object.assign(new Error("Tests have a 60-second cooldown"), {
          status: 429,
        });
      await blob.uploadData(
        Buffer.from(JSON.stringify({ lastRun: Date.now() })),
        {
          conditions: { leaseId: lease.leaseId },
          abortSignal: AbortSignal.timeout(10000),
        },
      );
      return await callback();
    } finally {
      await lease.releaseLease();
    }
  }
}

export class MemoryEvidenceStore {
  constructor() {
    this.items = new Map();
    this.busy = false;
    this.lastRun = 0;
  }
  async get(name) {
    return structuredClone(this.items.get(name) || null);
  }
  async put(name, value, { ifAbsent = false } = {}) {
    if (ifAbsent && this.items.has(name))
      throw Object.assign(new Error("Evidence already exists"), { statusCode: 412 });
    this.items.set(name, structuredClone(value));
  }
  async list(prefix, limit = 100) {
    return [...this.items]
      .filter(([name]) => name.startsWith(prefix))
      .sort(([left], [right]) => right.localeCompare(left))
      .slice(0, limit)
      .map(([, value]) => structuredClone(value));
  }
  async probe() {}
  async withLock(callback) {
    if (this.busy || Date.now() - this.lastRun < 60000)
      throw Object.assign(new Error("Test busy or cooling down"), {
        status: 429,
      });
    this.busy = true;
    this.lastRun = Date.now();
    try {
      return await callback();
    } finally {
      this.busy = false;
    }
  }
}
