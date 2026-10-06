import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createApp } from "../apps/control-portal/app.mjs";
import { names } from "../shared/config.mjs";
import { BlobEvidenceStore, MemoryEvidenceStore } from "../shared/evidence-store.mjs";
import { drowsyDragon, drowsyDragonRecipe } from "../shared/drowsy-dragon.mjs";
import { nginxProxy } from "../shared/nginx-proxy.mjs";
import { sha256 } from "../shared/image-evidence.mjs";
import { emptyReport } from "../shared/report.mjs";
import {
  imageReceiptLimit,
  imageReceiptMetadata,
  publishImageReceipt,
} from "../shared/receipt-publishing.mjs";
import { withPortalSession } from "../scripts/lib/portal-client.mjs";

const base = JSON.parse(await readFile(
  new URL("../config/deploy.config.json", import.meta.url),
));
const config = {
  ...base,
  subscriptionId: "22222222-2222-4222-8222-222222222222",
  tenantId: "11111111-1111-4111-8111-111111111111",
  adminUsername: "workshop-admin",
  adminPassword: "a".repeat(64),
  sessionKey: "b".repeat(64),
  drowsyDragonEnabled: true,
  nginxProxyEnabled: true,
};
config.origin = `https://${names(config).portal}.azurewebsites.net`;
const imageId = `sha256:${"a".repeat(64)}`;
const digest = `sha256:${"b".repeat(64)}`;

async function receiptFor(id = drowsyDragon.id) {
  const dragon = id === drowsyDragon.id;
  const definition = dragon ? drowsyDragon : nginxProxy;
  const version = dragon ? "1.0" : "1.30.3-1~noble";
  const artifacts = {
    dockerfile: dragon ? drowsyDragonRecipe : await readFile(
      new URL("../apps/nginx-proxy/upstream/Dockerfile", import.meta.url), "utf8",
    ),
    inventory: definition.packages.map((name) => `${name}\t${version}\n`).join(""),
    scanJson: JSON.stringify({
      SchemaVersion: 2,
      ArtifactType: "container_image",
      Metadata: { ImageID: imageId },
      Results: [{
        Packages: definition.packages.map((Name) => ({ Name, Version: version })),
      }],
      fixturePadding: "x".repeat(3000),
    }),
  };
  if (!dragon)
    artifacts.sourceLock = await readFile(
      new URL("../apps/nginx-proxy/source-lock.json", import.meta.url), "utf8",
    );
  return {
    schemaVersion: 1,
    demoId: id,
    imageDigest: digest,
    imageId,
    sourceRevision: "c".repeat(40),
    scannedAt: "2026-09-30T12:00:00Z",
    ...(dragon ? { baseImage: drowsyDragon.baseImage } : { mode: "vulnerable" }),
    hashes: {
      ...Object.fromEntries(Object.entries(artifacts).map(([key, value]) => [key, sha256(value)])),
      sarif: sha256("{}"),
    },
    artifacts,
  };
}

async function startPortal(t, options = {}) {
  const store = options.store || new MemoryEvidenceStore();
  const app = createApp({
    config,
    store,
    reportProvider: options.reportProvider || (async () => emptyReport(config, "live")),
    preview: options.preview || false,
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const requests = [];
  const fetcher = async (target, init = {}) => {
    const url = new URL(target);
    assert.equal(url.origin, config.origin);
    assert.equal(init.redirect, "error");
    assert.equal(init.headers.origin, config.origin);
    requests.push(url.pathname);
    return fetch(`${origin}${url.pathname}`, init);
  };
  const secrets = {
    async getSecret(name) {
      assert.ok(["admin-username", "admin-password"].includes(name));
      return { value: name === "admin-username" ? config.adminUsername : config.adminPassword };
    },
  };
  return { store, origin, requests, clientOptions: { fetcher, secrets } };
}

test("both approved receipts publish with create-only idempotence and exact readback", async () => {
  const store = new MemoryEvidenceStore();
  for (const id of [drowsyDragon.id, nginxProxy.id]) {
    const receipt = await receiptFor(id);
    const expected = imageReceiptMetadata(receipt);
    assert.ok(JSON.stringify(receipt).length > 2048);
    assert.deepEqual(await publishImageReceipt(store, receipt), expected);
    assert.deepEqual(await publishImageReceipt(store, receipt), expected);
    assert.deepEqual(await store.get(expected.key), receipt);
    await assert.rejects(
      publishImageReceipt(store, { ...receipt, scannedAt: "2026-10-01T12:00:00Z" }),
      { status: 409 },
    );
    assert.deepEqual(await store.get(expected.key), receipt);
  }
  assert.equal((await store.list("images/")).length, 2);
});

test("publication rejects invalid recipes, hashes, unknown demos and over-limit bodies", async () => {
  const receipt = await receiptFor();
  for (const invalid of [null, {}, { ...receipt, demoId: "sessions" }, { ...receipt, demoId: "__proto__" }])
    assert.throws(() => imageReceiptMetadata(invalid));
  const tampered = structuredClone(receipt);
  tampered.artifacts.inventory += "tar\t2.0\n";
  assert.throws(() => imageReceiptMetadata(tampered), /hash mismatch/);
  assert.throws(
    () => imageReceiptMetadata({ ...receipt, padding: "x".repeat(imageReceiptLimit) }),
    /publication limit/,
  );
  const drifted = structuredClone(receipt);
  drifted.artifacts.dockerfile += "EXPOSE 80\n";
  drifted.hashes.dockerfile = sha256(drifted.artifacts.dockerfile);
  assert.throws(() => imageReceiptMetadata(drifted), /recipe/);
});

test("blob writes set if-none-match and failures never become published evidence", async () => {
  const blob = new BlobEvidenceStore("testaccount", { getToken: async () => ({ token: "fixture" }) });
  let uploaded;
  blob.container = {
    getBlockBlobClient: () => ({
      uploadData: async (_data, options) => { uploaded = options; },
    }),
  };
  await blob.put("images/fixture", {}, { ifAbsent: true });
  assert.deepEqual(uploaded.conditions, { ifNoneMatch: "*" });
  await blob.put("runs/fixture", {});
  assert.equal(uploaded.conditions, undefined);
  const store = new MemoryEvidenceStore();
  const receipt = await receiptFor();
  store.put = async () => { throw Object.assign(new Error("forbidden"), { statusCode: 403 }); };
  await assert.rejects(publishImageReceipt(store, receipt), /forbidden/);
  const missing = new MemoryEvidenceStore();
  missing.get = async () => null;
  await assert.rejects(publishImageReceipt(missing, receipt), /readback/);
});

test("portal accepts large validated receipts only after session, origin and CSRF checks", async (t) => {
  const portal = await startPortal(t);
  const receipt = await receiptFor();
  const headers = { origin: config.origin, "content-type": "application/json" };
  const endpoint = `${portal.origin}/api/image-evidence`;
  const unauthenticated = await fetch(endpoint, {
    method: "POST", headers, body: JSON.stringify(receipt),
  });
  assert.equal(unauthenticated.status, 403);
  assert.equal((await portal.store.list("images/")).length, 0);
  const login = await fetch(`${portal.origin}/api/login`, {
    method: "POST", headers,
    body: JSON.stringify({ username: config.adminUsername, password: config.adminPassword }),
  });
  const cookie = login.headers.get("set-cookie").split(";")[0];
  const { csrf } = await login.json();
  for (const extra of [{}, { "x-csrf-token": "wrong" }, { "x-csrf-token": csrf, origin: "https://other.example" }]) {
    const denied = await fetch(endpoint, {
      method: "POST", headers: { ...headers, cookie, ...extra },
      body: JSON.stringify(receipt),
    });
    assert.equal(denied.status, 403);
  }
  const authenticated = { ...headers, cookie, "x-csrf-token": csrf };
  const uploaded = await fetch(endpoint, {
    method: "POST", headers: authenticated, body: JSON.stringify(receipt),
  });
  assert.equal(uploaded.status, 200);
  assert.deepEqual(await uploaded.json(), imageReceiptMetadata(receipt));
  const conflict = await fetch(endpoint, {
    method: "POST", headers: authenticated,
    body: JSON.stringify({ ...receipt, scannedAt: "2026-10-01T12:00:00Z" }),
  });
  assert.equal(conflict.status, 409);
  const invalid = await fetch(endpoint, {
    method: "POST", headers: authenticated, body: JSON.stringify({ demoId: "sessions" }),
  });
  assert.equal(invalid.status, 400);
  const oversized = await fetch(endpoint, {
    method: "POST", headers: authenticated,
    body: JSON.stringify({ padding: "x".repeat(imageReceiptLimit) }),
  });
  assert.equal(oversized.status, 413);
  assert.equal((await portal.store.list("images/")).length, 1);
});

test("portal client publishes both receipts, collects a scope-bound report and revokes its session", async (t) => {
  const portal = await startPortal(t);
  const receipts = await Promise.all([receiptFor(), receiptFor(nginxProxy.id)]);
  const report = await withPortalSession(config, null, async (client) => {
    for (const receipt of receipts)
      assert.deepEqual(await client.publish(receipt), imageReceiptMetadata(receipt));
    return client.report();
  }, portal.clientOptions);
  assert.equal(report.scope.subscriptionId, config.subscriptionId);
  assert.equal((await portal.store.list("images/")).length, 2);
  assert.equal(portal.requests.at(-1), "/api/logout");
  assert.ok((await portal.store.list("sessions/")).every((session) => session.revoked));
});

test("portal publication fails closed on audit failure and still revokes the CLI session", async (t) => {
  const portal = await startPortal(t);
  const receipt = await receiptFor();
  const put = portal.store.put.bind(portal.store);
  await assert.rejects(withPortalSession(config, null, async (client) => {
    portal.store.put = async (key, value, options) => {
      if (value.event === "image-receipt-publication")
        throw new Error("sensitive service error");
      return put(key, value, options);
    };
    await client.publish(receipt);
  }, portal.clientOptions), /HTTP 503/);
  assert.equal((await portal.store.list("images/")).length, 0);
  assert.ok((await portal.store.list("sessions/")).every((session) => session.revoked));
});

test("portal client rejects stale or wrong-scope reports and revokes failed sessions", async (t) => {
  for (const change of [
    (report) => { report.scope.subscriptionId = "wrong"; },
    (report) => { report.generatedAt = "2000-01-01T00:00:00Z"; },
    (report) => { report.nginxProxy.enabled = false; },
  ]) {
    await t.test("mismatched report", async (subtest) => {
      const portal = await startPortal(subtest, {
        reportProvider: async () => {
          const report = emptyReport(config, "live");
          change(report);
          return report;
        },
      });
      await assert.rejects(
        withPortalSession(config, null, (client) => client.report(), portal.clientOptions),
        /stale or does not match/,
      );
      assert.ok((await portal.store.list("sessions/")).every((session) => session.revoked));
    });
  }
});

test("portal client never follows credential redirects or reports returned secret bodies", async () => {
  const secrets = { getSecret: async (name) => ({
    value: name === "admin-username" ? config.adminUsername : config.adminPassword,
  }) };
  let calls = 0;
  await assert.rejects(withPortalSession(config, null, () => {}, {
    secrets,
    fetcher: async (_url, options) => {
      calls++;
      assert.equal(options.redirect, "error");
      return new Response("SENSITIVE", { status: 302, headers: { location: "https://foreign.example" } });
    },
  }), /HTTP 302/);
  assert.equal(calls, 1);
});

test("portal client rejects a mismatched receipt acknowledgement and revokes its session", async (t) => {
  const portal = await startPortal(t);
  const fetcher = portal.clientOptions.fetcher;
  await assert.rejects(withPortalSession(config, null, async (client) => {
    await client.publish(await receiptFor());
  }, {
    ...portal.clientOptions,
    fetcher: async (url, options) => {
      const response = await fetcher(url, options);
      if (url.endsWith("/api/image-evidence"))
        return Response.json({ ...await response.json(), imageDigest: `sha256:${"f".repeat(64)}` });
      return response;
    },
  }), /acknowledgement does not match/);
  assert.ok((await portal.store.list("sessions/")).every((session) => session.revoked));
});

test("read-only preview cannot publish image receipts", async (t) => {
  const portal = await startPortal(t, { preview: true });
  const response = await fetch(`${portal.origin}/api/image-evidence`, {
    method: "POST",
    headers: { origin: config.origin, "content-type": "application/json" },
    body: JSON.stringify(await receiptFor()),
  });
  assert.equal(response.status, 403);
  assert.equal((await portal.store.list("images/")).length, 0);
});
