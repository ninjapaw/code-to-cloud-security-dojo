import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createApp } from "../apps/control-portal/app.mjs";
import { MemoryEvidenceStore } from "../shared/evidence-store.mjs";
import { emptyReport } from "../shared/report.mjs";
import { runLabTest, readDojoHealth } from "../apps/control-portal/lab.mjs";

const config = {
  origin: "http://127.0.0.1",
  adminPassword: "a".repeat(64),
  sessionKey: "b".repeat(64),
  dojoHost: "dojo-123456789abc-app.azurewebsites.net",
  dojoName: "dojo-123456789abc-app",
  dojoResourceId: "/subscriptions/test/target",
  dojoDigest: `sha256:${"a".repeat(64)}`,
};
test("fixed private health probe refuses redirects and foreign targets", async () => {
  let requests = 0;
  const fetcher = async (url, options) => {
    requests++;
    assert.equal(url, `https://${config.dojoHost}/WebGoat/actuator/health`);
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "manual");
    return {
      status: requests === 1 ? 200 : 302,
      body: { cancel: async () => {} },
    };
  };
  assert.equal(await readDojoHealth(config, fetcher), true);
  assert.equal(await readDojoHealth(config, fetcher), false);
  await assert.rejects(
    readDojoHealth({ ...config, dojoHost: "169.254.169.254" }, fetcher),
    /Invalid fixed training target/,
  );
  assert.equal(requests, 2);
});
test("portal health checks the private Dojo without writing run evidence", async () => {
  const store = new MemoryEvidenceStore();
  let status = 200;
  let requests = 0;
  const app = createApp({
    config,
    store,
    reportProvider: async () => emptyReport(config),
    fetcher: async () => {
      requests++;
      return { status };
    },
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const url = `http://127.0.0.1:${server.address().port}/health/dojo`;
    const healthy = await fetch(url);
    assert.equal(healthy.status, 200);
    assert.deepEqual(await healthy.json(), { status: "healthy" });
    status = 302;
    const redirected = await fetch(url);
    assert.equal(redirected.status, 503);
    assert.deepEqual(await redirected.json(), { status: "unavailable" });
    assert.equal(requests, 2);
    assert.deepEqual(await store.list("runs/"), []);
  } finally {
    server.close();
  }
});
test("admin authorization, CSRF, logout revocation and fixed target boundary", async () => {
  const store = new MemoryEvidenceStore();
  let requests = 0;
  const app = createApp({
    config,
    store,
    reportProvider: async () => emptyReport(config),
    fetcher: async () => {
      requests++;
      return { status: 200 };
    },
  });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${origin}/api/report`)).status, 401);
    const headers = {
      origin: config.origin,
      "content-type": "application/json",
    };
    const malformed = await fetch(`${origin}/api/login`, {
      method: "POST",
      headers,
      body: "SECRET-test-marker-not-json",
    });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), { error: "Invalid request." });
    const oversized = await fetch(`${origin}/api/login`, {
      method: "POST",
      headers,
      body: JSON.stringify({ password: "x".repeat(3000) }),
    });
    assert.equal(oversized.status, 413);
    assert.deepEqual(await oversized.json(), {
      error: "Request body is too large.",
    });
    assert.equal(
      (
        await fetch(`${origin}/api/login`, {
          method: "POST",
          headers: { ...headers, origin: "https://other.example" },
          body: "{}",
        })
      ).status,
      403,
    );
    const login = await fetch(`${origin}/api/login`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        username: "admin",
        password: config.adminPassword,
      }),
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get("set-cookie").split(";")[0];
    const session = await login.json();
    assert.match(login.headers.get("set-cookie"), /HttpOnly/);
    assert.equal(
      (
        await fetch(`${origin}/api/tests/health`, {
          method: "POST",
          headers: { ...headers, cookie },
          body: JSON.stringify({ confirm: "authorized-training" }),
        })
      ).status,
      403,
    );
    const authenticated = { ...headers, cookie, "x-csrf-token": session.csrf };
    assert.equal(
      (
        await fetch(`${origin}/api/tests/health`, {
          method: "POST",
          headers: authenticated,
          body: JSON.stringify({
            confirm: "authorized-training",
            url: "http://169.254.169.254",
          }),
        })
      ).status,
      400,
    );
    const result = await fetch(`${origin}/api/tests/health`, {
      method: "POST",
      headers: authenticated,
      body: JSON.stringify({ confirm: "authorized-training" }),
    });
    assert.equal(result.status, 200);
    assert.equal(requests, 1);
    assert.equal((await store.list("runs/")).length, 1);
    await fetch(`${origin}/api/logout`, {
      method: "POST",
      headers: authenticated,
      body: "{}",
    });
    assert.equal(
      (await fetch(`${origin}/api/report`, { headers: { cookie } })).status,
      401,
    );
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
test("redirects are never followed and audit must precede network access", async () => {
  let requests = 0;
  const store = new MemoryEvidenceStore();
  const result = await runLabTest({
    id: "defender-validation",
    config,
    store,
    fetcher: async (_url, options) => {
      requests++;
      assert.equal(options.redirect, "manual");
      assert.equal((await store.list("runs/"))[0].state, "started");
      return { status: 302 };
    },
  });
  assert.equal(result.state, "redirect-not-followed");
  await assert.rejects(runLabTest({ id: "health", config, store }), /cooling/);
  const broken = new MemoryEvidenceStore();
  broken.put = async () => {
    throw new Error("Storage offline");
  };
  await assert.rejects(
    runLabTest({
      id: "health",
      config,
      store: broken,
      fetcher: async () => requests++,
    }),
    /Storage offline/,
  );
  assert.equal(requests, 1);
});
test("unresolved Key Vault references fail closed", () => {
  assert.throws(
    () =>
      createApp({
        config: {
          ...config,
          adminPassword:
            "@Microsoft.KeyVault(SecretUri=https://example/secrets/password)",
        },
      }),
    /credentials/,
  );
});
