import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { workflowConfig } from "../scripts/workflow-config.mjs";
import { configHash } from "../scripts/lib/lifecycle.mjs";

const base = JSON.parse(await readFile(
  new URL("../config/deploy.config.json", import.meta.url), "utf8",
));
const environment = {
  DOJO_TENANT_ID: "11111111-1111-4111-8111-111111111111",
  DOJO_SUBSCRIPTION_ID: "22222222-2222-4222-8222-222222222222",
  DOJO_RESOURCE_GROUP: "workflow-test",
  DOJO_LOCATION: "centralus",
  DOJO_OPERATOR_OBJECT_ID: "33333333-3333-4333-8333-333333333333",
  DOJO_ADMIN_CIDR: "203.0.113.10/32",
};

test("workflow configuration preserves committed image and network choices when variables are absent", () => {
  const defaults = workflowConfig(base, environment);
  assert.equal(defaults.drowsyDragonEnabled, false);
  assert.equal(defaults.nginxProxyEnabled, false);
  const selected = {
    ...base, drowsyDragonEnabled: true, nginxProxyEnabled: true,
    nginxProxyMode: "remediated", evidencePublicAccess: false,
    dojoPublicAccess: false,
  };
  const result = workflowConfig(selected, {
    ...environment,
    DOJO_DROWSY_DRAGON_ENABLED: "",
    DOJO_NGINX_PROXY_ENABLED: "",
    DOJO_NGINX_PROXY_MODE: "",
    DOJO_EVIDENCE_PUBLIC_ACCESS: "",
  });
  assert.equal(result.drowsyDragonEnabled, true);
  assert.equal(result.nginxProxyEnabled, true);
  assert.equal(result.nginxProxyMode, "remediated");
  assert.equal(result.evidencePublicAccess, false);
  assert.equal(result.dojoPublicAccess, false);
  assert.equal(selected.subscriptionId, base.subscriptionId);
  assert.equal(result.subscriptionId, environment.DOJO_SUBSCRIPTION_ID);
});

test("protected variables select every optional-image combination with configuration-bound releases", () => {
  const hashes = new Set();
  for (const dragon of [false, true]) {
    for (const nginx of [false, true]) {
      for (const mode of ["vulnerable", "remediated"]) {
        const result = workflowConfig(base, {
          ...environment,
          DOJO_DROWSY_DRAGON_ENABLED: String(dragon),
          DOJO_NGINX_PROXY_ENABLED: String(nginx),
          DOJO_NGINX_PROXY_MODE: mode,
          DOJO_EVIDENCE_PUBLIC_ACCESS: "false",
        });
        assert.equal(result.drowsyDragonEnabled, dragon);
        assert.equal(result.nginxProxyEnabled, nginx);
        assert.equal(result.nginxProxyMode, mode);
        assert.equal(result.evidencePublicAccess, false);
        assert.equal(result.adminCidr, environment.DOJO_ADMIN_CIDR);
        hashes.add(configHash(result));
      }
    }
  }
  assert.equal(hashes.size, 8);
});

test("invalid feature flags and missing target fields fail rather than disabling images silently", () => {
  for (const flag of ["DOJO_DROWSY_DRAGON_ENABLED", "DOJO_NGINX_PROXY_ENABLED", "DOJO_EVIDENCE_PUBLIC_ACCESS"]) {
    for (const value of ["yes", "0", "1", "null", " false ", null, 1]) {
      assert.throws(() => workflowConfig(base, { ...environment, [flag]: value }), /must be true or false/);
    }
  }
  assert.throws(
    () => workflowConfig(base, { ...environment, DOJO_NGINX_PROXY_MODE: "latest" }),
    /nginxProxyMode/,
  );
  assert.throws(() => workflowConfig(base, {}), /tenantId/);
});

test("workflow CLI writes a private configuration with NGINX enabled and refuses overwrite", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dojo-workflow-config-"));
  const target = join(directory, "workflow.json");
  const script = fileURLToPath(new URL("../scripts/workflow-config.mjs", import.meta.url));
  try {
    const env = {
      ...process.env,
      ...environment,
      DOJO_DROWSY_DRAGON_ENABLED: "true",
      DOJO_NGINX_PROXY_ENABLED: "true",
      DOJO_NGINX_PROXY_MODE: "vulnerable",
      DOJO_EVIDENCE_PUBLIC_ACCESS: "false",
    };
    const result = spawnSync(process.execPath, [script, target], { env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const text = await readFile(target, "utf8");
    const config = JSON.parse(text);
    assert.equal(config.nginxProxyEnabled, true);
    assert.equal(config.drowsyDragonEnabled, true);
    assert.equal(config.evidencePublicAccess, false);
    if (process.platform !== "win32")
      assert.equal((await stat(target)).mode & 0o777, 0o600);
    const overwrite = spawnSync(process.execPath, [script, target], { env, encoding: "utf8" });
    assert.notEqual(overwrite.status, 0);
    assert.equal(await readFile(target, "utf8"), text);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deployment workflow forwards protected feature choices and the private portal transport", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8",
  );
  for (const variable of [
    "DOJO_DROWSY_DRAGON_ENABLED", "DOJO_NGINX_PROXY_ENABLED",
    "DOJO_NGINX_PROXY_MODE", "DOJO_EVIDENCE_PUBLIC_ACCESS", "DOJO_VIA_PORTAL",
  ])
    assert.ok(workflow.includes(`${variable}: \${{ vars.${variable} }}`), variable);
  assert.match(workflow, /node scripts\/workflow-config\.mjs "\$config_path"/);
  assert.doesNotMatch(workflow, /\.(?:drowsyDragonEnabled|nginxProxyEnabled) = false/);
  assert.match(workflow, /true\) portal_args\+=\(--via-portal\)/);
  assert.match(workflow, /verify\|report\)[\s\S]*?scripts\/deploy\.mjs "\$OPERATION" "\$\{portal_args\[@\]\}"/);
  assert.match(workflow, /deploy_args\+=\("\$\{portal_args\[@\]\}"\)/);
  assert.match(workflow, /if \[\[ "\$ACCEPT_COSTS" == "true" \]\]; then deploy_args\+=\(--accept-costs\)/);
});
