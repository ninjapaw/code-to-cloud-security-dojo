import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { npmRegistry } from "../scripts/lib/image-build.mjs";
import { nginxRegistryRecipe, verifyNginxSource } from "../scripts/lib/nginx-proxy.mjs";
import { nginxProxy } from "../shared/nginx-proxy.mjs";
import { sha256 } from "../shared/image-evidence.mjs";

test("container npm registry inherits native npm configuration and honors explicit settings", async () => {
  const calls = [];
  assert.equal(await npmRegistry({}, (command, args) => {
    calls.push([command, args]);
    return "https://user.example.org/npm/";
  }), "https://user.example.org/npm/");
  assert.deepEqual(calls, [["npm", ["config", "get", "registry"]]]);
  const noProbe = () => { throw new Error("Explicit selection must not query another registry"); };
  assert.equal(await npmRegistry({ npm_config_registry: "https://example.org/npm/" }, noProbe), "https://example.org/npm/");
  assert.equal(await npmRegistry({ NPM_CONFIG_REGISTRY: "https://example.org/npm/" }, noProbe), "https://example.org/npm/");
  assert.equal(await npmRegistry({
    NPM_REGISTRY: "https://example.org/custom/",
    npm_config_registry: "https://example.org/npm/",
  }, noProbe), "https://example.org/custom/");
  const credentialRegistry = new URL("https://example.org");
  credentialRegistry.username = "test-user";
  credentialRegistry.password = "test-only";
  for (const value of ["", "invalid", "http://example.org", credentialRegistry.href,
    "https://example.org/?token=x", "https://example.org/#fragment", " https://example.org/"])
    await assert.rejects(npmRegistry({ NPM_REGISTRY: value }), /absolute HTTPS registry/);
  await assert.rejects(npmRegistry({}, () => { throw new Error("npm configuration unavailable"); }), /configuration unavailable/);
});

test("workflows only select a registry when an Actions variable is explicitly configured", async () => {
  for (const name of ["dojo", "deploy", "image-experiments"]) {
    const workflow = await readFile(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8");
    const installs = workflow.split(/      - name: Install dependencies\r?\n/);
    assert.ok(installs.length > 1);
    for (const before of installs.slice(0, -1)) {
      const step = before.slice(before.lastIndexOf("      - name:"));
      assert.match(step, /Use optional npm registry/);
      assert.ok(step.includes("if: vars.NPM_REGISTRY != ''"));
      assert.ok(step.includes("NPM_REGISTRY: ${{ vars.NPM_REGISTRY }}"));
      assert.ok(step.includes('echo "npm_config_registry=$NPM_REGISTRY" >> "$GITHUB_ENV"'));
    }
    assert.doesNotMatch(workflow, /vars\.NPM_REGISTRY \|\||npm config set registry/);
    assert.equal((workflow.match(/run: npm ci/g) ?? []).length, installs.length - 1);
  }
});

test("owned Docker recipes have no registry default and wrappers forward the user's selection", async () => {
  for (const name of ["apps/control-portal/Dockerfile", "scripts/Dockerfile.secret-bootstrap"]) {
    const recipe = await readFile(new URL(`../${name}`, import.meta.url), "utf8");
    assert.match(recipe, /^ARG NPM_REGISTRY\r?$/m);
    assert.match(recipe, /export npm_config_registry="\$\{NPM_REGISTRY\}"/);
    assert.doesNotMatch(recipe, /registry\.npmjs\.org|packagefeedproxy|npm config set registry/);
  }
  const core = await readFile(new URL("../scripts/lib/image-build.mjs", import.meta.url), "utf8");
  const nginx = await readFile(new URL("../scripts/lib/nginx-proxy.mjs", import.meta.url), "utf8");
  assert.ok(core.includes('`NPM_REGISTRY=${await npmRegistry(process.env, execute)}`'));
  assert.ok(nginx.includes('`NPM_REGISTRY_URL=${await npmRegistry(process.env, execute)}`'));
  assert.ok(nginx.includes('"NPM_USE_MIRROR=true"'));
});

test("the derived upstream npm recipe removes download pins without changing source, versions or integrity", async () => {
  const before = await verifyNginxSource();
  const recipe = nginxRegistryRecipe(await readFile(new URL("../apps/nginx-proxy/upstream/Dockerfile", import.meta.url), "utf8"));
  assert.match(recipe, /^ARG NPM_REGISTRY_URL\r?$/m);
  assert.doesNotMatch(recipe, /^ARG NPM_REGISTRY_URL=/m);
  assert.equal(sha256(recipe), nginxProxy.registryDockerfileHash);
  assert.equal(sha256(recipe.replace(/\r\n/g, "\n")), nginxProxy.registryDockerfileHash);
  const normalization = /^RUN node -e '(.+)'$/m.exec(recipe)?.[1];
  assert.ok(normalization);
  const temporary = await mkdtemp(join(tmpdir(), "dojo-lock-registry-"));
  try {
    const original = JSON.parse(await readFile(new URL("../apps/nginx-proxy/upstream/package-lock.json", import.meta.url), "utf8"));
    const expected = structuredClone(original);
    for (const entry of Object.values(expected.packages))
      if (!entry.link && /^https?:/.test(entry.resolved || "")) delete entry.resolved;
    await writeFile(join(temporary, "package-lock.json"), JSON.stringify(original));
    execFileSync(process.execPath, ["-e", normalization], { cwd: temporary });
    assert.deepEqual(JSON.parse(await readFile(join(temporary, "package-lock.json"), "utf8")), expected);
    assert.deepEqual(await verifyNginxSource(), before);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
