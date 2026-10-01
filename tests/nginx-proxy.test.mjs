import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm, cp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { names, validateConfig, booleanSetting, isLabHostname } from "../shared/config.mjs";
import { drowsyDragon } from "../shared/drowsy-dragon.mjs";
import {
  nginxProxy, nginxMode, validateNginxRuntime, summarizeNginxReceipt,
} from "../shared/nginx-proxy.mjs";
import { imageEvidenceKey, sha256 } from "../shared/image-evidence.mjs";
import { buildNginxProxy, readNginxReceipt, verifyNginxSource } from "../scripts/lib/nginx-proxy.mjs";
import {
  configHash, validateRelease, releaseParameters, requireReleaseCostApproval,
} from "../scripts/lib/lifecycle.mjs";
import { collectReport, emptyReport, reportHtml } from "../shared/report.mjs";
import { readNginxRuntime } from "../shared/nginx-report.mjs";
import { MemoryEvidenceStore } from "../shared/evidence-store.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const home = join(root, "apps", "nginx-proxy");
const base = JSON.parse(await readFile(join(root, "config", "deploy.config.json"), "utf8"));
const config = { ...base, subscriptionId: "test", nginxProxyEnabled: true };
const imageId = `sha256:${"a".repeat(64)}`;
const digest = `sha256:${"b".repeat(64)}`;
const recipe = await readFile(join(home, "upstream", "Dockerfile"), "utf8");
const sourceLock = await readFile(join(home, "source-lock.json"), "utf8");

function scanFixture(mode = "vulnerable") {
  const version = `${nginxMode(mode).version}-1~noble`;
  return {
    SchemaVersion: 2,
    ArtifactType: "container_image",
    Metadata: { ImageID: imageId },
    Results: [{
      Target: "synthetic-nginx-fixture",
      Type: "ubuntu",
      Packages: [{ Name: "nginx", Version: version }],
      Vulnerabilities: mode === "vulnerable" ? [{
        VulnerabilityID: nginxProxy.targetCve, PkgName: "nginx",
        InstalledVersion: version, FixedVersion: "1.30.4-1~noble", Severity: "HIGH",
      }] : [],
    }],
  };
}

function receiptFixture(mode = "vulnerable") {
  const artifacts = {
    dockerfile: recipe,
    sourceLock,
    inventory: `nginx\t${nginxMode(mode).version}-1~noble\n`,
    scanJson: JSON.stringify(scanFixture(mode)),
  };
  return {
    schemaVersion: 1, demoId: nginxProxy.id, mode, imageDigest: digest, imageId,
    sourceRevision: "c".repeat(40), scannedAt: "2026-09-30T12:00:00Z",
    artifacts,
    hashes: {
      ...Object.fromEntries(Object.entries(artifacts).map(([key, value]) => [key, sha256(value)])),
      sarif: sha256("{}"),
    },
  };
}

function runtimeFixture(mode = "vulnerable") {
  const expected = nginxMode(mode);
  return {
    runtime_verification: {
      nginx_binary_version: expected.version,
      nginx_package_version: `${expected.version}-1~noble`,
      scenario_config_state: expected.configState,
      map_regex_enabled: expected.mapRegexEnabled,
      vulnerability_detected: expected.mapRegexEnabled,
    },
  };
}

function releaseFixture(configuration) {
  const receipt = receiptFixture(configuration.nginxProxyMode);
  const common = {
    digest, imageId, sourceRevision: receipt.sourceRevision, scannedAt: receipt.scannedAt,
    scanPath: "scan.sarif", scanHash: receipt.hashes.sarif,
    scanJsonPath: "scan.json", scanJsonHash: receipt.hashes.scanJson,
    inventoryPath: "packages.txt", inventoryHash: receipt.hashes.inventory,
  };
  return {
    schemaVersion: 1, configHash: configHash(configuration),
    source: { ...configuration.source, tree: "d".repeat(40), snapshotSha256: "e".repeat(64), files: 1 },
    images: {
      dojo: { digest, scanHash: "f".repeat(64) },
      portal: { digest, scanHash: "f".repeat(64) },
      ...(configuration.drowsyDragonEnabled ? {
        drowsyDragon: {
          ...common, repository: drowsyDragon.id, baseImage: drowsyDragon.baseImage,
          image: `${names(configuration).registry}.azurecr.io/drowsy-dragon:test`,
          dockerfileHash: "f".repeat(64),
        },
      } : {}),
      ...(configuration.nginxProxyEnabled ? {
        nginxProxy: {
          ...common, repository: nginxProxy.id, mode: nginxMode(configuration.nginxProxyMode).mode,
          image: `${names(configuration).registry}.azurecr.io/nginx-proxy:test`,
          sourceLockPath: "source-lock.json", sourceLockHash: receipt.hashes.sourceLock,
          sourceSnapshotHash: nginxProxy.source.sha256, dockerfileHash: nginxProxy.dockerfileHash,
        },
      } : {}),
    },
  };
}

test("original eight-file source import, recipe and license match the reviewed pin", async () => {
  assert.equal((await verifyNginxSource()).sha256, nginxProxy.source.sha256);
  assert.equal(sha256(recipe), nginxProxy.dockerfileHash);
  assert.match(await readFile(join(home, "upstream", "LICENSE"), "utf8"), /MIT License/);
  const attributes = await readFile(join(root, ".gitattributes"), "utf8");
  assert.match(attributes, /apps\/nginx-proxy\/upstream\/\*\* -text/);
  const temp = await mkdtemp(join(tmpdir(), "dojo-nginx-source-"));
  try {
    await cp(home, temp, { recursive: true });
    await writeFile(join(temp, "upstream", "nginx.conf"), "changed");
    await assert.rejects(verifyNginxSource(temp), /snapshot has local changes/);
    const manifest = JSON.parse(sourceLock);
    manifest.revision = "f".repeat(40);
    await writeFile(join(temp, "source-lock.json"), JSON.stringify(manifest));
    await assert.rejects(verifyNginxSource(temp), /reviewed upstream pin/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("NGINX mode and feature flags are strict, default-off and compatible with legacy configs", () => {
  assert.equal(base.nginxProxyEnabled, false);
  const legacy = { ...base };
  delete legacy.nginxProxyEnabled;
  delete legacy.nginxProxyMode;
  validateConfig(legacy, { offline: true });
  assert.equal(nginxMode().version, "1.30.3");
  assert.equal(nginxMode("remediated").version, "1.30.4");
  for (const mode of ["patched", "", null, true])
    assert.throws(() => validateConfig({ ...base, nginxProxyMode: mode }, { offline: true }), /nginxProxyMode/);
  for (const enabled of ["true", "false", null, 1])
    assert.throws(() => validateConfig({ ...base, nginxProxyEnabled: enabled }, { offline: true }), /boolean/);
  for (const value of ["true", "True", "TRUE"])
    assert.equal(booleanSetting(value, "DEMO"), true);
  for (const value of ["false", "False", "FALSE"])
    assert.equal(booleanSetting(value, "DEMO"), false);
  assert.equal(booleanSetting(undefined, "DEMO"), false);
  assert.equal(booleanSetting(undefined, "DEMO", true), true);
  for (const value of ["yes", " true ", "", null, 1])
    assert.throws(() => booleanSetting(value, "DEMO"), /must be true or false/);
});

test("all optional-image combinations coexist without changing the default two-image release", () => {
  for (const drowsyDragonEnabled of [false, true]) {
    for (const nginxProxyEnabled of [false, true]) {
      const selected = { ...base, drowsyDragonEnabled, nginxProxyEnabled };
      const release = releaseFixture(selected);
      validateRelease(selected, release);
      assert.equal(Object.keys(release.images).length, 2 + Number(drowsyDragonEnabled) + Number(nginxProxyEnabled));
      const parameters = releaseParameters(selected, release);
      assert.equal(parameters.nginxProxyEnabled, nginxProxyEnabled);
      assert.equal(parameters.nginxProxyDigest, nginxProxyEnabled ? digest : "");
      assert.equal(parameters.nginxProxyName, names(selected).nginxProxy);
      assert.equal(parameters.drowsyDragonEnabled, drowsyDragonEnabled);
      if (drowsyDragonEnabled || nginxProxyEnabled)
        assert.throws(() => requireReleaseCostApproval(selected), /--accept-costs/);
      else requireReleaseCostApproval(selected);
      requireReleaseCostApproval(selected, true);
    }
  }
  const release = releaseFixture(config);
  for (const key of ["sourceSnapshotHash", "sourceLockHash", "sourceLockPath", "dockerfileHash", "imageId", "scanJsonHash"]) {
    const changed = structuredClone(release);
    delete changed.images.nginxProxy[key];
    assert.throws(() => validateRelease(config, changed), /approved mode, source pin/);
  }
  const changedMode = structuredClone(release);
  changedMode.images.nginxProxy.mode = "remediated";
  assert.throws(() => validateRelease(config, changedMode), /approved mode/);
  const disabled = releaseFixture(base);
  disabled.images.nginxProxy = release.images.nginxProxy;
  assert.throws(() => validateRelease(base, disabled), /not enabled/);
  assert.notEqual(
    imageEvidenceKey("nginx-proxy", digest, "f".repeat(64)),
    imageEvidenceKey("drowsy-dragon", digest, "f".repeat(64)),
  );
});

test("both optional demos can be planned offline without tools or Azure writes", async () => {
  const temp = await mkdtemp(join(tmpdir(), "dojo-nginx-plan-"));
  try {
    const path = join(temp, "config.json");
    await writeFile(path, JSON.stringify({
      ...base, drowsyDragonEnabled: true, nginxProxyEnabled: true, nginxProxyMode: "remediated",
    }));
    const result = spawnSync(process.execPath, [join(root, "scripts", "deploy.mjs"), "deploy", "--audit"], {
      cwd: temp, encoding: "utf8", env: { ...process.env, DOJO_CONFIG: path, PATH: "" },
    });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.audit, true);
    assert.equal(plan.drowsyDragon.enabled, true);
    assert.equal(plan.nginxProxy.enabled, true);
    assert.equal(plan.nginxProxy.version, "1.30.4");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("NGINX receipts distinguish package inventory, target association and incomplete/tampered evidence", () => {
  for (const mode of ["vulnerable", "remediated"]) {
    const receipt = receiptFixture(mode);
    const summary = summarizeNginxReceipt(receipt, digest, receipt.hashes.scanJson);
    assert.equal(summary.targetFindingObserved, mode === "vulnerable");
    assert.equal(summary.mode, mode);
    assert.equal(summary.upstream.revision, nginxProxy.source.revision);
  }
  const valid = receiptFixture();
  const bad = structuredClone(valid);
  bad.artifacts.sourceLock = sourceLock.replace(nginxProxy.source.revision, "f".repeat(40));
  bad.hashes.sourceLock = sha256(bad.artifacts.sourceLock);
  assert.throws(() => summarizeNginxReceipt(bad, digest, bad.hashes.scanJson), /upstream pin/);
  const wrongRecipe = structuredClone(valid);
  wrongRecipe.artifacts.dockerfile += "\nEXPOSE 9000\n";
  wrongRecipe.hashes.dockerfile = sha256(wrongRecipe.artifacts.dockerfile);
  assert.throws(() => summarizeNginxReceipt(wrongRecipe, digest, wrongRecipe.hashes.scanJson), /recipe/);
  const wrongMode = structuredClone(valid);
  wrongMode.mode = "remediated";
  assert.throws(() => summarizeNginxReceipt(wrongMode, digest, wrongMode.hashes.scanJson), /inventory/);
  const incomplete = structuredClone(valid);
  const scan = JSON.parse(incomplete.artifacts.scanJson);
  scan.Results[0].Packages = [];
  incomplete.artifacts.scanJson = JSON.stringify(scan);
  incomplete.hashes.scanJson = sha256(incomplete.artifacts.scanJson);
  assert.throws(() => summarizeNginxReceipt(incomplete, digest, incomplete.hashes.scanJson), /every tracked package/);
});

test("both build modes preserve upstream source and capture isolated inventory/full scans without deploying", async () => {
  const temp = await mkdtemp(join(tmpdir(), "dojo-nginx-build-"));
  try {
    for (const mode of ["vulnerable", "remediated"]) {
      const calls = [];
      const execute = async (command, args) => {
        calls.push([command, args]);
        if (command === "git") return "c".repeat(40);
        if (command === "docker" && args[0] === "image") return imageId;
        if (command === "docker" && args[0] === "run") return receiptFixture(mode).artifacts.inventory.trimEnd();
        if (command === "trivy")
          await writeFile(args[args.indexOf("--output") + 1], args[0] === "image" ? JSON.stringify(scanFixture(mode)) : "{}");
        return "";
      };
      const entry = await buildNginxProxy(`nginx-proxy:${mode}`, join(temp, mode), mode, { execute });
      const build = calls.find(([command, args]) => command === "docker" && args[0] === "build")[1];
      assert.ok(build.includes(`NGINX_VERSION=${nginxMode(mode).version}`));
      assert.ok(build.includes(`VULNERABILITY_STATUS=${mode}`));
      assert.ok(build.includes(`security.repro.version=${nginxMode(mode).version}`));
      const inventory = calls.find(([command, args]) => command === "docker" && args[0] === "run")[1];
      assert.equal(inventory[inventory.indexOf("--entrypoint") + 1], "dpkg-query");
      assert.equal(inventory[inventory.indexOf("--network") + 1], "none");
      assert.deepEqual(inventory.slice(-2), ["-W", "nginx"]);
      assert.equal(calls.some(([command, args]) => command === "az" || args[0] === "push"), false);
      assert.equal((await readNginxReceipt({ ...entry, digest })).mode, mode);
      await writeFile(entry.scanPath, "changed");
      await assert.rejects(readNginxReceipt({ ...entry, digest }), /SARIF evidence hash mismatch/);
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test("runtime verification requires raw startup measurements, never the legacy configured badge", () => {
  for (const mode of ["vulnerable", "remediated"])
    assert.equal(validateNginxRuntime(runtimeFixture(mode), mode).matchesExpectedMode, true);
  assert.equal(validateNginxRuntime(runtimeFixture(), "remediated").matchesExpectedMode, false);
  assert.throws(() => validateNginxRuntime({
    nginx_version: "1.30.3", vulnerability: { status: "vulnerable", detected: true },
    runtime_verification: { nginx_binary_version: null, map_regex_enabled: false, vulnerability_detected: null },
  }, "vulnerable"), /configured status is not proof/);
  const contradictory = runtimeFixture();
  contradictory.runtime_verification.nginx_package_version = "1.30.4-1~noble";
  assert.equal(validateNginxRuntime(contradictory, "vulnerable").matchesExpectedMode, false);
});

test("private runtime collection binds the exact host/path, refuses redirects and enforces 64 KiB", async () => {
  const name = names(config).nginxProxy;
  const host = `${name}.azurewebsites.net`;
  assert.equal(isLabHostname(host, name), true);
  assert.equal(isLabHostname(host, names(config).dojo), false);
  let calls = 0;
  const fetcher = async (url, options) => {
    calls++;
    assert.equal(url, `https://${host}/api/status`);
    assert.equal(options.redirect, "error");
    assert.ok(options.signal instanceof AbortSignal);
    return Response.json(runtimeFixture());
  };
  assert.equal((await readNginxRuntime(host, name, "vulnerable", fetcher)).matchesExpectedMode, true);
  for (const forbidden of ["169.254.169.254", `${host}.attacker.example`, `${names(config).dojo}.azurewebsites.net`])
    await assert.rejects(readNginxRuntime(forbidden, name, "vulnerable", fetcher), /outside/);
  assert.equal(calls, 1);
  await assert.rejects(readNginxRuntime(host, name, "vulnerable", async () => Response.redirect("https://example.com")), /HTTP 302/);
  await assert.rejects(readNginxRuntime(host, name, "vulnerable", async () => new Response("<html>")), /did not return JSON/);
  const json = JSON.stringify(runtimeFixture());
  const body = json + " ".repeat(65536 - Buffer.byteLength(json));
  const response = (text) => new Response(text, { headers: { "content-type": "application/json" } });
  assert.equal((await readNginxRuntime(host, name, "vulnerable", async () => response(body))).matchesExpectedMode, true);
  await assert.rejects(readNginxRuntime(host, name, "vulnerable", async () => response(`${body} `)), /64 KiB/);
});

function cloudFixture(configuration = config) {
  const resourceNames = names(configuration);
  const scope = "/subscriptions/test";
  const group = `${scope}/resourceGroups/${configuration.resourceGroup}`;
  const target = `${group}/providers/Microsoft.Web/sites/${resourceNames.nginxProxy}`;
  const receipt = receiptFixture(configuration.nginxProxyMode);
  const resources = [{ id: target, name: resourceNames.nginxProxy, type: "Microsoft.Web/sites" }];
  const site = {
    tags: { "dojo.scanHash": receipt.hashes.scanJson, "dojo.mode": nginxMode(configuration.nginxProxyMode).mode },
    properties: {
      state: "Running", publicNetworkAccess: "Disabled",
      defaultHostName: `${resourceNames.nginxProxy}.azurewebsites.net`,
    },
  };
  const requests = [];
  const client = {
    scope,
    request: async (path, options) => {
      assert.equal(options, undefined, "collection must not write Azure");
      requests.push(path);
      if (path.startsWith(`${target}?`)) return site;
      if (path.startsWith(`${target}/config/web`))
        return { properties: { linuxFxVersion: `DOCKER|${resourceNames.registry}.azurecr.io/nginx-proxy@${digest}` } };
      if (path.includes("/pricings/")) {
        const name = path.split("/pricings/")[1].split("?")[0];
        return { properties: configuration.protection[name] };
      }
      return { properties: { linuxFxVersion: `DOCKER|registry/dojo@${digest}` } };
    },
    list: async (path) => {
      if (path.includes("/resources?")) return resources;
      if (path.includes("/alerts?")) return [
        { name: "nginx-alert", properties: { resourceIdentifiers: [{ azureResourceId: target }] } },
        { name: "unrelated-alert", properties: { resourceIdentifiers: [{ azureResourceId: `${target}-other` }] } },
      ];
      return [];
    },
  };
  return { client, resources, requests, site, receipt, target, group };
}

test("collector keeps deployment, startup measurements, target-CVE scans and scoped alerts separate", async () => {
  for (const mode of ["vulnerable", "remediated"]) {
    const selected = { ...config, nginxProxyMode: mode };
    const fixture = cloudFixture(selected);
    const store = new MemoryEvidenceStore();
    await store.put(imageEvidenceKey(nginxProxy.id, digest, fixture.receipt.hashes.scanJson), fixture.receipt);
    const report = await collectReport(selected, fixture.client, [], store, {
      fetcher: async () => Response.json(runtimeFixture(mode)),
    });
    assert.equal(report.nginxProxy.state, "observed");
    assert.equal(report.nginxProxy.runtimeEvidenceState, "observed");
    assert.equal(report.nginxProxy.scanState, "observed");
    assert.equal(report.nginxProxy.targetFindingObserved, mode === "vulnerable");
    assert.equal(report.nginxProxy.runtime.mapRegexEnabled, mode === "vulnerable");
    assert.deepEqual(report.alerts.map((item) => item.id), ["nginx-alert"]);
    assert.match(report.release.nginxProxyObservedImage, /nginx-proxy@sha256:/);
    assert.match(reportHtml(report), /NGINX Proxy/);
    assert.match(reportHtml(report), /CVE-2026-42533/);
    assert.equal(report.nginxProxy.artifacts, undefined);
  }
});

test("missing scans, failed private access, legacy fallbacks and receipt drift never become success", async () => {
  const fixture = cloudFixture();
  const store = new MemoryEvidenceStore();
  const missing = await collectReport(config, fixture.client, [], store, {
    fetcher: async () => { throw new Error("Private DNS unavailable"); },
  });
  assert.equal(missing.nginxProxy.runtimeEvidenceState, "unknown");
  assert.equal(missing.nginxProxy.scanState, "pending");
  assert.equal(missing.nginxProxy.targetFindingObserved, undefined);
  assert.match(reportHtml(missing), /not collected/);
  const wrong = structuredClone(fixture.receipt);
  wrong.mode = "remediated";
  await store.put(imageEvidenceKey(nginxProxy.id, digest, wrong.hashes.scanJson), wrong);
  const drift = await collectReport(config, fixture.client, [], store, {
    fetcher: async () => Response.json({ vulnerability: { status: "vulnerable", detected: true } }),
  });
  assert.equal(drift.nginxProxy.scanState, "unknown");
  assert.equal(drift.nginxProxy.runtimeEvidenceState, "unknown");
  fixture.site.properties.publicNetworkAccess = "Enabled";
  const publicSite = await collectReport(config, fixture.client, [], store, {
    fetcher: async () => Response.json(runtimeFixture()),
  });
  assert.equal(publicSite.nginxProxy.state, "gap");
});

test("disabled NGINX performs no reads unless remnants exist, including a plan left before deployment", async () => {
  const selected = { ...config, nginxProxyEnabled: false };
  const fixture = cloudFixture(selected);
  fixture.resources.length = 0;
  const off = await collectReport(selected, fixture.client);
  assert.equal(off.nginxProxy.state, "disabled");
  assert.equal(fixture.requests.some((path) => path.startsWith(fixture.target)), false);
  fixture.resources.push({
    id: `${fixture.group}/providers/Microsoft.Web/serverfarms/${names(selected).nginxProxy}-plan`,
    type: "Microsoft.Web/serverfarms",
  });
  const retained = await collectReport(selected, fixture.client);
  assert.equal(retained.nginxProxy.state, "retained");
  assert.equal(retained.checks.find((item) => item.id === "NGINX Proxy retained resources").state, "gap");
  assert.equal(fixture.requests.some((path) => path.startsWith(fixture.target)), false);
  assert.equal(emptyReport(base).nginxProxy.scanState, "not-collected");
});
