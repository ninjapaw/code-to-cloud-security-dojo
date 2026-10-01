import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { names, validateConfig } from "../shared/config.mjs";
import {
  drowsyDragon,
  drowsyDragonRecipe,
  sha256,
  parseDragonInventory,
  summarizeDragonScan,
  summarizeDragonReceipt,
  drowsyDragonEvidenceKey,
} from "../shared/drowsy-dragon.mjs";
import {
  buildDrowsyDragon,
  readDragonReceipt,
} from "../scripts/lib/drowsy-dragon.mjs";
import {
  configHash,
  validateRelease,
  releaseParameters,
  requireReleaseCostApproval,
} from "../scripts/lib/lifecycle.mjs";
import { collectReport, emptyReport, reportHtml } from "../shared/report.mjs";
import { MemoryEvidenceStore } from "../shared/evidence-store.mjs";

const base = JSON.parse(
  await readFile(new URL("../config/deploy.config.json", import.meta.url)),
);
const config = { ...base, subscriptionId: "test", drowsyDragonEnabled: true };
const imageId = `sha256:${"a".repeat(64)}`;
const digest = `sha256:${"b".repeat(64)}`;
const inventory = "libc6:amd64\t1.0\nlibc-bin\t1.0\ntar\t1.0\nlibgcrypt20:amd64\t1.0\n";

function scanFixture() {
  return {
    SchemaVersion: 2,
    ArtifactType: "container_image",
    Metadata: { ImageID: imageId },
    Results: [{
      Target: "synthetic-debian-fixture",
      Type: "debian",
      Packages: drowsyDragon.packages.map((Name) => ({ Name, Version: "1.0" })),
      Vulnerabilities: [
        {
          VulnerabilityID: "TEST-DRAGON-0001",
          PkgName: "tar",
          Severity: "MEDIUM",
          InstalledVersion: "1.0",
          FixedVersion: "1.1",
        },
        {
          VulnerabilityID: "TEST-UNTRACKED-0002",
          PkgName: "untracked-package",
          Severity: "HIGH",
          InstalledVersion: "1.0",
        },
      ],
    }],
  };
}

function receiptFixture() {
  const artifacts = {
    dockerfile: drowsyDragonRecipe,
    inventory,
    scanJson: JSON.stringify(scanFixture()),
  };
  return {
    schemaVersion: 1,
    demoId: drowsyDragon.id,
    imageDigest: digest,
    imageId,
    baseImage: drowsyDragon.baseImage,
    sourceRevision: "c".repeat(40),
    scannedAt: "2026-09-30T12:00:00Z",
    hashes: {
      ...Object.fromEntries(Object.entries(artifacts).map(([key, value]) => [key, sha256(value)])),
      sarif: sha256("{}"),
    },
    artifacts,
  };
}

function releaseFixture(configuration) {
  const receipt = receiptFixture();
  return {
    schemaVersion: 1,
    configHash: configHash(configuration),
    source: {
      ...configuration.source,
      tree: "d".repeat(40),
      snapshotSha256: "e".repeat(64),
      files: 1,
    },
    images: {
      dojo: { digest, scanHash: "f".repeat(64) },
      portal: { digest, scanHash: "f".repeat(64) },
      ...(configuration.drowsyDragonEnabled ? {
        drowsyDragon: {
          repository: drowsyDragon.id,
          image: `${names(configuration).registry}.azurecr.io/drowsy-dragon:fixture`,
          digest,
          imageId,
          baseImage: drowsyDragon.baseImage,
          sourceRevision: receipt.sourceRevision,
          scannedAt: receipt.scannedAt,
          scanHash: receipt.hashes.sarif,
          scanPath: "fixture.sarif",
          scanJsonHash: receipt.hashes.scanJson,
          scanJsonPath: "fixture.json",
          inventoryHash: receipt.hashes.inventory,
          inventoryPath: "packages.txt",
          dockerfileHash: receipt.hashes.dockerfile,
        },
      } : {}),
    },
  };
}

test("recipe preserves the supplied digest, inventory command and sleeping entrypoint exactly", async () => {
  const recipe = await readFile(
    new URL("../apps/drowsy-dragon/Dockerfile", import.meta.url), "utf8",
  );
  assert.equal(recipe.replace(/\r\n/g, "\n"), drowsyDragonRecipe);
  assert.match(recipe, /@sha256:a04b53a72db39c248b8947109d1cce6718a7449b7828d85bdb1b8e1cc4e1b6ef/);
  assert.equal(drowsyDragon.platform, "linux/amd64");
});

test("demo is opt-in with strict booleans and backward-compatible missing configuration", () => {
  assert.equal(base.drowsyDragonEnabled, false);
  const legacy = { ...base };
  delete legacy.drowsyDragonEnabled;
  validateConfig(legacy, { offline: true });
  for (const value of ["false", "true", 0, 1, null, {}])
    assert.throws(
      () => validateConfig({ ...base, drowsyDragonEnabled: value }, { offline: true }),
      /must be a boolean/,
    );
  const report = emptyReport(base);
  assert.equal(report.drowsyDragon.state, "disabled");
  assert.equal(report.drowsyDragon.scanState, "not-collected");
  assert.match(reportHtml(report), /no clean result is implied/);
});

test("inventory requires all four packages, real versions and no duplicates", () => {
  assert.deepEqual(parseDragonInventory(inventory).map((pkg) => pkg.name), drowsyDragon.packages);
  for (const invalid of ["", "tar\t1.0\n", `${inventory}tar\t1.0\n`, inventory.replace("tar\t1.0", "tar\t")])
    assert.throws(() => parseDragonInventory(invalid), /inventory/);
});

test("scan summaries distinguish targeted packages, full-image findings and observed zero", () => {
  const packages = parseDragonInventory(inventory);
  const scan = scanFixture();
  const result = summarizeDragonScan(scan, imageId, packages);
  assert.equal(result.imageFindingCount, 2);
  assert.deepEqual(result.vulnerabilities.map((item) => item.id), ["TEST-DRAGON-0001"]);
  delete scan.Results[0].Vulnerabilities;
  assert.equal(summarizeDragonScan(scan, imageId, packages).vulnerabilities.length, 0);
  scan.Results[0].Packages.pop();
  assert.throws(() => summarizeDragonScan(scan, imageId, packages), /every tracked package/);
  assert.throws(() => summarizeDragonScan(scanFixture(), digest, packages), /another image/);
  assert.throws(() => summarizeDragonScan({}, imageId, packages), /incomplete/);
  const malformed = scanFixture();
  malformed.Results[0].Vulnerabilities = {};
  assert.throws(() => summarizeDragonScan(malformed, imageId, packages), /incomplete/);
});

test("receipt binds the deployed digest, scan hash, original artifacts and approved recipe", () => {
  const receipt = receiptFixture();
  assert.equal(summarizeDragonReceipt(receipt, digest, receipt.hashes.scanJson).packages.length, 4);
  assert.throws(() => summarizeDragonReceipt(receipt, imageId, receipt.hashes.scanJson), /deployed release/);
  assert.throws(() => drowsyDragonEvidenceKey("latest", receipt.hashes.scanJson), /image digest/);
  assert.throws(() => drowsyDragonEvidenceKey(digest, "../receipt"), /scan hash/);
  for (const key of ["dockerfile", "inventory", "scanJson"]) {
    const changed = structuredClone(receipt);
    changed.artifacts[key] += "tampered";
    assert.throws(() => summarizeDragonReceipt(changed, digest, receipt.hashes.scanJson), /hash mismatch/);
  }
  const changed = structuredClone(receipt);
  changed.artifacts.dockerfile += "EXPOSE 8080\n";
  changed.hashes.dockerfile = sha256(changed.artifacts.dockerfile);
  assert.throws(() => summarizeDragonReceipt(changed, digest, receipt.hashes.scanJson), /approved base and commands/);
});

test("release requires enabled demo evidence, unchanged provenance and separate ACI cost consent", () => {
  const release = releaseFixture(config);
  validateRelease(config, release);
  const parameters = releaseParameters(config, release);
  assert.equal(parameters.drowsyDragonEnabled, true);
  assert.equal(parameters.drowsyDragonDigest, digest);
  assert.equal(parameters.drowsyDragonScanHash, release.images.drowsyDragon.scanJsonHash);
  assert.equal(parameters.drowsyDragonName, names(config).drowsyDragon);
  const missing = structuredClone(release);
  delete missing.images.drowsyDragon;
  assert.throws(() => validateRelease(config, missing), /Missing digest or scan evidence/);
  for (const key of ["baseImage", "scanJsonHash", "inventoryHash", "dockerfileHash", "imageId", "sourceRevision", "scanJsonPath"]) {
    const invalid = structuredClone(release);
    delete invalid.images.drowsyDragon[key];
    assert.throws(() => validateRelease(config, invalid), /pinned provenance/);
  }
  const disabled = releaseFixture(base);
  assert.equal(releaseParameters(base, disabled).drowsyDragonDigest, "");
  validateRelease(base, disabled);
  disabled.images.drowsyDragon = release.images.drowsyDragon;
  assert.throws(() => validateRelease(base, disabled), /not enabled/);
  assert.throws(() => requireReleaseCostApproval(config), /--accept-costs/);
  assert.throws(() => requireReleaseCostApproval(config, "true"), /--accept-costs/);
  requireReleaseCostApproval(config, true);
  requireReleaseCostApproval(base);
});

test("builder captures isolated inventory and all-severity scans; tampered artifacts and scanner failures stop release", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-dragon-test-"));
  const calls = [];
  const execute = async (command, args) => {
    calls.push([command, args]);
    if (command === "git") return "c".repeat(40);
    if (command === "docker" && args[0] === "image") return imageId;
    if (command === "docker" && args[0] === "run") return inventory.trimEnd();
    if (command === "trivy") {
      const path = args[args.indexOf("--output") + 1];
      await writeFile(path, args[0] === "image" ? JSON.stringify(scanFixture()) : "{}");
    }
    return "";
  };
  try {
    const entry = await buildDrowsyDragon("drowsy-dragon:test", output, { execute });
    const build = calls.find(([command, args]) => command === "docker" && args[0] === "build")[1];
    assert.equal(build[build.indexOf("--platform") + 1], "linux/amd64");
    const inspect = calls.find(([command, args]) => command === "docker" && args[0] === "run")[1];
    assert.ok(inspect.includes("--read-only"));
    assert.equal(inspect[inspect.indexOf("--network") + 1], "none");
    assert.equal(inspect[inspect.indexOf("--entrypoint") + 1], "dpkg-query");
    assert.deepEqual(inspect.slice(-4), drowsyDragon.packages);
    const scan = calls.find(([command, args]) => command === "trivy" && args[0] === "image")[1];
    assert.equal(scan[scan.indexOf("--severity") + 1], "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL");
    assert.ok(scan.includes("--list-all-pkgs"));
    assert.equal(calls.some(([command, args]) => command === "az" || args[0] === "push"), false);
    const receipt = await readDragonReceipt({ ...entry, digest });
    assert.equal(receipt.imageDigest, digest);
    await writeFile(entry.inventoryPath, `${inventory}tampered`);
    await assert.rejects(readDragonReceipt({ ...entry, digest }), /inventory evidence hash mismatch/);
    await assert.rejects(
      buildDrowsyDragon("drowsy-dragon:test", join(output, "failed"), {
        execute: async (command, args) => {
          if (command === "trivy") throw new Error("scanner unavailable");
          return execute(command, args);
        },
      }),
      /scanner unavailable/,
    );
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

function cloudFixture(configuration = config) {
  const resourceNames = names(configuration);
  const scope = "/subscriptions/test";
  const group = `${scope}/resourceGroups/${configuration.resourceGroup}`;
  const target = `${group}/providers/Microsoft.ContainerInstance/containerGroups/${resourceNames.drowsyDragon}`;
  const receipt = receiptFixture();
  const instance = {
    id: target,
    tags: { "dojo.scanHash": receipt.hashes.scanJson },
    properties: {
      provisioningState: "Succeeded",
      instanceView: { state: "Running" },
      containers: [{
        name: "drowsy-dragon",
        properties: {
          image: `${resourceNames.registry}.azurecr.io/drowsy-dragon@${digest}`,
          instanceView: { currentState: { state: "Running" } },
        },
      }],
    },
  };
  const requests = [];
  const client = {
    scope,
    request: async (path, options) => {
      assert.equal(options, undefined, "collector must never write Azure");
      requests.push(path);
      if (path.includes("Microsoft.ContainerInstance")) return instance;
      if (path.includes("/pricings/")) {
        const name = path.split("/pricings/")[1].split("?")[0];
        return { properties: configuration.protection[name] };
      }
      return { properties: { linuxFxVersion: `DOCKER|registry/dojo@${digest}` } };
    },
    list: async (path) => {
      if (path.includes("/resources?"))
        return [{ id: target, name: resourceNames.drowsyDragon, type: "Microsoft.ContainerInstance/containerGroups" }];
      if (path.includes("/alerts?"))
        return [
          { name: "dragon-alert", properties: { resourceIdentifiers: [{ azureResourceId: target }] } },
          { name: "unrelated-alert", properties: { resourceIdentifiers: [{ azureResourceId: `${target}-unrelated` }] } },
        ];
      return [];
    },
  };
  return { client, instance, receipt, requests };
}

test("collector correlates actual ACI state, digest-bound package evidence and exact resource alerts", async () => {
  const fixture = cloudFixture();
  const store = new MemoryEvidenceStore();
  await store.put(drowsyDragonEvidenceKey(digest, fixture.receipt.hashes.scanJson), fixture.receipt);
  const report = await collectReport(config, fixture.client, [], store);
  assert.equal(report.drowsyDragon.state, "observed");
  assert.equal(report.drowsyDragon.scanState, "observed");
  assert.equal(report.drowsyDragon.packages.length, 4);
  assert.equal(report.drowsyDragon.vulnerabilities[0].id, "TEST-DRAGON-0001");
  assert.deepEqual(report.alerts.map((item) => item.id), ["dragon-alert"]);
  assert.match(report.release.drowsyDragonObservedImage, /drowsy-dragon@sha256:/);
  assert.match(reportHtml(report), /TEST-DRAGON-0001/);
  assert.match(reportHtml(report), /this is not a Defender assessment/);
  assert.equal(report.drowsyDragon.artifacts, undefined, "raw scanner output stays out of the portal report");
});

test("missing, unreadable and tampered scan receipts never become zero-vulnerability observations", async () => {
  const fixture = cloudFixture();
  const key = drowsyDragonEvidenceKey(digest, fixture.receipt.hashes.scanJson);
  const store = new MemoryEvidenceStore();
  const missing = await collectReport(config, fixture.client, [], store);
  assert.equal(missing.drowsyDragon.scanState, "pending");
  assert.match(reportHtml(missing), /no clean result is implied/);
  const broken = structuredClone(fixture.receipt);
  broken.artifacts.inventory += "changed";
  await store.put(key, broken);
  const tampered = await collectReport(config, fixture.client, [], store);
  assert.equal(tampered.drowsyDragon.scanState, "unknown");
  assert.equal(tampered.checks.find((item) => item.id === "Drowsy Dragon scan evidence").state, "unknown");
  const denied = await collectReport(config, fixture.client, [], {
    get: async () => { throw new Error("Evidence access denied"); },
  });
  assert.equal(denied.drowsyDragon.scanState, "unknown");
  assert.match(denied.checks.find((item) => item.id === "Drowsy Dragon scan evidence").detail, /access denied/);
});

test("runtime drift, wrong images and retained disabled instances are gaps, not healthy demos", async () => {
  for (const mutate of [
    (instance) => { instance.properties.ipAddress = { type: "Public", ip: "203.0.113.5" }; },
    (instance) => { instance.properties.containers[0].properties.ports = [{ port: 80 }]; },
    (instance) => { instance.properties.containers[0].properties.instanceView.currentState.state = "Terminated"; },
    (instance) => { instance.properties.containers[0].properties.image = `other.azurecr.io/drowsy-dragon@${digest}`; },
    (instance) => { instance.properties.containers.push({ name: "unapproved", properties: {} }); },
  ]) {
    const fixture = cloudFixture();
    mutate(fixture.instance);
    const report = await collectReport(config, fixture.client);
    assert.equal(report.drowsyDragon.state, "gap");
  }
  const disabled = { ...config, drowsyDragonEnabled: false };
  const retained = await collectReport(disabled, cloudFixture(disabled).client);
  assert.equal(retained.drowsyDragon.state, "retained");
  assert.equal(retained.checks.find((item) => item.id === "Drowsy Dragon runtime").state, "gap");
  const fixture = cloudFixture(disabled);
  fixture.client.list = async () => [];
  const unchanged = await collectReport(disabled, fixture.client);
  assert.equal(unchanged.drowsyDragon.state, "disabled");
  assert.equal(fixture.requests.some((path) => path.includes("Microsoft.ContainerInstance")), false);
  const wrongDigest = await collectReport(
    { ...config, drowsyDragonDigest: imageId },
    cloudFixture().client,
  );
  assert.equal(wrongDigest.drowsyDragon.state, "gap");
});

test("failed ACI readback stays unknown instead of substituting configured state", async () => {
  const fixture = cloudFixture();
  const request = fixture.client.request;
  fixture.client.request = async (path) => {
    if (path.includes("Microsoft.ContainerInstance"))
      throw new Error("Container read denied");
    return request(path);
  };
  const report = await collectReport(config, fixture.client);
  assert.equal(report.drowsyDragon.state, "unknown");
  assert.equal(report.drowsyDragon.scanState, "pending");
  assert.equal(report.drowsyDragon.observedImage, undefined);
  const check = report.checks.find((item) => item.id === "Drowsy Dragon runtime");
  assert.equal(check.state, "unknown");
  assert.match(check.detail, /Container read denied/);
});

test("ACI recipe is opt-in, digest-bound and pull-only, without ingress or workload overrides", async () => {
  const module = await readFile(new URL("../infra/modules/drowsy-dragon.bicep", import.meta.url), "utf8");
  const main = await readFile(new URL("../infra/main.bicep", import.meta.url), "utf8");
  assert.match(main, /param drowsyDragonEnabled bool = false/);
  assert.match(main, /if \(drowsyDragonEnabled\)/);
  assert.match(module, /Microsoft\.ContainerInstance\/containerGroups@2023-05-01/);
  assert.match(module, /drowsy-dragon@\$\{imageDigest\}/);
  assert.match(module, /7f951dda-4ed3-4680-a7ca-43fe172d538d/);
  assert.match(module, /identity: identity\.id/);
  assert.doesNotMatch(module, /\b(ipAddress|ports|command|environmentVariables|volumes)\s*:/);
  assert.doesNotMatch(module, /password|listKeys\(/);
});
