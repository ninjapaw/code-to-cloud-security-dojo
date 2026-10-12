import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { names } from "../shared/config.mjs";
import { buildCoreImage, imageBaseArguments, resolveLatestBaseImage } from "../scripts/lib/image-build.mjs";
import { publishImageArchive, sourceArchiveTags } from "../scripts/lib/image-archive.mjs";
import { registryFixture } from "./fixtures/image-registry.mjs";

const base = JSON.parse(await readFile(new URL("../config/deploy.config.json", import.meta.url), "utf8"));
const config = { ...base, subscriptionId: "test" };
const imageId = `sha256:${"a".repeat(64)}`;
const imageDigest = `sha256:${"c".repeat(64)}`;
const sourceDigest = `sha256:${"b".repeat(64)}`;

function builder(calls = [], selectedDigest = sourceDigest) {
  return async (command, args) => {
    calls.push([command, args]);
    if (command === "git") return "d".repeat(40);
    if (command === "docker" && args[0] === "buildx")
      return JSON.stringify({ digest: args[3].includes("@") ? args[3].split("@")[1] : selectedDigest });
    if (command === "docker" && args[0] === "image") return imageId;
    if (command === "trivy")
      await writeFile(args[args.indexOf("--output") + 1], '{"version":"2.1.0","runs":[]}');
    return "";
  };
}

async function portalEntry(output, registry, testBuild = false) {
  const repository = names(config).portal;
  return buildCoreImage("portal", `${names(config).registry}.azurecr.io/${repository}:${testBuild ? "test-fixture" : "latest"}`, output, {
    ...registry, latest: true, repository, log: () => {},
    ...(testBuild ? { baseOverrides: { RUNTIME_IMAGE: sourceDigest, BUILD_IMAGE: "latest" } } : {}),
  });
}

test("archives contain full source hashes, full image digest tags, protected scan companions and a mutable latest tag", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-archive-"));
  const calls = [];
  const logs = [];
  const registry = registryFixture(config, builder(calls), { imageId, digest: imageDigest });
  try {
    const entry = await portalEntry(output, registry);
    const published = await publishImageArchive(config, entry, output, { ...registry, promoteLatest: true, log: (line) => logs.push(line) });
    assert.equal(published.digest, imageDigest);
    assert.equal(published.archiveTags.length, 4);
    assert.ok(published.archiveTags.includes(`sha256-${imageDigest.slice(7)}`));
    assert.ok(published.archiveTags.includes(`base-runtime-sha256-${sourceDigest.slice(7)}-${imageDigest.slice(7, 23)}`));
    assert.ok(published.archiveTags.includes(`base-build-sha256-${sourceDigest.slice(7)}-${imageDigest.slice(7, 23)}`));
    assert.ok(published.archiveTags.every((tag) => tag.length <= 128));
    for (const tag of [...published.archiveTags, ...published.scanArchive.tags]) {
      const record = registry.tags.get(registry.reference(entry.repository, tag));
      assert.equal(record.changeableAttributes.writeEnabled, false);
      assert.equal(record.changeableAttributes.deleteEnabled, false);
    }
    assert.equal(registry.tags.get(entry.image).changeableAttributes.writeEnabled, true);
    assert.equal(registry.manifests.get(`${entry.repository}@${imageDigest}`).changeableAttributes.deleteEnabled, false);
    assert.equal(registry.manifests.get(`${entry.repository}@${published.scanArchive.digest}`).changeableAttributes.deleteEnabled, false);
    const directories = (await readdir(output)).filter((name) => name.startsWith("archive-evidence-"));
    const manifest = JSON.parse(await readFile(join(output, directories[0], "manifest.json"), "utf8"));
    assert.equal(manifest.image, `${entry.image.split(":latest")[0]}@${imageDigest}`);
    assert.equal(manifest.imageId, imageId);
    assert.equal(manifest.hashes["scan.sarif"], entry.scanHash);
    assert.equal(manifest.baseImages.RUNTIME_IMAGE, entry.baseImages.RUNTIME_IMAGE);
    assert.equal(await readFile(join(output, directories[0], "scan.sarif"), "utf8"), await readFile(entry.scanPath, "utf8"));
    assert.ok(logs.some((line) => line.includes(`source manifest=${entry.baseImages.RUNTIME_IMAGE}`)));
    assert.ok(logs.some((line) => line.includes(`current latest=${imageDigest}`)));
    assert.ok(logs.some((line) => line.includes(`scan SHA256=${entry.scanHash}`)));
    const lastPush = calls.filter(([command, args]) => command === "docker" && args[0] === "push").at(-1);
    assert.equal(lastPush[1][1], entry.image);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("repeat scans reuse locked image archives but retain distinct immutable scan bundles", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-repeat-"));
  const calls = [];
  const registry = registryFixture(config, builder(calls), { imageId, digest: imageDigest });
  try {
    const entry = await portalEntry(output, registry);
    entry.scannedAt = "2026-10-12T12:00:00Z";
    const first = await publishImageArchive(config, entry, output, { ...registry, promoteLatest: true, log: () => {} });
    entry.scannedAt = "2026-10-12T13:00:00Z";
    const second = await publishImageArchive(config, entry, output, { ...registry, promoteLatest: true, log: () => {} });
    assert.deepEqual(second.archiveTags, first.archiveTags);
    assert.notEqual(second.scanArchive.bundleHash, first.scanArchive.bundleHash);
    assert.notEqual(second.scanArchive.image, first.scanArchive.image);
    assert.equal(second.previousLatestDigest, imageDigest);
    for (const tag of first.archiveTags)
      assert.equal(calls.filter(([command, args]) => command === "docker" && args[0] === "push" && args[1].endsWith(`:${tag}`)).length, 1);
    assert.equal(calls.filter(([command, args]) => command === "docker" && args[0] === "push" && args[1].endsWith(":latest")).length, 2);
    assert.equal((await readdir(output)).filter((name) => name.startsWith("archive-evidence-")).length, 2);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("archive collisions and failed lock readbacks never overwrite history or advance latest", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-conflict-"));
  try {
    const calls = [];
    const registry = registryFixture(config, builder(calls), { imageId, digest: imageDigest });
    const entry = await portalEntry(output, registry);
    const tag = `sha256-${imageDigest.slice(7)}`;
    registry.tags.set(registry.reference(entry.repository, tag), {
      name: tag, digest: `sha256:${"f".repeat(64)}`, changeableAttributes: { writeEnabled: false, deleteEnabled: false },
    });
    await assert.rejects(publishImageArchive(config, entry, output, { ...registry, promoteLatest: true, log: () => {} }), /Refusing to overwrite/);
    assert.equal(calls.some(([command, args]) => command === "docker" && args[0] === "push" && args[1].endsWith(":latest")), false);
    assert.equal(registry.tags.get(registry.reference(entry.repository, tag)).digest, `sha256:${"f".repeat(64)}`);

    const lockCalls = [];
    const lockRegistry = registryFixture(config, builder(lockCalls), { imageId, digest: imageDigest });
    const second = await portalEntry(join(output, "lock"), lockRegistry);
    await assert.rejects(publishImageArchive(config, second, join(output, "lock"), {
      ...lockRegistry, promoteLatest: true, log: () => {}, pause: async () => {},
      executeAz: async (args, options) => {
        const value = await lockRegistry.executeAz(args, options);
        return args[1] === "repository" && args[2] === "show"
          ? { ...value, changeableAttributes: { ...value.changeableAttributes, writeEnabled: true } }
          : value;
      },
    }), /lock was not verified/);
    assert.equal(lockCalls.some(([command, args]) => command === "docker" && args[0] === "push" && args[1].endsWith(":latest")), false);
    await assert.rejects(readFile(join(output, "lock", "published-image.json")), { code: "ENOENT" });
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("archive locks tolerate observed metadata propagation but never promote latest until exact readback is protected", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-propagation-"));
  const registry = registryFixture(config, builder(), { imageId, digest: imageDigest });
  const delays = [];
  const logs = [];
  let delayedReads = 0;
  try {
    const entry = await portalEntry(output, registry);
    const target = `${entry.repository}:sha256-${imageDigest.slice(7)}`;
    const published = await publishImageArchive(config, entry, output, {
      ...registry, promoteLatest: true, log: (line) => logs.push(line),
      pause: async (attempt) => delays.push(attempt),
      executeAz: async (args, options) => {
        const result = await registry.executeAz(args, options);
        if (args[1] === "repository" && args[2] === "show" && args.includes(target) && ++delayedReads < 3)
          return { ...result, changeableAttributes: { writeEnabled: true, deleteEnabled: true } };
        return result;
      },
    });
    assert.equal(published.digest, imageDigest);
    assert.deepEqual(delays, [0, 1]);
    assert.equal(delayedReads, 3);
    assert.ok(logs.some((line) => line.includes("readback pending") && line.includes("writeEnabled=true")));
    assert.equal(registry.tags.get(entry.image).digest, imageDigest);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("archive checks bind an OCI index to its single linux/amd64 scanned config and protect its child manifest", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-index-"));
  const registry = registryFixture(config, builder(), { imageId, digest: imageDigest });
  const child = `sha256:${"e".repeat(64)}`;
  try {
    const entry = await portalEntry(output, registry);
    registry.manifests.set(`${entry.repository}@${child}`, { config: { digest: imageId }, changeableAttributes: { deleteEnabled: true } });
    const published = await publishImageArchive(config, entry, output, {
      ...registry, promoteLatest: true, log: () => {},
      execute: async (command, args, options) => {
        if (command === "docker" && args.includes("--raw") && args[3].endsWith(`@${imageDigest}`))
          return JSON.stringify({ manifests: [{ digest: child, platform: { os: "linux", architecture: "amd64" } }] });
        return registry.execute(command, args, options);
      },
    });
    assert.equal(published.digest, imageDigest);
    assert.equal(registry.manifests.get(`${entry.repository}@${child}`).changeableAttributes.deleteEnabled, false);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("explicit source selections are exact, logged, bounded to known arguments and never replaced with latest", async () => {
  const selected = `sha256:${"e".repeat(64)}`;
  const calls = [];
  const logs = [];
  const resolved = await resolveLatestBaseImage(`node:24-bookworm-slim@${sourceDigest}`, {
    execute: builder(calls), selection: selected, log: (line) => logs.push(line),
  });
  assert.equal(resolved, `node:24-bookworm-slim@${selected}`);
  assert.equal(calls[0][1][3], resolved);
  assert.ok(logs[0].includes(`selection=${selected}`));
  await assert.rejects(resolveLatestBaseImage("node:24", {
    execute: () => JSON.stringify({ digest: sourceDigest }), selection: selected, log: () => {},
  }), /explicitly selected source digest/);
  const recipe = `ARG BASE_IMAGE=node:24@${sourceDigest}\nFROM \${BASE_IMAGE}\n`;
  for (const baseOverrides of [
    null, [], { UNKNOWN_IMAGE: selected }, { toString: "latest" }, { BASE_IMAGE: "https://attacker.invalid/image" }, { BASE_IMAGE: "sha256:short" },
  ])
    await assert.rejects(imageBaseArguments(recipe, { baseOverrides }), /Base overrides/);
  assert.ok(sourceArchiveTags({ BASE_IMAGE: resolved }, imageDigest)[0].includes(selected.slice(7)));
});

test("manual exact-SHA builds are archived and scanned without changing latest or author defaults", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-sha-manual-"));
  const calls = [];
  const registry = registryFixture(config, builder(calls), { imageId, digest: imageDigest });
  try {
    const entry = await portalEntry(output, registry, true);
    assert.equal(entry.channel, "test");
    assert.equal(entry.baseImages.RUNTIME_IMAGE.split("@")[1], sourceDigest);
    const published = await publishImageArchive(config, entry, output, { ...registry, log: () => {} });
    assert.ok(published.image.endsWith(`:sha256-${imageDigest.slice(7)}`));
    assert.equal(published.channel, "test");
    assert.equal(calls.some(([command, args]) => command === "docker" && args[0] === "push" && args[1].endsWith(":latest")), false);
    assert.equal(JSON.parse(await readFile(join(output, "published-image.json"), "utf8")).stage, "published-test");
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
