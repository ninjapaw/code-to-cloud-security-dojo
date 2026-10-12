import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { names } from "../shared/config.mjs";
import { drowsyDragon } from "../shared/drowsy-dragon.mjs";
import { nginxMode } from "../shared/nginx-proxy.mjs";
import { imageBaseArguments, buildCoreImage, publishLatestImage, resolveLatestBaseImage } from "../scripts/lib/image-build.mjs";
import { publishLatestImages } from "../scripts/lib/latest-images.mjs";
import { verifySource } from "../scripts/lib/dojo-source.mjs";
import { verifyNginxSource } from "../scripts/lib/nginx-proxy.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const base = JSON.parse(await readFile(join(root, "config", "deploy.config.json"), "utf8"));
const config = { ...base, subscriptionId: "test" };
const imageId = `sha256:${"a".repeat(64)}`;
const upstreamDigest = `sha256:${"b".repeat(64)}`;
const registryDigest = `sha256:${"c".repeat(64)}`;
const portalRecipe = await readFile(join(root, "apps", "control-portal", "Dockerfile"), "utf8");
const workerRecipe = await readFile(join(root, "scripts", "Dockerfile.secret-bootstrap"), "utf8");

function executor(calls, selected = config, digest = upstreamDigest) {
  return async (command, args) => {
    calls.push([command, args]);
    if (command === "git") return "d".repeat(40);
    if (command === "docker" && args[0] === "buildx") return JSON.stringify({ digest });
    if (command === "docker" && args[0] === "image") return imageId;
    if (command === "docker" && args[0] === "run") {
      return args.some((arg) => arg.includes("-dragon:"))
        ? drowsyDragon.packages.map((name) => `${name}\t1.0`).join("\n")
        : `nginx\t${nginxMode(selected.nginxProxyMode).version}-1~noble`;
    }
    if (command === "trivy") {
      const json = args.includes("json");
      const dragon = args.at(-1).includes("-dragon:");
      const packages = dragon
        ? drowsyDragon.packages.map((Name) => ({ Name, Version: "1.0" }))
        : [{ Name: "nginx", Version: `${nginxMode(selected.nginxProxyMode).version}-1~noble` }];
      await writeFile(args[args.indexOf("--output") + 1], json ? JSON.stringify({
        SchemaVersion: 2, ArtifactType: "container_image", Metadata: { ImageID: imageId },
        Results: [{ Target: "fixture", Type: "debian", Packages: packages, Vulnerabilities: [] }],
      }) : "{}");
    }
    return "";
  };
}

test("multi-stage image arguments retain approved defaults and resolve both latest bases by digest", async () => {
  const calls = [];
  const execute = executor(calls);
  const pinned = await imageBaseArguments(portalRecipe, { execute });
  assert.match(pinned.baseImages.BUILD_IMAGE, /^node:24-bookworm-slim@sha256:0e0ff40/);
  assert.match(pinned.baseImages.RUNTIME_IMAGE, /^gcr\.io\/distroless\/nodejs24-debian13:nonroot@sha256:9eeb7f/);
  assert.deepEqual(pinned.buildArgs, []);
  assert.deepEqual(calls, []);
  const latest = await imageBaseArguments(portalRecipe, { execute, latest: true });
  assert.equal(latest.baseImages.BUILD_IMAGE, `node:24-bookworm-slim@${upstreamDigest}`);
  assert.equal(latest.baseImages.RUNTIME_IMAGE, `gcr.io/distroless/nodejs24-debian13:nonroot@${upstreamDigest}`);
  assert.deepEqual(latest.buildArgs, [
    "--pull", "--build-arg", `BUILD_IMAGE=${latest.baseImages.BUILD_IMAGE}`,
    "--build-arg", `RUNTIME_IMAGE=${latest.baseImages.RUNTIME_IMAGE}`,
  ]);
  assert.deepEqual(calls.map(([, args]) => args[3]), [
    "node:24-bookworm-slim", "gcr.io/distroless/nodejs24-debian13:nonroot",
  ]);
});

test("base resolution rejects invalid recipes and failed or incomplete registry manifests rather than falling back", async () => {
  for (const recipe of [
    "FROM unrelated:latest\n",
    "FROM ${BASE_IMAGE}\n",
    "ARG BASE_IMAGE=node:24\nARG BASE_IMAGE=node:22\nFROM ${BASE_IMAGE}\n",
  ])
    await assert.rejects(imageBaseArguments(recipe), /reviewed base image arguments|one approved default/);
  await assert.rejects(resolveLatestBaseImage("node", { execute: () => { throw new Error("Unexpected command"); } }), /reviewed tagged/);
  for (const manifest of ["{}", "null", '{"digest":"invalid"}', "{invalid"])
    await assert.rejects(resolveLatestBaseImage("node:24", { execute: () => manifest }), /JSON|valid latest base image digest/);
  await assert.rejects(resolveLatestBaseImage("node:24", {
    execute: () => { throw new Error("registry unavailable"); },
  }), /registry unavailable/);
});

test("core image builds expose latest options while default builds keep authored bases, commands and source unchanged", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-core-images-"));
  const dojoHome = join(root, "apps", "dojo");
  const before = await verifySource(dojoHome, base.source);
  try {
    for (const component of ["dojo", "portal", "secretBootstrap"]) {
      for (const latest of [false, true]) {
        const calls = [];
        const entry = await buildCoreImage(component, `${component.toLowerCase()}:${latest ? "latest" : "test"}`, join(output, `${component}-${latest}`), {
          source: base.source, latest, execute: executor(calls),
        });
        assert.equal(entry.channel, latest ? "latest" : "pinned");
        assert.equal(entry.imageId, imageId);
        assert.match(entry.scanHash, /^[a-f0-9]{64}$/);
        const build = calls.find(([command, args]) => command === "docker" && args[0] === "build")[1];
        assert.equal(build.includes("--pull"), latest);
        assert.equal(calls.filter(([command, args]) => command === "docker" && args[0] === "buildx").length,
          latest ? component === "dojo" ? 1 : 2 : 0);
        assert.ok(build.includes("--platform"));
        const scan = calls.find(([command, args]) => command === "trivy" && args[0] === "image")[1];
        assert.equal(scan[scan.indexOf("--exit-code") + 1], component === "dojo" ? "0" : "1");
        if (component === "portal") assert.ok(build.includes(`DOJO_CODE_REVISION=${"d".repeat(40)}`));
        if (component === "dojo") {
          assert.deepEqual(entry.source, before);
          assert.ok(build.includes(`org.opencontainers.image.revision=${base.source.revision}`));
          assert.equal((await readFile(entry.dockerfilePath, "utf8")).match(/^FROM \$\{BASE_IMAGE\}/gm)?.length, 2);
        }
        if (latest) {
          assert.ok(Object.values(entry.baseImages).every((value) => value.endsWith(`@${upstreamDigest}`)));
          for (const [variable, value] of Object.entries(entry.baseImages))
            assert.ok((await readFile(entry.dockerfilePath, "utf8")).includes(`ARG ${variable}=${value}`));
        }
        assert.equal(calls.some(([command, args]) => command === "az" || args[0] === "push" || args[0] === "run"), false);
      }
    }
    const unscannedCalls = [];
    const unscanned = await buildCoreImage("dojo", "dojo:local", join(output, "unscanned"), {
      source: base.source, scan: false, execute: executor(unscannedCalls),
    });
    assert.equal(unscanned.scanHash, undefined);
    assert.equal(unscannedCalls.some(([command]) => command === "trivy"), false);
    assert.deepEqual(await verifySource(dojoHome, base.source), before);
    assert.equal(await readFile(join(root, "apps", "control-portal", "Dockerfile"), "utf8"), portalRecipe);
    assert.equal(await readFile(join(root, "scripts", "Dockerfile.secret-bootstrap"), "utf8"), workerRecipe);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("latest publication scans every selected image before pushing and works with optional demos disabled or enabled", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-all-latest-"));
  const approvedBase = drowsyDragon.baseImage;
  try {
    for (const enabled of [false, true]) {
      const selected = { ...config, drowsyDragonEnabled: enabled, nginxProxyEnabled: enabled, nginxProxyMode: "remediated" };
      const calls = [];
      const azureCalls = [];
      const images = await publishLatestImages(selected, join(output, String(enabled)), {
        execute: executor(calls, selected),
        executeAz: async (args) => {
          azureCalls.push(args);
          return args.includes("show-metadata") ? registryDigest : "";
        },
      });
      assert.deepEqual(Object.keys(images), [
        "dojo", "portal", "secretBootstrap", ...(enabled ? ["drowsyDragon", "nginxProxy"] : []),
      ]);
      const pushes = calls.filter(([command, args]) => command === "docker" && args[0] === "push");
      assert.deepEqual(pushes.map(([, args]) => args[1]), Object.values(images).map((entry) => entry.image));
      const firstPush = calls.findIndex(([command, args]) => command === "docker" && args[0] === "push");
      const lastScan = calls.findLastIndex(([command]) => command === "trivy");
      assert.ok(firstPush > lastScan);
      for (const [component, entry] of Object.entries(images)) {
        assert.equal(entry.channel, "latest");
        assert.ok(entry.image.endsWith(":latest"));
        assert.equal(entry.digest, registryDigest);
        const recorded = JSON.parse(await readFile(join(output, String(enabled), component, "published-image.json"), "utf8"));
        assert.equal(recorded.stage, "published-latest");
        assert.equal(recorded.digest, registryDigest);
      }
      assert.equal(images.secretBootstrap.repository, "secret-bootstrap");
      assert.ok(azureCalls.every((args) => args[0] === "acr"));
      assert.equal(azureCalls.filter((args) => args.includes("show-metadata")).length, Object.keys(images).length);
    }
    assert.equal(drowsyDragon.baseImage, approvedBase);
    await verifyNginxSource();
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("unchanged and newer upstream digests both publish latest without rewriting the Node pins", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-latest-repeat-"));
  const resourceNames = names(config);
  const calls = [];
  try {
    for (const digest of [upstreamDigest, upstreamDigest, `sha256:${"e".repeat(64)}`]) {
      const entry = await buildCoreImage("portal", `${resourceNames.registry}.azurecr.io/${resourceNames.portal}:latest`, output, {
        latest: true, repository: resourceNames.portal, execute: executor(calls, config, digest),
      });
      const published = await publishLatestImage(config, entry, output, {
        execute: executor(calls), executeAz: async (args) => args.includes("show-metadata") ? registryDigest : "",
      });
      assert.ok(published.baseImages.BUILD_IMAGE.endsWith(`@${digest}`));
      assert.ok(published.baseImages.RUNTIME_IMAGE.endsWith(`@${digest}`));
    }
    assert.equal(calls.filter(([command, args]) => command === "docker" && args[0] === "push").length, 3);
    assert.equal(await readFile(join(root, "apps", "control-portal", "Dockerfile"), "utf8"), portalRecipe);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("scanner failures, changed scan evidence, moving-tag substitutions and missing registry digests do not report latest success", async () => {
  const output = await mkdtemp(join(tmpdir(), "dojo-latest-guards-"));
  const calls = [];
  const resourceNames = names(config);
  try {
    const execute = executor(calls);
    await assert.rejects(publishLatestImages(config, join(output, "failed"), {
      execute: async (command, args) => {
        if (command === "trivy" && args.at(-1).includes("-portal:"))
          throw new Error("portal high severity scan failed");
        return execute(command, args);
      },
      executeAz: () => { throw new Error("Unexpected Azure command"); },
    }), /portal high severity/);
    assert.equal(calls.some(([command, args]) => command === "docker" && args[0] === "push"), false);

    const entry = await buildCoreImage("portal", `${resourceNames.registry}.azurecr.io/${resourceNames.portal}:latest`, join(output, "entry"), {
      latest: true, repository: resourceNames.portal, execute,
    });
    const publishOptions = { execute, executeAz: () => { throw new Error("Unexpected Azure command"); } };
    for (const changed of [
      { ...entry, channel: "pinned" },
      { ...entry, image: entry.image.replace(":latest", ":training") },
      { ...entry, repository: "unowned" },
      { ...entry, image: entry.image.replace(resourceNames.registry, "other") },
    ])
      await assert.rejects(publishLatestImage(config, changed, output, publishOptions), /owned repository/);
    await assert.rejects(publishLatestImage(config, entry, output, {
      execute, executeAz: async (args) => args.includes("show-metadata") ? "invalid" : "",
    }), /ACR did not return a valid/);
    await assert.rejects(readFile(join(output, "published-image.json")), { code: "ENOENT" });
    await writeFile(entry.scanPath, "tampered");
    await assert.rejects(publishLatestImage(config, entry, output, publishOptions), /scan evidence changed/);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});
