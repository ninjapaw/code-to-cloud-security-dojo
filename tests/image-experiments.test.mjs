import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { names } from "../shared/config.mjs";
import { experimentBaseSelection, discoverImageHashes, hashCatalogHtml, hashCatalogMarkdown, writeHashCatalog } from "../scripts/lib/image-catalog.mjs";
import { smokeTestImage } from "../scripts/lib/image-smoke.mjs";

const base = JSON.parse(await readFile(new URL("../config/deploy.config.json", import.meta.url), "utf8"));
const config = { ...base, subscriptionId: "test" };
const current = `sha256:${"b".repeat(64)}`;
const archived = `sha256:${"a".repeat(64)}`;
const imageDigest = `sha256:${"c".repeat(64)}`;
const container = "d".repeat(64);
const network = "e".repeat(64);
const entry = { image: "owned:test-fixture", imageId: archived, sourceRevision: "f".repeat(40) };

test("native SHA selection supports latest or exact hashes and rejects unused, partial, unknown and URL inputs", () => {
  assert.deepEqual(experimentBaseSelection("portal", archived, "latest"), { RUNTIME_IMAGE: archived, BUILD_IMAGE: "latest" });
  assert.deepEqual(experimentBaseSelection("dojo"), { BASE_IMAGE: "latest" });
  for (const image of ["all", "unknown", "__proto__"])
    assert.throws(() => experimentBaseSelection(image), /supported image/);
  for (const digest of ["", "latest@sha256:short", "sha256:short", `sha256:${"A".repeat(64)}`, "https://other.invalid/image"])
    assert.throws(() => experimentBaseSelection("portal", digest), /complete sha256/);
  assert.throws(() => experimentBaseSelection("drowsy-dragon", current, archived), /only to Node/);
});

test("detected catalogs distinguish current, approved and archived source hashes without building or pushing", async () => {
  const calls = [];
  const catalog = await discoverImageHashes(config, "portal", {
    log: () => {},
    execute: async (command, args) => {
      calls.push([command, args]);
      return JSON.stringify({ digest: current });
    },
    executeAz: async (args) => args[2] === "list" ? [names(config).portal] : [
      { name: `base-runtime-sha256-${archived.slice(7)}-${imageDigest.slice(7, 23)}`, digest: imageDigest },
      { name: `sha256-${imageDigest.slice(7)}`, digest: imageDigest },
      { name: `scan-${imageDigest.slice(7)}-${"d".repeat(32)}`, digest: imageDigest },
    ],
  });
  const runtime = catalog.images[0].bases.find((item) => item.argument === "RUNTIME_IMAGE");
  assert.equal(runtime.current.split("@")[1], current);
  assert.ok(runtime.choices.some((choice) => choice.statuses.includes("approved")));
  assert.ok(runtime.choices.some((choice) => choice.digest === archived && choice.statuses.includes("archived")));
  assert.equal(catalog.images[0].archives.length, 1);
  assert.equal(catalog.images[0].scans.length, 1);
  assert.ok(calls.every(([command, args]) => command === "docker" && args.slice(0, 3).join(" ") === "buildx imagetools inspect"));
  const html = hashCatalogHtml(catalog, config);
  assert.match(html, /Copy SHA/);
  assert.match(html, /Copy build command/);
  assert.ok(html.includes(`base-sha=${archived}`));
  assert.ok(html.includes(`build-sha=${current}`));
  assert.match(html, /does not dynamically populate/);
  assert.match(hashCatalogMarkdown(catalog, config), /100 most recently updated tags/);
  const output = await mkdtemp(join(tmpdir(), "dojo-hash-catalog-"));
  try {
    await writeHashCatalog(catalog, config, output);
    assert.equal(JSON.parse(await readFile(join(output, "hash-catalog.json"), "utf8")).schemaVersion, 1);
    assert.match(await readFile(join(output, "hash-catalog.html"), "utf8"), /Container hash catalog/);
  } finally {
    await rm(output, { recursive: true, force: true });
  }
});

test("archive catalog refuses mislabeled source aliases and invalid registry output", async () => {
  await assert.rejects(discoverImageHashes(config, "portal", {
    executeAz: () => "unexpected",
  }), /repository inventory/);
  await assert.rejects(discoverImageHashes(config, "portal", {
    log: () => {},
    execute: () => JSON.stringify({ digest: current }),
    executeAz: (args) => args[2] === "list" ? [names(config).portal] : [
      { name: `base-runtime-sha256-${archived.slice(7)}-${"e".repeat(16)}`, digest: imageDigest },
    ],
  }), /does not match its image manifest/);
});

test("manual workflow selection is protected, registry-only and cannot promote latest or deploy infrastructure", async () => {
  const workflow = await readFile(new URL("../.github/workflows/image-experiments.yml", import.meta.url), "utf8");
  assert.match(workflow, /options: \[detect, build-test\]/);
  assert.match(workflow, /base-sha:[\s\S]*?default: latest/);
  assert.match(workflow, /environment: code-to-cloud-images/);
  assert.match(workflow, /group: dojo-images-code-to-cloud-training/);
  assert.doesNotMatch(workflow, /contents: write|actions: write|client-secret|environment: code-to-cloud-training|deploy --|provision --|--automatic/);
  const condition = workflow.match(/^    if: (.+)$/m)[1];
  assert.equal(runInNewContext(condition, { github: { ref: "refs/heads/dev", event_name: "workflow_dispatch" } }), true);
  for (const [ref, event_name] of [["refs/heads/main", "workflow_dispatch"], ["refs/heads/dev", "pull_request"], ["refs/heads/dev", "push"]])
    assert.equal(runInNewContext(condition, { github: { ref, event_name } }), false);
  assert.match(workflow, /node scripts\/image-experiments\.mjs "\$\{args\[@\]\}"/);
  assert.match(workflow, /retention-days: 30/);
});

test("manual audit validates SHA inputs offline and never writes outputs or authenticates", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "dojo-image-audit-"));
  const path = join(temporary, "config.json");
  try {
    await writeFile(path, JSON.stringify(base));
    for (const [operation, image] of [["detect", "all"], ["build-test", "portal"], ["build-test", "drowsy-dragon"]]) {
      const result = spawnSync(process.execPath, [
        fileURLToPath(new URL("../scripts/image-experiments.mjs", import.meta.url)), operation,
        "--image", image, "--audit",
      ], { cwd: temporary, encoding: "utf8", env: { ...process.env, DOJO_CONFIG: path, PATH: "" } });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).audit, true);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

function smokeExecutor(calls) {
  return async (command, args) => {
    calls.push([command, args]);
    if (args[0] === "image") return entry.imageId;
    if (args[0] === "network" && args[1] === "create") return network;
    if (args[0] === "run" && args.includes("--detach")) return container;
    if (args[0] === "port") return "127.0.0.1:49152";
    if (args[0] === "inspect") return "true";
    return "";
  };
}

test("optional smoke tests isolate runtime access and never execute the credential bootstrap worker", async () => {
  for (const image of ["dojo", "portal", "nginx-proxy", "drowsy-dragon", "secret-bootstrap"]) {
    const calls = [];
    const result = await smokeTestImage(image, entry, {
      execute: smokeExecutor(calls), pause: async () => {}, log: () => {},
      fetcher: async () => Response.json(image === "dojo" ? { status: "UP" }
        : image === "portal" ? { status: "running", mode: "read-only-preview", codeRevision: entry.sourceRevision }
          : { status: "healthy", environment: "training" }),
    });
    assert.equal(result.state, "observed");
    const run = calls.find(([, args]) => args[0] === "run")[1];
    assert.equal(run.includes("--privileged"), false);
    assert.equal(run.some((arg) => /AZURE_|DOJO_ADMIN/.test(arg)), false);
    if (image === "secret-bootstrap") {
      assert.ok(run.includes("--check"));
      assert.ok(run.includes("scripts/secret-bootstrap.mjs"));
      assert.equal(run[run.indexOf("--network") + 1], "none");
    } else {
      assert.ok(calls.some(([, args]) => args[0] === "rm" && args.includes(container)));
      if (image !== "drowsy-dragon") {
        assert.ok(calls.some(([, args]) => args[0] === "network" && args.includes("--internal")));
        assert.ok(calls.some(([, args]) => args[0] === "network" && args[1] === "rm" && args.includes(network)));
      }
    }
    if (image === "portal") assert.ok(run.includes("--preview"));
  }
});

test("smoke failures and non-loopback bindings fail explicitly and clean up only created container/network IDs", async () => {
  const calls = [];
  await assert.rejects(smokeTestImage("portal", entry, {
    execute: smokeExecutor(calls), attempts: 1, pause: async () => {}, log: () => {},
    fetcher: async () => Response.json({ status: "running", mode: "configured", codeRevision: entry.sourceRevision }),
  }), /health did not match/);
  assert.ok(calls.some(([, args]) => args[0] === "rm" && args.includes(container)));
  assert.ok(calls.some(([, args]) => args[0] === "network" && args[1] === "rm" && args.includes(network)));
  const otherCalls = [];
  const execute = smokeExecutor(otherCalls);
  await assert.rejects(smokeTestImage("dojo", entry, {
    execute: (command, args) => args[0] === "port" ? "0.0.0.0:49152" : execute(command, args),
    log: () => {},
  }), /loopback/);
  assert.ok(otherCalls.some(([, args]) => args[0] === "rm" && args.includes(container)));
  assert.ok(otherCalls.some(([, args]) => args[0] === "network" && args[1] === "rm" && args.includes(network)));
});
