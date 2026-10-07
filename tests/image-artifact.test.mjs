import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportImageArtifact } from "../scripts/export-image-artifact.mjs";

const image = "registry.example/dojo-123456789abc-app:training-test";
const imageId = `sha256:${"a".repeat(64)}`;
const revision = "b".repeat(40);
const recipe = Buffer.from("FROM scratch\r\nLABEL test=\"fixture\"\r\n");
const archive = Buffer.from([0, 1, 2, 128, 255, 10]);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture(callback) {
  const root = await mkdtemp(join(tmpdir(), "dojo-image-artifact-"));
  try {
    const dockerfile = join(root, "input.Dockerfile");
    await writeFile(dockerfile, recipe);
    await callback({ root, dockerfile, output: join(root, "artifact") });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function executor(calls = []) {
  return async (command, args) => {
    calls.push([command, args]);
    if (command === "git") return revision;
    assert.equal(command, "docker");
    if (args[1] === "inspect") {
      assert.equal(args[2], image);
      return JSON.stringify({ Id: imageId, Os: "linux", Architecture: "amd64" });
    }
    assert.deepEqual(args.slice(0, 3), ["image", "save", "--output"]);
    assert.equal(args[4], image);
    await writeFile(args[3], archive);
    return "";
  };
}

test("image artifact contains loadable-image export, exact recipe, identity and verified hashes", async () => {
  await fixture(async ({ dockerfile, output }) => {
    const calls = [];
    const metadata = await exportImageArtifact(image, dockerfile, output, {
      expectedImageId: imageId, execute: executor(calls),
    });
    assert.deepEqual((await readdir(output)).sort(),
      ["Dockerfile", "SHA256SUMS", "image.json", "image.tar"].sort());
    assert.deepEqual(await readFile(join(output, "Dockerfile")), recipe);
    assert.deepEqual(await readFile(join(output, "image.tar")), archive);
    assert.equal(metadata.image, image);
    assert.equal(metadata.imageId, imageId);
    assert.equal(metadata.platform, "linux/amd64");
    assert.equal(metadata.exportRevision, revision);
    assert.equal(metadata.archiveBytes, archive.length);
    assert.equal(metadata.archiveSha256, hash(archive));
    assert.equal(metadata.dockerfileSha256, hash(recipe));
    assert.deepEqual(JSON.parse(await readFile(join(output, "image.json"), "utf8")), metadata);
    for (const line of (await readFile(join(output, "SHA256SUMS"), "utf8")).trim().split("\n")) {
      const [expected, name] = line.split("  ");
      assert.equal(hash(await readFile(join(output, name))), expected);
    }
    assert.equal(calls.filter(([, args]) => args[1] === "inspect").length, 2);
    assert.equal(calls.some(([, args]) => args.includes("push") || args.includes("run")), false);
  });
});

test("mismatched scanned image and invalid image/platform fail before creating artifacts", async () => {
  await fixture(async ({ dockerfile, output }) => {
    await assert.rejects(
      exportImageArtifact(image, dockerfile, output, {
        expectedImageId: `sha256:${"c".repeat(64)}`, execute: executor(),
      }), /scanned release/,
    );
    for (const info of [
      { Id: "missing", Os: "linux", Architecture: "amd64" },
      { Id: imageId, Os: "linux", Architecture: "arm64" },
      { Id: imageId, Os: "windows", Architecture: "amd64" },
    ])
      await assert.rejects(
        exportImageArtifact(image, dockerfile, output, {
          execute: async () => JSON.stringify(info),
        }), /verified linux\/amd64/,
      );
    await assert.rejects(exportImageArtifact("--unsafe", dockerfile, output), /required/);
    await assert.rejects(stat(output), { code: "ENOENT" });
  });
});

test("image export errors, empty archives and tag changes never leave publishable partial artifacts", async () => {
  await fixture(async ({ dockerfile, output }) => {
    for (const failure of ["save", "empty", "changed"]) {
      const normal = executor();
      let inspected = 0;
      const execute = async (command, args) => {
        if (args[1] === "save") {
          if (failure === "save") throw new Error("Docker save failed");
          if (failure === "empty") {
            await writeFile(args[3], "");
            return "";
          }
        }
        if (args[1] === "inspect" && ++inspected === 2 && failure === "changed")
          return JSON.stringify({ Id: `sha256:${"c".repeat(64)}` });
        return normal(command, args);
      };
      await assert.rejects(exportImageArtifact(image, dockerfile, output, { execute }),
        /Docker save failed|nonempty image archive|Image changed/);
      await assert.rejects(stat(output), { code: "ENOENT" });
    }
  });
});

test("export refuses to overwrite or remove any preexisting output", async () => {
  await fixture(async ({ dockerfile, output }) => {
    await exportImageArtifact(image, dockerfile, output, { execute: executor() });
    const original = await readFile(join(output, "image.json"));
    await assert.rejects(
      exportImageArtifact(image, dockerfile, output, { execute: executor() }),
      { code: "EEXIST" },
    );
    assert.deepEqual(await readFile(join(output, "image.json")), original);
  });
});
