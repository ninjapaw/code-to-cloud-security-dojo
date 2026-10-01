import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import {
  fingerprint,
  verifySource,
  synchronizeSource,
  imageRecipe,
} from "../scripts/lib/dojo-source.mjs";

test("source snapshot is deterministic, idempotent and refuses modified imports", async () => {
  const home = await mkdtemp(join(tmpdir(), "dojo-source-test-"));
  const source = {
    repository: "https://github.com/WebGoat/WebGoat.git",
    revision: "a".repeat(40),
  };
  try {
    await mkdir(join(home, "upstream"));
    await writeFile(join(home, "upstream", "LICENSE"), "fixture-license\n");
    const manifest = {
      schemaVersion: 1,
      ...source,
      ...(await fingerprint(join(home, "upstream"))),
    };
    await writeFile(join(home, "source-lock.json"), JSON.stringify(manifest));
    assert.deepEqual(await verifySource(home, source), manifest);
    const result = await synchronizeSource(home, source, {
      execute: () => {
        throw new Error("Unexpected network call");
      },
    });
    assert.equal(result.state, "found");
    await writeFile(join(home, "upstream", "LICENSE"), "local changes\n");
    await assert.rejects(
      synchronizeSource(home, { ...source, revision: "b".repeat(40) }),
      /local changes/,
    );
    assert.equal(
      await readFile(join(home, "upstream", "LICENSE"), "utf8"),
      "local changes\n",
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
test("unowned source and unpinned revisions cannot be imported", async () => {
  const home = await mkdtemp(join(tmpdir(), "dojo-source-test-"));
  try {
    await mkdir(join(home, "upstream"));
    await assert.rejects(
      synchronizeSource(home, { revision: "main" }),
      /commit SHA/,
    );
    await assert.rejects(
      synchronizeSource(home, { revision: "a".repeat(40) }),
      /unowned/,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
test("owned image build retains upstream runtime recipe and fails on recipe drift", () => {
  const original =
    'FROM docker.io/eclipse-temurin:25-jdk-noble\nCOPY --chown=webgoat target/webgoat-*.jar /home/webgoat/webgoat.jar\nUSER webgoat\nENTRYPOINT ["java","-jar","webgoat.jar"]\n';
  const recipe = imageRecipe(original);
  assert.equal(
    recipe.match(/eclipse-temurin:25-jdk-noble@sha256:[a-f0-9]{64}/g)?.length,
    2,
  );
  assert.match(recipe, /mvnw -B -DskipTests package/);
  assert.ok(recipe.includes("sed -i 's/\\r$//' mvnw"));
  assert.match(recipe, /COPY --from=dojo-build/);
  assert.ok(
    recipe.includes('USER webgoat\nENTRYPOINT ["java","-jar","webgoat.jar"]\n'),
  );
  assert.ok(
    recipe.endsWith(
      'LABEL name="Code to Cloud Security Dojo" org.opencontainers.image.title="Code to Cloud Security Dojo"\n',
    ),
  );
  assert.throws(() => imageRecipe("FROM changed"), /packaging changed/);
});
test("copy-based refresh publishes a complete snapshot and preserves the previous one on fetch failure", async () => {
  const home = await mkdtemp(join(tmpdir(), "dojo-source-refresh-"));
  const source = {
    repository: "https://github.com/WebGoat/WebGoat.git",
    revision: "a".repeat(40),
  };
  const execute = (command, args) => {
    if (command === "git" && args[0] === "rev-parse")
      return args[1].includes("tree") ? "c".repeat(40) : source.revision;
    if (command === "tar")
      for (const name of [
        "LICENSE.txt",
        "COPYRIGHT.txt",
        "pom.xml",
        "mvnw",
        "Dockerfile",
      ])
        writeFileSync(join(args[3], name), `${name}\n${source.revision}\n`);
    return "";
  };
  try {
    assert.equal(
      (await synchronizeSource(home, source, { execute })).state,
      "imported",
    );
    source.revision = "b".repeat(40);
    assert.equal(
      (await synchronizeSource(home, source, { execute })).state,
      "imported",
    );
    const before = await verifySource(home, source);
    await assert.rejects(
      synchronizeSource(
        home,
        { ...source, revision: "d".repeat(40) },
        {
          execute: () => {
            throw new Error("Fetch unavailable");
          },
        },
      ),
      /Fetch unavailable/,
    );
    assert.deepEqual(await verifySource(home, source), before);
    await writeFile(join(home, ".source-sync.lock"), "active");
    await assert.rejects(synchronizeSource(home, source, { execute }), {
      code: "EEXIST",
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
