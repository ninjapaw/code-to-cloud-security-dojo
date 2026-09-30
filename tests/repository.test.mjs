import test from "node:test";
import assert from "node:assert/strict";
import { readFile, stat, mkdtemp, writeFile, rm } from "node:fs/promises";
import { join, dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  publicationFindings,
  reviewedUpstreamMarker,
} from "../scripts/check-public.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
test("publication exception is bound to the reviewed upstream file and exact bytes", async () => {
  const path =
    "apps/dojo/upstream/src/main/java/org/owasp/webgoat/lessons/cryptography/CryptoUtil.java";
  const content = await readFile(join(root, path), "utf8");
  assert.equal(reviewedUpstreamMarker(path, content), true);
  assert.equal(reviewedUpstreamMarker(path, `${content}\nchanged`), false);
  assert.equal(reviewedUpstreamMarker("other.java", content), false);
});
test("publication guard catches secrets and private artifacts without returning values", () => {
  const credential = "ghp_" + "x".repeat(36);
  assert.deepEqual(publicationFindings("example.txt", credential), [
    "GitHub token",
  ]);
  assert.deepEqual(publicationFindings("config/deploy.local.json", "{}"), [
    "private or generated artifact",
  ]);
  assert.deepEqual(publicationFindings("identity.pfx", "binary fixture"), [
    "private or generated artifact",
  ]);
  assert.deepEqual(
    publicationFindings(
      "config/deploy.config.json",
      JSON.stringify({ tenantId: "configured" }),
    ),
    ["environment-specific public defaults"],
  );
  assert.deepEqual(
    publicationFindings("README.md", "https://github.com/WebGoat/WebGoat"),
    [],
  );
});
test("owned labels use product and component names", async () => {
  for (const relative of [
    "README.md",
    "apps/dojo/README.md",
    "apps/control-portal/public/index.html",
    "apps/control-portal/public/app.js",
    "shared/report.mjs",
    ".github/workflows/dojo.yml",
  ]) {
    const content = await readFile(join(root, relative), "utf8");
    assert.doesNotMatch(
      content,
      /\bscen(?:ario|airo)s?[\s_:#-]*(?:one|two|0?[12])\b/i,
      relative,
    );
  }
  const readme = await readFile(join(root, "README.md"), "utf8");
  assert.match(readme, /^# Code to Cloud Security Dojo\r?\n/);
  assert.doesNotMatch(readme, /\bscen(?:ario|airo)s?\b/i);
});
test("all mutation audits are offline and do not write outputs", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "dojo-audit-"));
  const path = join(temporary, "config.json");
  await writeFile(
    path,
    await readFile(join(root, "config/deploy.config.json")),
  );
  try {
    for (const action of [
      "provision",
      "protection",
      "build",
      "deploy",
      "repair",
      "rotate",
      "deprovision",
      "source-sync",
      "source-check",
      "source-upstream",
    ]) {
      const result = spawnSync(
        process.execPath,
        [join(root, "scripts/deploy.mjs"), action, "--audit"],
        {
          cwd: temporary,
          encoding: "utf8",
          env: { ...process.env, DOJO_CONFIG: path, PATH: "" },
        },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).audit, true);
    }
    await assert.rejects(stat(join(temporary, "output")));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
test("documentation local links and heading anchors resolve", async () => {
  for (const relative of ["README.md", "SECURITY.md", "apps/dojo/README.md"]) {
    const path = join(root, relative);
    const markdown = await readFile(path, "utf8");
    assert.doesNotMatch(markdown, /\]\((?:\.\.\/)*docs\//);
    for (const match of markdown.matchAll(/\]\(([^)#]*)(?:#([^)]*))?\)/g)) {
      const [, target, anchor] = match;
      if (/^https?:/.test(target)) continue;
      const resolved = target
        ? resolve(dirname(path), decodeURI(target))
        : path;
      assert.ok(await stat(resolved), `${relative}: ${target}`);
      if (anchor && !/^L\d+$/.test(anchor)) {
        const headings = [
          ...(await readFile(resolved, "utf8")).matchAll(/^#{1,6} (.+)$/gm),
        ].map((heading) =>
          heading[1]
            .toLowerCase()
            .replace(/[^a-z0-9 -]/g, "")
            .replace(/ +/g, "-"),
        );
        assert.ok(
          headings.includes(anchor),
          `${relative}: missing ${target}#${anchor}`,
        );
      }
    }
  }
});
