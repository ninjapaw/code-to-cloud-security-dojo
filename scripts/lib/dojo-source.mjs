import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  writeFile,
  readdir,
  lstat,
  rename,
  rm,
  cp,
  open,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { run } from "./lifecycle.mjs";

export async function fingerprint(directory) {
  const records = [];
  async function visit(relative = "") {
    for (const entry of (
      await readdir(join(directory, relative), { withFileTypes: true })
    ).sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink())
        throw new Error(`Source symlinks are not supported: ${path}`);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile())
        records.push(
          `${path}\0${createHash("sha256")
            .update(await readFile(join(directory, path)))
            .digest("hex")}\n`,
        );
      else throw new Error(`Unsupported source entry: ${path}`);
    }
  }
  await visit();
  return {
    files: records.length,
    sha256: createHash("sha256").update(records.join("")).digest("hex"),
  };
}

export async function verifySource(home, source) {
  const manifest = JSON.parse(
    await readFile(join(home, "source-lock.json"), "utf8"),
  );
  if (
    manifest.schemaVersion !== 1 ||
    manifest.repository !== source.repository ||
    manifest.revision !== source.revision
  )
    throw new Error(
      "WebGoat snapshot does not match configured upstream pin; run source:sync and review the import",
    );
  const actual = await fingerprint(join(home, "upstream"));
  if (actual.files !== manifest.files || actual.sha256 !== manifest.sha256)
    throw new Error(
      "WebGoat snapshot has local changes; preserve/review them before synchronizing or building",
    );
  return manifest;
}

export async function synchronizeSource(home, source, options = {}) {
  await mkdir(home, { recursive: true });
  const lockPath = join(home, ".source-sync.lock");
  const lock = await open(lockPath, "wx");
  try {
    return await synchronizeOwnedSource(home, source, options);
  } finally {
    await lock.close();
    await rm(lockPath);
  }
}

async function synchronizeOwnedSource(home, source, { execute = run } = {}) {
  if (!/^[a-f0-9]{40}$/.test(source.revision))
    throw new Error("A full upstream commit SHA is required");
  await mkdir(home, { recursive: true });
  let previous;
  try {
    previous = JSON.parse(
      await readFile(join(home, "source-lock.json"), "utf8"),
    );
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (previous) {
    await verifySource(home, previous);
    if (
      previous.repository === source.repository &&
      previous.revision === source.revision
    )
      return { state: "found", manifest: previous };
  } else {
    try {
      await lstat(join(home, "upstream"));
      throw new Error("Refusing to replace an unowned upstream directory");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const temporary = await mkdtemp(join(tmpdir(), "dojo-"));
  const staged = await mkdtemp(join(home, ".source-stage-"));
  const backup = `${staged}-previous`;
  let backedUp = false;
  let promoted = false;
  let committed = false;
  const nextManifest = `${staged}.json`;
  try {
    const checkout = join(temporary, "checkout");
    execute("git", ["init", checkout]);
    execute("git", ["remote", "add", "origin", source.repository], {
      cwd: checkout,
    });
    execute("git", ["fetch", "--depth=1", "origin", source.revision], {
      cwd: checkout,
      inherit: true,
    });
    const revision = execute("git", ["rev-parse", "FETCH_HEAD^{commit}"], {
      cwd: checkout,
    });
    if (revision !== source.revision)
      throw new Error("Fetched source revision mismatch");
    const tree = execute("git", ["rev-parse", "FETCH_HEAD^{tree}"], {
      cwd: checkout,
    });
    const archive = join(temporary, "source.tar");
    execute("git", ["archive", "--format=tar", "--output", archive, revision], {
      cwd: checkout,
    });
    execute("tar", ["-xf", archive, "-C", resolve(staged)]);
    const content = await fingerprint(staged);
    for (const required of [
      "pom.xml",
      "mvnw",
      "Dockerfile",
      "LICENSE.txt",
      "COPYRIGHT.txt",
    ])
      await lstat(join(staged, required));
    const manifest = {
      schemaVersion: 1,
      repository: source.repository,
      revision,
      tree,
      ...content,
    };
    await writeFile(nextManifest, `${JSON.stringify(manifest, null, 2)}\n`);
    if (previous) {
      await verifySource(home, previous);
      await cp(join(home, "upstream"), backup, {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      backedUp = true;
      await rm(join(home, "upstream"), {
        recursive: true,
        maxRetries: 5,
        retryDelay: 200,
      });
    }
    promoted = true;
    await cp(staged, join(home, "upstream"), {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
    const copied = await fingerprint(join(home, "upstream"));
    if (copied.sha256 !== manifest.sha256 || copied.files !== manifest.files)
      throw new Error("Copied source verification failed");
    await rename(nextManifest, join(home, "source-lock.json"));
    committed = true;
    if (backedUp) await rm(backup, { recursive: true });
    return { state: "imported", manifest };
  } catch (error) {
    if (!committed) {
      if (promoted)
        await rm(join(home, "upstream"), {
          recursive: true,
          force: true,
          maxRetries: 5,
          retryDelay: 200,
        });
      if (backedUp)
        await cp(backup, join(home, "upstream"), {
          recursive: true,
          force: true,
        });
    }
    throw error;
  } finally {
    await rm(temporary, { recursive: true, force: true });
    await rm(staged, { recursive: true, force: true });
    await rm(nextManifest, { force: true });
  }
}

export function imageRecipe(upstreamRecipe) {
  const copy = "COPY --chown=webgoat target/webgoat-*.jar";
  const upstreamBase = "FROM docker.io/eclipse-temurin:25-jdk-noble";
  const pinnedBase =
    "eclipse-temurin:25-jdk-noble@sha256:f6366ccac38ceae180280ad7012d18a15e8031548a430dc2bae06631d9e88ed0";
  const rootRedirect =
    "overlay/src/main/java/org/owasp/webgoat/container/DojoRootRedirect.java";
  if (
    upstreamRecipe.split(copy).length !== 2 ||
    upstreamRecipe.split(upstreamBase).length !== 2
  )
    throw new Error(
      "Upstream Dockerfile packaging changed; review the image recipe",
    );
  return `FROM ${pinnedBase} AS dojo-build\nWORKDIR /src\nCOPY upstream/ .\nCOPY ${rootRedirect} src/main/java/org/owasp/webgoat/container/DojoRootRedirect.java\nRUN sed -i 's/\\r$//' mvnw && chmod +x mvnw && ./mvnw -B -DskipTests package\n${upstreamRecipe.replace(upstreamBase, `FROM ${pinnedBase}`).replace(copy, "COPY --from=dojo-build --chown=webgoat /src/target/webgoat-*.jar")}\nLABEL name="Code to Cloud Security Dojo" org.opencontainers.image.title="Code to Cloud Security Dojo"\n`;
}

export async function prepareDojoImage(home, source, output) {
  const manifest = await verifySource(home, source);
  const sourcePath = join(home, "upstream");
  await readFile(
    join(
      home,
      "overlay/src/main/java/org/owasp/webgoat/container/DojoRootRedirect.java",
    ),
    "utf8",
  );
  const recipe = imageRecipe(
    await readFile(join(sourcePath, "Dockerfile"), "utf8"),
  );
  await mkdir(output, { recursive: true });
  const dockerfile = join(output, "Dojo.Dockerfile");
  await writeFile(dockerfile, recipe);
  await writeFile(`${dockerfile}.dockerignore`, ".git\n**/target\n");
  return { contextPath: home, dockerfile, manifest };
}
