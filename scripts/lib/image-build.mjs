import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { root, names } from "../../shared/config.mjs";
import { sha256 } from "../../shared/image-evidence.mjs";
import { prepareDojoImage, verifySource } from "./dojo-source.mjs";
import { run, az } from "./lifecycle.mjs";

export async function resolveLatestBaseImage(baseImage, { execute = run } = {}) {
  const source = baseImage.split("@")[0];
  if (!/^[a-z0-9][a-z0-9./:_-]+$/.test(source) || !source.split("/").at(-1).includes(":"))
    throw new Error("Latest builds require a reviewed tagged base image");
  const manifest = JSON.parse(await execute("docker", [
    "buildx", "imagetools", "inspect", source, "--format", "{{json .Manifest}}",
  ]));
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest?.digest || ""))
    throw new Error("Docker did not return a valid latest base image digest");
  return `${source}@${manifest.digest}`;
}

export async function imageBaseArguments(recipe, { latest = false, execute = run } = {}) {
  const argumentsSection = recipe.slice(0, recipe.search(/^FROM\s/m));
  const variables = [...new Set([...recipe.matchAll(/^FROM\s+\$\{([A-Z][A-Z0-9_]*)\}(?:\s+AS\s+[\w-]+)?\r?$/gm)]
    .map((match) => match[1]))];
  if (!variables.length)
    throw new Error("Image recipe must expose reviewed base image arguments");
  const baseImages = {};
  for (const variable of variables) {
    const definitions = [...argumentsSection.matchAll(new RegExp(`^ARG ${variable}=(\\S+)\\r?$`, "gm"))];
    if (definitions.length !== 1)
      throw new Error(`Image recipe requires one approved default for ${variable}`);
    baseImages[variable] = latest
      ? await resolveLatestBaseImage(definitions[0][1], { execute })
      : definitions[0][1];
  }
  return {
    baseImages,
    buildArgs: latest
      ? ["--pull", ...Object.entries(baseImages).flatMap(([key, value]) => ["--build-arg", `${key}=${value}`])]
      : [],
  };
}

export async function buildCoreImage(component, image, output, {
  source, latest = false, scan = true, repository = component, execute = run,
} = {}) {
  const directory = fileURLToPath(root);
  let context = directory;
  let dockerfile;
  let manifest;
  if (component === "dojo") {
    context = fileURLToPath(new URL("apps/dojo/", root));
    const prepared = await prepareDojoImage(context, source, output);
    dockerfile = prepared.dockerfile;
    manifest = prepared.manifest;
  } else if (component === "portal") {
    dockerfile = fileURLToPath(new URL("apps/control-portal/Dockerfile", root));
  } else if (component === "secretBootstrap") {
    dockerfile = fileURLToPath(new URL("scripts/Dockerfile.secret-bootstrap", root));
  } else {
    throw new Error("Core image must be dojo, portal or secretBootstrap");
  }
  const sourceRevision = await execute("git", ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(sourceRevision))
    throw new Error("Image build requires a Git source revision");
  let recipe = await readFile(dockerfile, "utf8");
  const { baseImages, buildArgs } = await imageBaseArguments(recipe, { latest, execute });
  await mkdir(output, { recursive: true });
  if (latest) {
    for (const [key, value] of Object.entries(baseImages))
      recipe = recipe.replace(new RegExp(`^ARG ${key}=\\S+\\r?$`, "m"), `ARG ${key}=${value}`);
    const ignorePath = `${dockerfile}.dockerignore`;
    dockerfile = join(output, "Dockerfile");
    await writeFile(dockerfile, recipe);
    if (component === "dojo")
      await writeFile(`${dockerfile}.dockerignore`, await readFile(ignorePath));
  }
  await execute("docker", [
    "build", "--platform", "linux/amd64", ...buildArgs,
    "--label", `org.opencontainers.image.source=${manifest ? source.repository.replace(/\.git$/, "") : "https://github.com/ninjapaw/code-to-cloud-security-dojo"}`,
    "--label", `org.opencontainers.image.revision=${manifest ? manifest.revision : sourceRevision}`,
    ...(manifest ? ["--label", `dojo.source.sha256=${manifest.sha256}`] : []),
    ...(component === "portal" ? ["--build-arg", `DOJO_CODE_REVISION=${sourceRevision}`] : []),
    "-f", dockerfile, "-t", image, context,
  ], { inherit: true });
  if (manifest) await verifySource(context, source);
  const imageId = await execute("docker", ["image", "inspect", image, "--format", "{{.Id}}"]);
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId))
    throw new Error("Docker did not return a valid built image ID");
  const entry = {
    schemaVersion: 1,
    repository, image, imageId, sourceRevision,
    channel: latest ? "latest" : "pinned",
    baseImages,
    dockerfilePath: dockerfile,
    dockerfileHash: sha256(recipe),
    ...(manifest ? { source: manifest } : {}),
  };
  if (scan) {
    const scanPath = join(output, "scan.sarif");
    await execute("trivy", [
      "image", "--scanners", "vuln", "--format", "sarif", "--output", scanPath,
      "--severity", "HIGH,CRITICAL", "--exit-code", component === "dojo" ? "0" : "1",
      image,
    ], { inherit: true });
    Object.assign(entry, {
      scanPath,
      scanHash: sha256(await readFile(scanPath)),
      scannedAt: new Date().toISOString(),
    });
  }
  await writeFile(join(output, "local-image.json"), JSON.stringify({
    ...entry, stage: scan ? "local-build-scanned" : "local-build-unscanned",
  }, null, 2));
  return entry;
}

export async function publishLatestImage(config, entry, output, {
  execute = run,
  executeAz = (args, options) => az(config, args, options),
} = {}) {
  const resourceNames = names(config);
  if (
    entry.channel !== "latest" ||
    ![resourceNames.dojo, resourceNames.portal, resourceNames.drowsyDragon, resourceNames.nginxProxy, "secret-bootstrap"].includes(entry.repository) ||
    entry.image !== `${resourceNames.registry}.azurecr.io/${entry.repository}:latest`
  )
    throw new Error("Latest publication requires an owned repository and an explicitly latest-built image");
  for (const key of ["scan", "scanJson", "inventory", "dockerfile", "sourceLock"]) {
    if (key !== "scan" && entry[`${key}Hash`] === undefined) continue;
    if (
      !/^[a-f0-9]{64}$/.test(entry[`${key}Hash`] || "") ||
      typeof entry[`${key}Path`] !== "string" ||
      sha256(await readFile(entry[`${key}Path`])) !== entry[`${key}Hash`]
    )
      throw new Error(`${entry.repository} ${key} evidence changed before latest publication`);
  }
  if (await execute("docker", [
    "image", "inspect", entry.image, "--format", "{{.Id}}",
  ]) !== entry.imageId)
    throw new Error(`${entry.repository} image changed after scanning; rebuild before pushing`);
  await executeAz(["acr", "login", "--name", resourceNames.registry]);
  await execute("docker", ["push", entry.image], { inherit: true });
  const digest = await executeAz([
    "acr", "manifest", "show-metadata", "--registry", resourceNames.registry,
    "--name", `${entry.repository}:latest`, "--query", "digest",
  ], { json: true });
  if (!/^sha256:[a-f0-9]{64}$/.test(digest || ""))
    throw new Error("ACR did not return a valid latest image digest");
  const published = { ...entry, digest };
  await writeFile(
    join(output, "published-image.json"),
    JSON.stringify({ ...published, stage: "published-latest" }, null, 2),
  );
  return published;
}
