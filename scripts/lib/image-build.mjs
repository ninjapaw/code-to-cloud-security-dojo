import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { root } from "../../shared/config.mjs";
import { sha256 } from "../../shared/image-evidence.mjs";
import { prepareDojoImage, verifySource } from "./dojo-source.mjs";
import { run } from "./lifecycle.mjs";
import { publishImageArchive } from "./image-archive.mjs";

export async function resolveLatestBaseImage(baseImage, { execute = run, selection = "latest", log = console.log } = {}) {
  const source = baseImage.split("@")[0];
  if (!/^[a-z0-9][a-z0-9./:_-]+$/.test(source) || !source.split("/").at(-1).includes(":"))
    throw new Error("Latest builds require a reviewed tagged base image");
  if (selection !== "latest" && !/^sha256:[a-f0-9]{64}$/.test(selection))
    throw new Error("Base selection must be latest or a complete sha256 digest");
  const reference = selection === "latest" ? source : `${source}@${selection}`;
  const manifest = JSON.parse(await execute("docker", [
    "buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest}}",
  ]));
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest?.digest || ""))
    throw new Error("Docker did not return a valid latest base image digest");
  if (selection !== "latest" && manifest.digest !== selection)
    throw new Error("Registry did not return the explicitly selected source digest");
  log(`[hash] Base track=${source}; approved default=${baseImage}; selection=${selection}; resolved source SHA=${manifest.digest}; platform=linux/amd64`);
  return `${source}@${manifest.digest}`;
}

export function imageBaseDefaults(recipe) {
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
    baseImages[variable] = definitions[0][1];
  }
  return baseImages;
}

export async function imageBaseArguments(recipe, { latest = false, baseOverrides = {}, execute = run, log = console.log } = {}) {
  const defaults = imageBaseDefaults(recipe);
  if (!baseOverrides || typeof baseOverrides !== "object" || Array.isArray(baseOverrides) ||
      Object.keys(baseOverrides).some((key) => !Object.hasOwn(defaults, key)) ||
      Object.values(baseOverrides).some((selection) => selection !== "latest" && !/^sha256:[a-f0-9]{64}$/.test(selection)))
    throw new Error("Base overrides must select known image arguments with latest or complete SHA256 digests");
  const modified = latest || Object.keys(baseOverrides).length > 0;
  const baseImages = {};
  for (const [variable, approved] of Object.entries(defaults)) {
    baseImages[variable] = modified
      ? await resolveLatestBaseImage(approved, { execute, selection: baseOverrides[variable] ?? "latest", log })
      : approved;
    if (!modified) log(`[hash] ${variable}: approved base=${approved}; channel=pinned; platform=linux/amd64`);
  }
  return {
    baseImages,
    buildArgs: modified
      ? ["--pull", ...Object.entries(baseImages).flatMap(([key, value]) => ["--build-arg", `${key}=${value}`])]
      : [],
  };
}

export async function buildCoreImage(component, image, output, {
  source, latest = false, baseOverrides = {}, scan = true, repository = component, execute = run, log = console.log,
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
  const { baseImages, buildArgs } = await imageBaseArguments(recipe, { latest, baseOverrides, execute, log });
  const modified = latest || Object.keys(baseOverrides).length > 0;
  await mkdir(output, { recursive: true });
  if (modified) {
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
    channel: Object.keys(baseOverrides).length ? "test" : latest ? "latest" : "pinned",
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
  log(`[hash] Built ${image}; channel=${entry.channel}; image ID=${imageId}; code=${sourceRevision}; scan SHA256=${entry.scanHash ?? "not-scanned"}`);
  return entry;
}

export async function publishLatestImage(config, entry, output, options = {}) {
  return publishImageArchive(config, entry, output, { ...options, promoteLatest: true });
}
