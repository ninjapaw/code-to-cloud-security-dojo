import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { names } from "../../shared/config.mjs";
import { sha256 } from "../../shared/image-evidence.mjs";
import { run, az } from "./lifecycle.mjs";

const digestPattern = /^sha256:[a-f0-9]{64}$/;
const evidenceFiles = {
  scan: "scan.sarif",
  scanJson: "scan.json",
  inventory: "packages.txt",
  dockerfile: "Dockerfile",
  sourceLock: "source-lock.json",
};

function sourceBaseEntries(baseImages) {
  if (!baseImages || typeof baseImages !== "object" || Array.isArray(baseImages) || !Object.keys(baseImages).length)
    throw new Error("Archive requires resolved source base hashes");
  const entries = Object.entries(baseImages);
  for (const [variable, reference] of entries)
    if (!/^[A-Z][A-Z0-9_]{0,31}$/.test(variable) || !/^[^@\s]+@sha256:[a-f0-9]{64}$/.test(reference))
      throw new Error("Archive requires resolved source base hashes");
  return entries;
}

export function sourceArchiveTags(baseImages, digest) {
  if (!digestPattern.test(digest))
    throw new Error("Archive requires a complete image manifest digest");
  return [...new Set(sourceBaseEntries(baseImages).map(([variable, reference]) => {
    const kind = variable.toLowerCase().replace(/_image$/, "");
    return `${kind === "base" ? "base" : `base-${kind}`}-sha256-${reference.split("@")[1].slice(7)}-${digest.slice(7, 23)}`;
  }))];
}

export async function publishImageArchive(config, entry, output, {
  promoteLatest = false,
  execute = run,
  executeAz = (args, options) => az(config, args, options),
  log = console.log,
  pause = (attempt) => delay(Math.min(1000 * 2 ** attempt, 8000)),
} = {}) {
  const resourceNames = names(config);
  const prefix = `${resourceNames.registry}.azurecr.io/${entry.repository}`;
  if (
    ![resourceNames.dojo, resourceNames.portal, resourceNames.drowsyDragon, resourceNames.nginxProxy, "secret-bootstrap"].includes(entry.repository) ||
    !digestPattern.test(entry.imageId || "") ||
    !/^[a-f0-9]{40}$/.test(entry.sourceRevision || "") ||
    !Number.isFinite(Date.parse(entry.scannedAt)) ||
    (promoteLatest
      ? entry.channel !== "latest" || entry.image !== `${prefix}:latest`
      : entry.channel !== "test" || !entry.image.startsWith(`${prefix}:test-`))
  )
    throw new Error("Archive publication requires an owned repository and an explicitly latest or test-built image");
  const baseImages = entry.baseImages ?? { BASE_IMAGE: entry.baseImage };
  sourceBaseEntries(baseImages);
  for (const [key] of Object.entries(evidenceFiles)) {
    if (key !== "scan" && entry[`${key}Hash`] === undefined) continue;
    if (
      !/^[a-f0-9]{64}$/.test(entry[`${key}Hash`] || "") ||
      typeof entry[`${key}Path`] !== "string" ||
      sha256(await readFile(entry[`${key}Path`])) !== entry[`${key}Hash`]
    )
      throw new Error(`${entry.repository} ${key} evidence changed before archive publication`);
  }
  if (await execute("docker", ["image", "inspect", entry.image, "--format", "{{.Id}}"]) !== entry.imageId)
    throw new Error(`${entry.repository} image changed after scanning; rebuild before pushing`);
  log(`[hash] ${entry.repository}: image ID=${entry.imageId}; code=${entry.sourceRevision}; scan SHA256=${entry.scanHash}; scanned=${entry.scannedAt}`);
  for (const [variable, reference] of Object.entries(baseImages))
    log(`[hash] ${entry.repository} ${variable}: source manifest=${reference}; platform=linux/amd64`);
  await executeAz(["acr", "login", "--name", resourceNames.registry]);
  const repositories = await executeAz(["acr", "repository", "list", "--name", resourceNames.registry], { json: true });
  if (!Array.isArray(repositories) || repositories.some((repository) => typeof repository !== "string"))
    throw new Error("ACR did not return its repository inventory");
  let repositoryExists = repositories.includes(entry.repository);
  const metadata = async (reference, query = "digest") => {
    const result = await executeAz([
      "acr", "manifest", "show-metadata", "--registry", resourceNames.registry,
      "--name", `${entry.repository}${reference}`, "--query", query,
    ], { json: true });
    if (query === "digest" && !digestPattern.test(result || ""))
      throw new Error("ACR did not return a valid archive image digest");
    return result;
  };
  const findTag = async (tag) => {
    if (!/^[a-z0-9][a-z0-9_.-]{0,127}$/.test(tag))
      throw new Error("Archive tag exceeds Docker's supported format or length");
    if (!repositoryExists) return undefined;
    const matches = await executeAz([
      "acr", "repository", "show-tags", "--name", resourceNames.registry,
      "--repository", entry.repository, "--detail",
      "--query", `[?name=='${tag}'].{name:name,digest:digest}`,
    ], { json: true });
    if (!Array.isArray(matches) || matches.length > 1 ||
        matches.some((item) => item?.name !== tag || !digestPattern.test(item.digest || "")))
      throw new Error("ACR returned invalid archive tag metadata");
    return matches[0]?.digest;
  };
  const checkConfig = async (digest, imageId) => {
    let manifest = JSON.parse(await execute("docker", [
      "buildx", "imagetools", "inspect", `${prefix}@${digest}`, "--raw",
    ]));
    let platformDigest = digest;
    if (Array.isArray(manifest?.manifests)) {
      const platforms = manifest.manifests.filter((item) =>
        item.platform?.os === "linux" && item.platform.architecture === "amd64");
      if (platforms.length !== 1 || !digestPattern.test(platforms[0].digest || ""))
        throw new Error("Archive index does not identify one linux/amd64 image");
      platformDigest = platforms[0].digest;
      manifest = JSON.parse(await execute("docker", [
        "buildx", "imagetools", "inspect", `${prefix}@${platformDigest}`, "--raw",
      ]));
    }
    if (manifest?.config?.digest !== imageId)
      throw new Error("Archived manifest does not match the scanned Docker image ID");
    return platformDigest;
  };
  const push = async (localImage, tag) => {
    await execute("docker", ["tag", localImage, `${prefix}:${tag}`]);
    await execute("docker", ["push", `${prefix}:${tag}`], { inherit: true });
    repositoryExists = true;
    return metadata(`:${tag}`);
  };
  const verifyProtection = async (check, label) => {
    let detail;
    for (let attempt = 0; attempt < 6; attempt++) {
      const observed = await check();
      if (observed.ready) return;
      detail = observed.detail;
      log(`[archive] ${label} readback pending (${attempt + 1}/6): ${detail}`);
      if (attempt < 5) await pause(attempt);
    }
    throw new Error(`${label} was not verified after bounded readback: ${detail}`);
  };
  const lockTag = async (tag, digest) => {
    await executeAz([
      "acr", "repository", "update", "--name", resourceNames.registry,
      "--image", `${entry.repository}:${tag}`, "--write-enabled", "false", "--delete-enabled", "false",
    ]);
    await verifyProtection(async () => {
      const observed = await executeAz([
        "acr", "repository", "show", "--name", resourceNames.registry,
        "--image", `${entry.repository}:${tag}`,
      ], { json: true });
      return {
        ready: observed?.digest === digest && observed.changeableAttributes?.writeEnabled === false &&
          observed.changeableAttributes?.deleteEnabled === false,
        detail: `tag=${tag}; expected digest=${digest}; observed digest=${observed?.digest ?? "missing"}; writeEnabled=${observed?.changeableAttributes?.writeEnabled ?? "missing"}; deleteEnabled=${observed?.changeableAttributes?.deleteEnabled ?? "missing"}`,
      };
    }, "ACR archive tag lock");
    log(`[archive] Locked ${prefix}:${tag} -> ${digest}`);
  };
  const protectManifest = async (digest) => {
    await executeAz([
      "acr", "repository", "update", "--name", resourceNames.registry,
      "--image", `${entry.repository}@${digest}`, "--delete-enabled", "false",
    ]);
    await verifyProtection(async () => {
      const observed = await metadata(`@${digest}`, "changeableAttributes.deleteEnabled");
      return { ready: observed === false, detail: `manifest=${digest}; deleteEnabled=${observed ?? "missing"}` };
    }, "ACR archive manifest deletion protection");
  };
  const ensureTag = async (localImage, tag, digest) => {
    const existing = await findTag(tag);
    if (existing && existing !== digest)
      throw new Error(`Refusing to overwrite archive tag ${tag} with a different image digest`);
    if (!existing && await push(localImage, tag) !== digest)
      throw new Error("ACR archive alias digest did not match the scanned image");
    await lockTag(tag, digest);
  };
  const imageIdTag = `image-sha256-${entry.imageId.slice(7)}`;
  const previousLatestDigest = promoteLatest ? await findTag("latest") : undefined;
  if (promoteLatest) log(`[hash] ${entry.repository}: previous hosted latest manifest=${previousLatestDigest ?? "not-published"}`);
  let digest = await findTag(imageIdTag);
  if (!digest) digest = await push(entry.image, imageIdTag);
  const platformDigest = await checkConfig(digest, entry.imageId);
  await lockTag(imageIdTag, digest);
  const archiveTags = [imageIdTag, `sha256-${digest.slice(7)}`, ...sourceArchiveTags(baseImages, digest)];
  for (const tag of archiveTags.slice(1))
    await ensureTag(entry.image, tag, digest);
  await protectManifest(digest);
  if (platformDigest !== digest) await protectManifest(platformDigest);

  await mkdir(output, { recursive: true });
  const evidence = await mkdtemp(join(output, "archive-evidence-"));
  const hashes = {};
  for (const [key, filename] of Object.entries(evidenceFiles)) {
    if (entry[`${key}Hash`] === undefined) continue;
    await copyFile(entry[`${key}Path`], join(evidence, filename));
    if (sha256(await readFile(join(evidence, filename))) !== entry[`${key}Hash`])
      throw new Error("Scan evidence changed while creating its archive bundle");
    hashes[filename] = entry[`${key}Hash`];
  }
  const record = {
    schemaVersion: 1,
    image: `${prefix}@${digest}`,
    imageId: entry.imageId,
    archiveTags,
    baseImages,
    sourceRevision: entry.sourceRevision,
    scannedAt: entry.scannedAt,
    scanner: "Trivy",
    channel: entry.channel,
    ...(entry.source ? { source: entry.source } : {}),
    ...(entry.sourceSnapshotHash ? { sourceSnapshotHash: entry.sourceSnapshotHash } : {}),
    ...(entry.mode ? { mode: entry.mode } : {}),
    hashes,
  };
  await writeFile(join(evidence, "manifest.json"), JSON.stringify(record, null, 2));
  const bundleHash = sha256([
    ...Object.entries(hashes),
    ["manifest.json", sha256(await readFile(join(evidence, "manifest.json")))],
  ].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([name, hash]) => `${name}\0${hash}\n`).join(""));
  const evidenceTag = `evidence-sha256-${bundleHash}`;
  const scanTag = `scan-${digest.slice(7)}-${bundleHash.slice(0, 32)}`;
  const evidenceImage = `${prefix}:${evidenceTag}`;
  const evidenceRecipe = join(output, "Evidence.Dockerfile");
  await writeFile(evidenceRecipe, `FROM scratch\nCOPY . /evidence/\nLABEL org.opencontainers.image.title="Archived container security evidence" io.ninjapaw.artifact.kind="image-security-evidence" io.ninjapaw.image.digest="${digest}" io.ninjapaw.evidence.sha256="${bundleHash}"\n`);
  await execute("docker", [
    "build", "--platform", "linux/amd64", "-f", evidenceRecipe, "-t", evidenceImage, evidence,
  ], { inherit: true });
  const evidenceId = await execute("docker", ["image", "inspect", evidenceImage, "--format", "{{.Id}}"]);
  if (!digestPattern.test(evidenceId))
    throw new Error("Docker did not return a valid scan evidence image ID");
  let evidenceDigest = await findTag(evidenceTag);
  if (!evidenceDigest) evidenceDigest = await push(evidenceImage, evidenceTag);
  const evidencePlatformDigest = await checkConfig(evidenceDigest, evidenceId);
  await lockTag(evidenceTag, evidenceDigest);
  await ensureTag(evidenceImage, scanTag, evidenceDigest);
  await protectManifest(evidenceDigest);
  if (evidencePlatformDigest !== evidenceDigest) await protectManifest(evidencePlatformDigest);
  if (promoteLatest) {
    await execute("docker", ["push", `${prefix}:latest`], { inherit: true });
    if (await metadata(":latest") !== digest)
      throw new Error("Latest readback did not match the archived image digest");
    log(`[hash] ${entry.repository}: previous latest=${previousLatestDigest ?? "not-published"}; current latest=${digest}`);
  }
  const published = {
    ...entry,
    image: promoteLatest ? `${prefix}:latest` : `${prefix}:sha256-${digest.slice(7)}`,
    digest,
    ...(promoteLatest ? { previousLatestDigest: previousLatestDigest ?? null } : {}),
    archiveTags,
    scanArchive: { image: `${prefix}:${scanTag}`, digest: evidenceDigest, bundleHash, tags: [evidenceTag, scanTag] },
  };
  await writeFile(join(output, "published-image.json"), JSON.stringify({
    ...published, stage: promoteLatest ? "published-latest" : "published-test",
  }, null, 2));
  log(`[hash] Published ${published.image}; image manifest=${digest}; scan archive=${published.scanArchive.image}@${evidenceDigest}; evidence SHA256=${bundleHash}`);
  return published;
}

export function imageArchiveSummary(entry) {
  const prefix = entry.image.slice(0, entry.image.lastIndexOf(":"));
  const baseImages = entry.baseImages ?? { BASE_IMAGE: entry.baseImage };
  return [
    `### ${entry.repository}: ${entry.channel} image archive`, "",
    `- Image manifest: \`${entry.digest}\``,
    `- Docker image ID: \`${entry.imageId}\``,
    ...Object.entries(baseImages).map(([variable, reference]) => `- ${variable}: \`${reference}\``),
    `- Code revision: \`${entry.sourceRevision}\``,
    `- Scan SHA256: \`${entry.scanHash}\`; scanned: ${entry.scannedAt}`,
    `- Durable scan bundle: \`${entry.scanArchive.image}\``,
    ...(entry.channel === "latest" ? [`- Previous latest: \`${entry.previousLatestDigest ?? "not-published"}\`; current latest: \`${entry.digest}\``] : []),
    ...entry.archiveTags.map((tag) => `- Locked image tag: \`${prefix}:${tag}\``), "",
  ].join("\n");
}
