import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { root, names } from "../../shared/config.mjs";
import {
  drowsyDragon,
  drowsyDragonRecipe,
  sha256,
  summarizeDragonReceipt,
} from "../../shared/drowsy-dragon.mjs";
import { run } from "./lifecycle.mjs";
import { captureImageEvidence } from "./image-evidence.mjs";
import { resolveLatestBaseImage, publishLatestImage } from "./image-build.mjs";

const home = fileURLToPath(new URL("apps/drowsy-dragon/", root));
const recipePath = join(home, "Dockerfile");

export async function buildDrowsyDragon(image, output, { execute = run, repository = drowsyDragon.id, latest = false, baseOverrides = {}, log = console.log } = {}) {
  let dockerfile = await readFile(recipePath, "utf8");
  if (dockerfile.replace(/\r\n/g, "\n") !== drowsyDragonRecipe)
    throw new Error("Review the Drowsy Dragon recipe and approved pin before building");
  const sourceRevision = await execute("git", ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(sourceRevision))
    throw new Error("Drowsy Dragon requires a Git source revision");
  if (!baseOverrides || typeof baseOverrides !== "object" || Array.isArray(baseOverrides) ||
      Object.keys(baseOverrides).some((key) => key !== "BASE_IMAGE"))
    throw new Error("Drowsy Dragon supports only the BASE_IMAGE override");
  const modified = latest || Object.keys(baseOverrides).length > 0;
  let baseImage = drowsyDragon.baseImage;
  if (modified) baseImage = await resolveLatestBaseImage(baseImage, { execute, selection: baseOverrides.BASE_IMAGE ?? "latest", log });
  else log(`[hash] Drowsy Dragon approved base=${baseImage}; channel=pinned`);
  await mkdir(output, { recursive: true });
  let buildRecipePath = recipePath;
  if (modified) {
    dockerfile = dockerfile.replace(drowsyDragon.baseImage, baseImage);
    buildRecipePath = join(output, "Dockerfile");
    await writeFile(buildRecipePath, dockerfile);
  }
  await execute(
    "docker",
    [
      "build", "--platform", drowsyDragon.platform,
      ...(modified ? ["--pull", "--build-arg", `BASE_IMAGE=${baseImage}`] : []),
      "--label", "org.opencontainers.image.source=https://github.com/ninjapaw/code-to-cloud-security-dojo",
      "--label", `org.opencontainers.image.revision=${sourceRevision}`,
      "--label", `org.opencontainers.image.base.name=${baseImage}`,
      "-f", buildRecipePath, "-t", image, home,
    ],
    { inherit: true },
  );
  const { evidence, summary } = await captureImageEvidence(
    image, output, drowsyDragon, { execute },
  );
  const entry = {
    repository,
    image,
    ...evidence,
    sourceRevision,
    baseImage,
    channel: Object.keys(baseOverrides).length ? "test" : latest ? "latest" : "pinned",
    dockerfilePath: buildRecipePath,
    dockerfileHash: sha256(dockerfile),
  };
  await writeFile(
    join(output, "local-image.json"),
    JSON.stringify({ ...entry, stage: "local-build-scanned", ...summary }, null, 2),
  );
  log(`[hash] Built ${image}; channel=${entry.channel}; source base=${baseImage}; image ID=${entry.imageId}; scan SHA256=${entry.scanHash}`);
  return entry;
}

export async function publishDrowsyDragonLatest(config, output, options = {}) {
  if (config.drowsyDragonEnabled !== true)
    throw new Error("Drowsy Dragon is not enabled for latest image publishing");
  const resourceNames = names(config);
  const entry = await buildDrowsyDragon(
    `${resourceNames.registry}.azurecr.io/${resourceNames.drowsyDragon}:latest`,
    output,
    { ...options, repository: resourceNames.drowsyDragon, latest: true },
  );
  return publishLatestImage(config, entry, output, options);
}

export async function readDragonReceipt(entry) {
  if (["latest", "test"].includes(entry.channel))
    throw new Error("Drowsy Dragon latest/test comparisons are not approved release receipts");
  const [dockerfile, inventory, scanJson, sarif] = await Promise.all([
    readFile(recipePath, "utf8"),
    readFile(entry.inventoryPath, "utf8"),
    readFile(entry.scanJsonPath, "utf8"),
    readFile(entry.scanPath),
  ]);
  if (sha256(sarif) !== entry.scanHash)
    throw new Error("Drowsy Dragon SARIF evidence hash mismatch");
  const receipt = {
    schemaVersion: 1,
    demoId: drowsyDragon.id,
    imageDigest: entry.digest,
    imageId: entry.imageId,
    sourceRevision: entry.sourceRevision,
    baseImage: entry.baseImage,
    scannedAt: entry.scannedAt,
    hashes: {
      dockerfile: entry.dockerfileHash,
      inventory: entry.inventoryHash,
      scanJson: entry.scanJsonHash,
      sarif: entry.scanHash,
    },
    artifacts: { dockerfile, inventory, scanJson },
  };
  summarizeDragonReceipt(receipt, entry.digest, entry.scanJsonHash);
  return receipt;
}
