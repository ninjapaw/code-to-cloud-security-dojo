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
import { run, az } from "./lifecycle.mjs";
import { captureImageEvidence } from "./image-evidence.mjs";

const home = fileURLToPath(new URL("apps/drowsy-dragon/", root));
const recipePath = join(home, "Dockerfile");

export async function buildDrowsyDragon(image, output, { execute = run, repository = drowsyDragon.id, latest = false } = {}) {
  const dockerfile = await readFile(recipePath, "utf8");
  if (dockerfile.replace(/\r\n/g, "\n") !== drowsyDragonRecipe)
    throw new Error("Review the Drowsy Dragon recipe and approved pin before building");
  const sourceRevision = await execute("git", ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(sourceRevision))
    throw new Error("Drowsy Dragon requires a Git source revision");
  let baseImage = drowsyDragon.baseImage;
  if (latest) {
    const source = baseImage.split("@")[0];
    const manifest = JSON.parse(await execute("docker", [
      "buildx", "imagetools", "inspect", source,
      "--format", "{{json .Manifest}}",
    ]));
    if (!/^sha256:[a-f0-9]{64}$/.test(manifest?.digest || ""))
      throw new Error("Docker did not return a valid latest Drowsy Dragon base digest");
    baseImage = `${source}@${manifest.digest}`;
  }
  await mkdir(output, { recursive: true });
  await execute(
    "docker",
    [
      "build", "--platform", drowsyDragon.platform,
      ...(latest ? ["--pull", "--build-arg", `BASE_IMAGE=${baseImage}`] : []),
      "--label", "org.opencontainers.image.source=https://github.com/ninjapaw/code-to-cloud-security-dojo",
      "--label", `org.opencontainers.image.revision=${sourceRevision}`,
      "--label", `org.opencontainers.image.base.name=${baseImage}`,
      "-f", recipePath, "-t", image, home,
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
    dockerfileHash: sha256(dockerfile),
  };
  await writeFile(
    join(output, "local-image.json"),
    JSON.stringify({ ...entry, stage: "local-build-scanned", ...summary }, null, 2),
  );
  return entry;
}

export async function publishDrowsyDragonLatest(config, output, {
  execute = run,
  executeAz = (args, options) => az(config, args, options),
} = {}) {
  if (config.drowsyDragonEnabled !== true)
    throw new Error("Drowsy Dragon is not enabled for latest image publishing");
  const resourceNames = names(config);
  const entry = await buildDrowsyDragon(
    `${resourceNames.registry}.azurecr.io/${resourceNames.drowsyDragon}:latest`,
    output,
    { execute, repository: resourceNames.drowsyDragon, latest: true },
  );
  if (await execute("docker", [
    "image", "inspect", entry.image, "--format", "{{.Id}}",
  ]) !== entry.imageId)
    throw new Error("Drowsy Dragon latest image changed after scanning; rebuild before pushing");
  await executeAz(["acr", "login", "--name", resourceNames.registry]);
  await execute("docker", ["push", entry.image], { inherit: true });
  entry.digest = await executeAz([
    "acr", "manifest", "show-metadata", "--registry", resourceNames.registry,
    "--name", `${entry.repository}:latest`, "--query", "digest",
  ], { json: true });
  if (!/^sha256:[a-f0-9]{64}$/.test(entry.digest || ""))
    throw new Error("ACR did not return a valid Drowsy Dragon latest image digest");
  await writeFile(
    join(output, "published-image.json"),
    JSON.stringify({ ...entry, stage: "published-latest" }, null, 2),
  );
  return entry;
}

export async function readDragonReceipt(entry) {
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
