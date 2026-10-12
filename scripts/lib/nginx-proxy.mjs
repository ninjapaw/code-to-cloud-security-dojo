import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { root } from "../../shared/config.mjs";
import {
  nginxProxy,
  nginxMode,
  validateNginxSourceLock,
  validateNginxInventory,
  summarizeNginxReceipt,
} from "../../shared/nginx-proxy.mjs";
import { sha256 } from "../../shared/image-evidence.mjs";
import { fingerprint } from "./dojo-source.mjs";
import { captureImageEvidence } from "./image-evidence.mjs";
import { run } from "./lifecycle.mjs";
import { imageBaseArguments } from "./image-build.mjs";

const home = fileURLToPath(new URL("apps/nginx-proxy/", root));
const sourcePath = join(home, "upstream");
const recipePath = join(sourcePath, "Dockerfile");
const sourceLockPath = join(home, "source-lock.json");

export async function verifyNginxSource(directory = home) {
  const manifest = validateNginxSourceLock(JSON.parse(await readFile(join(directory, "source-lock.json"), "utf8")));
  const actual = await fingerprint(join(directory, "upstream"));
  if (actual.sha256 !== manifest.sha256 || actual.files !== manifest.files)
    throw new Error("NGINX Proxy snapshot has local changes; review the import before building");
  return manifest;
}

export async function buildNginxProxy(image, output, selectedMode, { execute = run, repository = nginxProxy.id, latest = false } = {}) {
  const mode = nginxMode(selectedMode);
  const source = await verifyNginxSource();
  let dockerfile = await readFile(recipePath, "utf8");
  const sourceLock = await readFile(sourceLockPath, "utf8");
  const sourceRevision = await execute("git", ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(sourceRevision))
    throw new Error("NGINX Proxy requires a Git source revision");
  await mkdir(output, { recursive: true });
  let buildRecipePath = recipePath;
  let baseImages;
  let buildArgs = [];
  if (latest) {
    const from = "FROM ${BASE_OS_IMAGE}:${BASE_OS_VERSION}";
    if (dockerfile.split(from).length !== 2)
      throw new Error("NGINX Proxy base recipe changed; review the latest build wrapper");
    dockerfile = `ARG BASE_IMAGE=ubuntu:24.04\n${dockerfile.replace(from, "FROM ${BASE_IMAGE}")}`;
    ({ baseImages, buildArgs } = await imageBaseArguments(dockerfile, { latest: true, execute }));
    dockerfile = dockerfile.replace("ARG BASE_IMAGE=ubuntu:24.04", `ARG BASE_IMAGE=${baseImages.BASE_IMAGE}`);
    buildRecipePath = join(output, "Dockerfile");
    await writeFile(buildRecipePath, dockerfile);
  }
  await execute("docker", [
    "build", "--platform", nginxProxy.platform, ...buildArgs,
    "--build-arg", `NGINX_VERSION=${mode.version}`,
    "--build-arg", `VULNERABILITY_STATUS=${mode.mode}`,
    "--build-arg", "BASE_OS_IMAGE=ubuntu",
    "--build-arg", "BASE_OS_VERSION=24.04",
    "--build-arg", "NODE_MAJOR_VERSION=24",
    "--build-arg", "PORT=3000",
    "--label", "org.opencontainers.image.source=https://github.com/ninjapaw/code-to-cloud-security-dojo",
    "--label", `org.opencontainers.image.revision=${sourceRevision}`,
    "--label", `dojo.upstream.revision=${source.revision}`,
    "--label", `security.repro.version=${mode.version}`,
    "--label", "security.repro.expected_result=Record actual scanner association; detection is not guaranteed",
    "-f", buildRecipePath, "-t", image, sourcePath,
  ], { inherit: true });
  const { evidence, summary } = await captureImageEvidence(image, output, nginxProxy, { execute });
  validateNginxInventory(summary.packages, mode.mode);
  await verifyNginxSource();
  const entry = {
    repository,
    image,
    mode: mode.mode,
    channel: latest ? "latest" : "pinned",
    ...(baseImages ? { baseImages } : {}),
    sourceRevision,
    dockerfilePath: buildRecipePath,
    dockerfileHash: sha256(dockerfile),
    sourceLockPath,
    sourceLockHash: sha256(sourceLock),
    sourceSnapshotHash: source.sha256,
    ...evidence,
  };
  await writeFile(
    join(output, "local-image.json"),
    JSON.stringify({ ...entry, stage: "local-build-scanned", upstream: source, ...summary }, null, 2),
  );
  return entry;
}

export async function readNginxReceipt(entry) {
  if (entry.channel === "latest")
    throw new Error("NGINX Proxy latest comparisons are not approved release receipts");
  await verifyNginxSource();
  const [dockerfile, sourceLock, inventory, scanJson, sarif] = await Promise.all([
    readFile(recipePath, "utf8"),
    readFile(entry.sourceLockPath, "utf8"),
    readFile(entry.inventoryPath, "utf8"),
    readFile(entry.scanJsonPath, "utf8"),
    readFile(entry.scanPath),
  ]);
  if (sha256(sarif) !== entry.scanHash)
    throw new Error("NGINX Proxy SARIF evidence hash mismatch");
  const receipt = {
    schemaVersion: 1,
    demoId: nginxProxy.id,
    mode: entry.mode,
    imageDigest: entry.digest,
    imageId: entry.imageId,
    sourceRevision: entry.sourceRevision,
    scannedAt: entry.scannedAt,
    hashes: {
      dockerfile: entry.dockerfileHash,
      sourceLock: entry.sourceLockHash,
      inventory: entry.inventoryHash,
      scanJson: entry.scanJsonHash,
      sarif: entry.scanHash,
    },
    artifacts: { dockerfile, sourceLock, inventory, scanJson },
  };
  summarizeNginxReceipt(receipt, entry.digest, entry.scanJsonHash);
  return receipt;
}
