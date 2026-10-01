import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  sha256,
  parsePackageInventory,
  summarizePackageScan,
} from "../../shared/image-evidence.mjs";
import { run } from "./lifecycle.mjs";

export async function captureImageEvidence(image, output, definition, { execute = run } = {}) {
  await mkdir(output, { recursive: true });
  const imageId = await execute("docker", [
    "image", "inspect", image, "--format", "{{.Id}}",
  ]);
  if (!/^sha256:[a-f0-9]{64}$/.test(imageId))
    throw new Error(`${definition.title} image ID was not returned`);
  const inventory = `${await execute("docker", [
    "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--entrypoint", "dpkg-query",
    image, "-W", ...definition.packages,
  ])}\n`;
  const packages = parsePackageInventory(inventory, definition);
  const inventoryPath = join(output, "packages.txt");
  const scanJsonPath = join(output, "scan.json");
  const scanPath = join(output, "scan.sarif");
  await writeFile(inventoryPath, inventory);
  await execute("trivy", [
    "image", "--scanners", "vuln", "--list-all-pkgs",
    "--format", "json", "--output", scanJsonPath,
    "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "--exit-code", "0", image,
  ], { inherit: true });
  const scanJson = await readFile(scanJsonPath, "utf8");
  const summary = summarizePackageScan(JSON.parse(scanJson), imageId, packages, definition);
  await execute("trivy", [
    "convert", "--format", "sarif", "--output", scanPath, scanJsonPath,
  ], { inherit: true });
  return {
    evidence: {
      imageId,
      inventoryPath,
      inventoryHash: sha256(inventory),
      scanJsonPath,
      scanJsonHash: sha256(scanJson),
      scanPath,
      scanHash: sha256(await readFile(scanPath)),
      scannedAt: new Date().toISOString(),
    },
    summary: { packages, ...summary },
  };
}
