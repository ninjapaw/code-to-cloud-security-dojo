import {
  imageEvidenceKey,
  parsePackageInventory,
  summarizePackageScan,
  summarizeImageReceipt,
} from "./image-evidence.mjs";
export { sha256 } from "./image-evidence.mjs";

export const drowsyDragon = Object.freeze({
  id: "drowsy-dragon",
  title: "Drowsy Dragon",
  baseImage:
    "dhi.io/dotnet:8-sdk@sha256:238ae2cade2e61c0615dfdd416ff1857a343321e9e89de3b656b6f5c24ace8e8",
  packages: Object.freeze(["libc6", "libc-bin", "tar", "libgcrypt20"]),
  platform: "linux/amd64",
});

export const drowsyDragonRecipe = `FROM ${drowsyDragon.baseImage}\n\nRUN dpkg-query -W ${drowsyDragon.packages.join(" ")}\n\nCMD ["sleep", "infinity"]\n`;
export function drowsyDragonEvidenceKey(digest, scanHash) {
  return imageEvidenceKey(drowsyDragon.id, digest, scanHash);
}

export function parseDragonInventory(text) {
  return parsePackageInventory(text, drowsyDragon);
}

export function summarizeDragonScan(scan, imageId, packages) {
  return summarizePackageScan(scan, imageId, packages, drowsyDragon);
}

export function summarizeDragonReceipt(receipt, digest, scanHash) {
  const summary = summarizeImageReceipt(receipt, drowsyDragon, digest, scanHash);
  if (receipt.baseImage !== drowsyDragon.baseImage)
    throw new Error("Drowsy Dragon receipt does not match the deployed release");
  if (
    receipt.artifacts.dockerfile.replace(/\r\n/g, "\n") !== drowsyDragonRecipe
  )
    throw new Error("Drowsy Dragon recipe does not match the approved base and commands");
  return summary;
}
