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
    "dhi.io/dotnet:8-sdk@sha256:1ebc91b79beb49566cfb2a6a13bb6cdb42cea37e02b008248ae451e40aa7e792",
  packages: Object.freeze(["libc6", "libc-bin", "tar", "libgcrypt20"]),
  platform: "linux/amd64",
});

export const drowsyDragonRecipe = `ARG BASE_IMAGE=${drowsyDragon.baseImage}\nFROM \${BASE_IMAGE}\n\nRUN dpkg-query -W ${drowsyDragon.packages.join(" ")}\n\nCMD ["sleep", "infinity"]\n`;
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
