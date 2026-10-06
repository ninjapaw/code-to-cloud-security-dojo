import { imageEvidenceKey, sha256 } from "./image-evidence.mjs";
import { summarizeDragonReceipt } from "./drowsy-dragon.mjs";
import { summarizeNginxReceipt } from "./nginx-proxy.mjs";

export const imageReceiptLimit = 16 * 1024 * 1024;

export function imageReceiptMetadata(receipt) {
  const serialized = JSON.stringify(receipt);
  if (!serialized || Buffer.byteLength(serialized) > imageReceiptLimit)
    throw new Error("Image receipt is missing or exceeds the publication limit");
  const summarize = {
    "drowsy-dragon": summarizeDragonReceipt,
    "nginx-proxy": summarizeNginxReceipt,
  };
  if (!Object.hasOwn(summarize, receipt?.demoId))
    throw new Error("Unsupported image receipt");
  summarize[receipt.demoId](receipt, receipt.imageDigest, receipt.hashes?.scanJson);
  return {
    key: imageEvidenceKey(receipt.demoId, receipt.imageDigest, receipt.hashes.scanJson),
    demoId: receipt.demoId,
    imageDigest: receipt.imageDigest,
    scanHash: receipt.hashes.scanJson,
    receiptHash: sha256(serialized),
  };
}

export async function publishImageReceipt(store, receipt) {
  const metadata = imageReceiptMetadata(receipt);
  try {
    await store.put(metadata.key, receipt, { ifAbsent: true });
  } catch (error) {
    if (![409, 412].includes(error.statusCode)) throw error;
  }
  const stored = await store.get(metadata.key);
  if (!stored || sha256(JSON.stringify(stored)) !== metadata.receiptHash)
    throw Object.assign(new Error("Image receipt readback does not match"), {
      status: 409,
    });
  return metadata;
}
