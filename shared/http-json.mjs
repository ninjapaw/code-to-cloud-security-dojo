export async function readJsonResponse(response, limit, label) {
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`${label} returned HTTP ${response.status}; check access and connectivity`);
  }
  if (!/^application\/json(?:;|$)/i.test(response.headers.get("content-type") || "")) {
    await response.body?.cancel();
    throw new Error(`${label} did not return JSON`);
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error(`${label} body is missing`);
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error(`${label} exceeds the ${limit / 1024} KiB collection limit`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
  } catch {
    throw new Error(`${label} did not return valid JSON`);
  }
}
