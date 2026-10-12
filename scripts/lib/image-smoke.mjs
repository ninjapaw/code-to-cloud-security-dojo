import { setTimeout as delay } from "node:timers/promises";
import { run } from "./lifecycle.mjs";

export async function smokeTestImage(image, entry, {
  execute = run, fetcher = fetch, pause = () => delay(5000), attempts = 90, log = console.log,
} = {}) {
  if (!["dojo", "portal", "secret-bootstrap", "drowsy-dragon", "nginx-proxy"].includes(image) ||
      !/^sha256:[a-f0-9]{64}$/.test(entry.imageId || ""))
    throw new Error("Smoke tests require a supported image and a scanned image ID");
  if (await execute("docker", ["image", "inspect", entry.image, "--format", "{{.Id}}"]) !== entry.imageId)
    throw new Error("Test image changed after its security scan");
  if (image === "secret-bootstrap") {
    await execute("docker", [
      "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", entry.image, "--check", "scripts/secret-bootstrap.mjs",
    ], { inherit: true });
    log(`[test] ${entry.image}: utility syntax checked only; no credentials, Key Vault calls or grants`);
    return { state: "observed", kind: "syntax-only", image: entry.image, imageId: entry.imageId };
  }
  let container;
  let network;
  try {
    const sleeping = image === "drowsy-dragon";
    if (!sleeping) {
      network = await execute("docker", ["network", "create", "--internal", `image-test-${process.pid}-${Date.now()}`]);
      if (!/^[a-f0-9]{64}$/.test(network))
        throw new Error("Docker did not return an isolated smoke-test network ID");
    }
    const port = image === "nginx-proxy" ? "80" : "8080";
    container = await execute("docker", [
      "run", "--detach", "--network", sleeping ? "none" : network,
      "--security-opt", "no-new-privileges",
      ...(sleeping ? ["--read-only", "--cap-drop", "ALL"] : ["--publish", `127.0.0.1::${port}`]),
      entry.image,
      ...(image === "portal" ? ["apps/control-portal/server.mjs", "--preview"] : []),
    ]);
    if (!/^[a-f0-9]{64}$/.test(container))
      throw new Error("Docker did not return a smoke-test container ID");
    if (sleeping) {
      if (await execute("docker", ["inspect", container, "--format", "{{.State.Running}}"]) !== "true")
        throw new Error("Drowsy Dragon did not remain running with its sleeping entrypoint");
    } else {
      const endpoint = await execute("docker", ["port", container, `${port}/tcp`]);
      if (!/^127\.0\.0\.1:[0-9]{1,5}$/.test(endpoint) ||
          Number(endpoint.split(":")[1]) < 1 || Number(endpoint.split(":")[1]) > 65535)
        throw new Error("Smoke-test endpoint was not restricted to loopback");
      let ready = false;
      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          const response = await fetcher(`http://${endpoint}${image === "dojo" ? "/WebGoat/actuator/health" : "/health"}`, {
            redirect: "error", signal: AbortSignal.timeout(5000),
          });
          if (response.status === 200) {
            const result = await response.json();
            ready = image === "dojo" ? result.status === "UP"
              : image === "portal" ? result.status === "running" && result.mode === "read-only-preview" && result.codeRevision === entry.sourceRevision
                : result.status === "healthy" && result.environment === "training";
          } else await response.body?.cancel();
        } catch (error) {
          if (error.name !== "TimeoutError" &&
              !["ECONNREFUSED", "ECONNRESET", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET"].includes(error.cause?.code))
            throw error;
          log(`[test] ${image} health not ready (${error.name}); attempt ${attempt + 1}/${attempts}`);
        }
        if (ready) break;
        if (attempt + 1 < attempts) await pause();
      }
      if (!ready) {
        await execute("docker", ["logs", "--tail", "80", container], { inherit: true });
        throw new Error("Isolated image health did not match the expected runtime before timeout");
      }
    }
    log(`[test] ${entry.image}: ${sleeping ? "sleeping runtime observed without network access" : "isolated loopback health verified"}; image ID=${entry.imageId}`);
    return { state: "observed", kind: sleeping ? "sleeping-runtime" : "isolated-health", image: entry.image, imageId: entry.imageId };
  } finally {
    try {
      if (container && /^[a-f0-9]{64}$/.test(container))
        await execute("docker", ["rm", "--force", container]);
    } finally {
      if (network && /^[a-f0-9]{64}$/.test(network))
        await execute("docker", ["network", "rm", network]);
    }
  }
}
