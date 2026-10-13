import { setTimeout as delay } from "node:timers/promises";
import { run } from "./lifecycle.mjs";

export async function smokeTestImage(image, entry, {
  execute = run, pause = () => delay(5000), attempts = 90, log = console.log,
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
      ...(sleeping ? ["--read-only", "--cap-drop", "ALL"] : []),
      entry.image,
      ...(image === "portal" ? ["apps/control-portal/server.mjs", "--preview"] : []),
    ]);
    if (!/^[a-f0-9]{64}$/.test(container))
      throw new Error("Docker did not return a smoke-test container ID");
    if (sleeping) {
      if (await execute("docker", ["inspect", container, "--format", "{{.State.Running}}"]) !== "true")
        throw new Error("Drowsy Dragon did not remain running with its sleeping entrypoint");
    } else {
      const endpoint = `http://127.0.0.1:${port}${image === "dojo" ? "/WebGoat/actuator/health" : "/health"}`;
      let probe = ["curl", "--silent", "--show-error", "--max-time", "5", "--write-out", "\n%{http_code}", endpoint];
      if (image === "portal") {
        const entrypoint = JSON.parse(await execute("docker", [
          "image", "inspect", entry.image, "--format", "{{json .Config.Entrypoint}}",
        ]));
        if (!Array.isArray(entrypoint) || entrypoint.length !== 1 ||
            typeof entrypoint[0] !== "string" || !/^\/[A-Za-z0-9/_-]+\/node$/.test(entrypoint[0]))
          throw new Error("Portal smoke probe requires the reviewed Node executable entrypoint");
        probe = [entrypoint[0], "--input-type=module", "-e", `
try {
  const response = await fetch(${JSON.stringify(endpoint)}, { redirect: "error", signal: AbortSignal.timeout(5000) });
  process.stdout.write((await response.text()) + "\\n" + response.status);
} catch (error) {
  if (error.name === "TimeoutError" || ["ECONNREFUSED", "ECONNRESET", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET"].includes(error.cause?.code)) {
    console.error("Container-local health not ready: " + (error.cause?.code ?? error.name));
    process.exitCode = 75;
  } else throw error;
}
`];
      }
      let ready = false;
      for (let attempt = 0; attempt < attempts; attempt++) {
        try {
          const output = await execute("docker", ["exec", container, ...probe]);
          const separator = output.lastIndexOf("\n");
          if (Buffer.byteLength(output) > 4096 || separator < 0 ||
              !/^[1-5][0-9]{2}$/.test(output.slice(separator + 1)))
            throw new Error("Container-local health probe returned invalid or oversized output");
          const status = Number(output.slice(separator + 1));
          if (status === 200) {
            const result = JSON.parse(output.slice(0, separator));
            ready = image === "dojo" ? result.status === "UP"
              : image === "portal" ? result.status === "running" && result.mode === "read-only-preview" && result.codeRevision === entry.sourceRevision
                : result.status === "healthy" && result.environment === "training";
          }
          if (!ready)
            log(`[test] ${image} container-local health not ready (HTTP ${status}); attempt ${attempt + 1}/${attempts}`);
        } catch (error) {
          if (!/^docker failed \((?:7|28|52|56|75)\)/.test(error.message))
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
    log(`[test] ${entry.image}: ${sleeping ? "sleeping runtime observed without network access" : "container-local loopback health verified without published ports"}; image ID=${entry.imageId}`);
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
