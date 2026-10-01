import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { root } from "../shared/config.mjs";
import { nginxMode } from "../shared/nginx-proxy.mjs";
import { buildNginxProxy, verifyNginxSource } from "./lib/nginx-proxy.mjs";

const { values } = parseArgs({
  options: {
    tag: { type: "string" },
    mode: { type: "string", default: "vulnerable" },
    "check-source": { type: "boolean" },
  },
});
try {
  const mode = nginxMode(values.mode);
  if (values["check-source"]) {
    console.log(JSON.stringify(await verifyNginxSource(), null, 2));
  } else {
    const image = values.tag || `nginx-proxy:${mode.mode}`;
    if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(image))
      throw new Error("Invalid local image tag");
    const output = fileURLToPath(new URL(`output/images/nginx-proxy/${mode.mode}/`, root));
    const entry = await buildNginxProxy(image, output, mode.mode);
    console.log(`Built and scanned ${entry.image} (${entry.imageId}). Evidence: ${output}. Local only: not pushed or deployed; review actual CVE association.`);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
