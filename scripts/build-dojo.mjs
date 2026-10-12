import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { loadConfig, root } from "../shared/config.mjs";
import { prepareDojoImage } from "./lib/dojo-source.mjs";
import { buildCoreImage } from "./lib/image-build.mjs";

const { values } = parseArgs({
  options: {
    tag: { type: "string" },
    latest: { type: "boolean", default: false },
    "prepare-only": { type: "boolean" },
  },
});
try {
  const image = values.tag ?? (values.latest ? "dojo:latest" : "dojo:local");
  if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(image))
    throw new Error("Invalid local image tag");
  if (values.latest && values["prepare-only"])
    throw new Error("--latest resolves registry digests during a build; use --prepare-only without --latest for the approved template");
  const config = await loadConfig({ offline: true });
  const home = fileURLToPath(new URL("apps/dojo/", root));
  const output = fileURLToPath(new URL(`output/images/${config.source.revision}/${values.latest ? "latest/" : ""}`, root));
  if (values["prepare-only"]) {
    console.log(JSON.stringify(await prepareDojoImage(home, config.source, output), null, 2));
  } else {
    const entry = await buildCoreImage("dojo", image, output, {
      source: config.source, latest: values.latest, scan: values.latest,
    });
    console.log(`Built ${image} (${entry.imageId}). Local only: ${values.latest ? "scanned, not pushed or deployed" : "not scanned, pushed or deployed"}. Use the approved environment build action for release.`);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}