import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { loadConfig, root } from "../shared/config.mjs";
import { run } from "./lib/lifecycle.mjs";
import { prepareDojoImage, verifySource } from "./lib/dojo-source.mjs";

const { values } = parseArgs({ options: { tag: { type: "string", default: "dojo:local" }, "prepare-only": { type: "boolean" } } });
try {
  if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(values.tag)) throw new Error("Invalid local image tag");
  const config = await loadConfig({ offline: true });
  const home = fileURLToPath(new URL("apps/dojo/", root));
  const output = fileURLToPath(new URL(`output/images/${config.source.revision}/`, root));
  const prepared = await prepareDojoImage(home, config.source, output);
  if (values["prepare-only"]) console.log(JSON.stringify(prepared, null, 2));
  else {
    run("docker", ["build", "--platform", "linux/amd64", "--label", `org.opencontainers.image.source=${config.source.repository.replace(/\.git$/, "")}`, "--label", `org.opencontainers.image.revision=${prepared.manifest.revision}`, "--label", `dojo.source.sha256=${prepared.manifest.sha256}`, "-f", prepared.dockerfile, "-t", values.tag, prepared.sourcePath], { inherit: true });
    await verifySource(home, config.source);
    const imageId = run("docker", ["image", "inspect", values.tag, "--format", "{{.Id}}"]);
    await writeFile(join(output, "local-image.json"), JSON.stringify({ schemaVersion: 1, stage: "local-build-unscanned", image: values.tag, imageId, source: prepared.manifest }, null, 2));
    console.log(`Built ${values.tag} (${imageId}). Local only: not scanned, pushed or deployed. Use the approved environment build action for release.`);
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }