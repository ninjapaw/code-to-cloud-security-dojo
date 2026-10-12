import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { root } from "../shared/config.mjs";
import { buildCoreImage } from "./lib/image-build.mjs";

const { values } = parseArgs({
  options: {
    component: { type: "string" },
    tag: { type: "string" },
    latest: { type: "boolean", default: false },
  },
});
try {
  if (!["portal", "secret-bootstrap"].includes(values.component))
    throw new Error("--component must be portal or secret-bootstrap");
  const repository = values.component === "portal" ? "control-portal" : "secret-bootstrap";
  const image = values.tag ?? `${repository}:${values.latest ? "latest" : "local"}`;
  if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(image))
    throw new Error("Invalid local image tag");
  const output = fileURLToPath(new URL(
    `output/images/${repository}/${values.latest ? "latest" : "pinned"}/`, root,
  ));
  const entry = await buildCoreImage(
    values.component === "portal" ? "portal" : "secretBootstrap",
    image, output, { latest: values.latest, repository },
  );
  console.log(`Built and scanned ${entry.image} (${entry.imageId}). Evidence: ${output}. Local only: not pushed, deployed or granted credentials.`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
