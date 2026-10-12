import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { root } from "../shared/config.mjs";
import { buildDrowsyDragon } from "./lib/drowsy-dragon.mjs";

const { values } = parseArgs({
  options: {
    tag: { type: "string" },
    latest: { type: "boolean", default: false },
  },
});
try {
  const tag = values.tag ?? (values.latest ? "drowsy-dragon:latest" : "drowsy-dragon:local");
  if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(tag))
    throw new Error("Invalid local image tag");
  const output = fileURLToPath(new URL(
    `output/images/drowsy-dragon/${values.latest ? "latest/" : ""}`, root,
  ));
  const image = await buildDrowsyDragon(tag, output, { latest: values.latest });
  console.log(
    `Built and scanned ${image.image} (${image.imageId}) from ${image.baseImage}. Evidence: ${output}. Local only: not pushed or deployed; review findings before release.`,
  );
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
