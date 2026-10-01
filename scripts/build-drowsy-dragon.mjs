import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { root } from "../shared/config.mjs";
import { buildDrowsyDragon } from "./lib/drowsy-dragon.mjs";

const { values } = parseArgs({
  options: { tag: { type: "string", default: "drowsy-dragon:local" } },
});
try {
  if (!/^[a-z0-9][a-z0-9./:_-]{0,200}$/.test(values.tag))
    throw new Error("Invalid local image tag");
  const output = fileURLToPath(new URL("output/images/drowsy-dragon/", root));
  const image = await buildDrowsyDragon(values.tag, output);
  console.log(
    `Built and scanned ${image.image} (${image.imageId}). Evidence: ${output}. Local only: not pushed or deployed; review findings before release.`,
  );
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
