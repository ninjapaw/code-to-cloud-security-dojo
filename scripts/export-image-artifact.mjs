import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { run } from "./lib/lifecycle.mjs";

async function fileHash(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

export async function exportImageArtifact(
  image, dockerfile, directory, { expectedImageId, execute = run } = {},
) {
  if (!/^[a-z0-9][A-Za-z0-9./:_@-]{0,255}$/.test(image || "") ||
      !dockerfile || !directory)
    throw new Error("An image reference, Dockerfile and new output directory are required");
  const recipe = await readFile(dockerfile);
  const inspect = async () => JSON.parse(await execute("docker", [
    "image", "inspect", image, "--format", "{{json .}}",
  ]));
  const info = await inspect();
  if (!/^sha256:[a-f0-9]{64}$/.test(info.Id || "") ||
      info.Os !== "linux" || info.Architecture !== "amd64")
    throw new Error("Image artifacts require a verified linux/amd64 image");
  if (expectedImageId !== undefined && info.Id !== expectedImageId)
    throw new Error("Image ID does not match the scanned release");
  const exportRevision = await execute("git", ["rev-parse", "HEAD"]);
  if (!/^[a-f0-9]{40}$/.test(exportRevision))
    throw new Error("Image artifacts require a Git export revision");
  const output = resolve(directory);
  await mkdir(dirname(output), { recursive: true });
  await mkdir(output);
  try {
    await writeFile(join(output, "Dockerfile"), recipe, { flag: "wx" });
    const archive = join(output, "image.tar");
    await execute("docker", [
      "image", "save", "--output", archive, image,
    ], { inherit: true });
    const saved = await stat(archive);
    if (!saved.isFile() || saved.size === 0)
      throw new Error("Docker did not produce a nonempty image archive");
    if ((await inspect()).Id !== info.Id)
      throw new Error("Image changed while exporting; rebuild before publishing");
    const metadata = {
      schemaVersion: 1,
      image,
      imageId: info.Id,
      platform: `${info.Os}/${info.Architecture}`,
      exportRevision,
      exportedAt: new Date().toISOString(),
      archive: "image.tar",
      archiveBytes: saved.size,
      archiveSha256: await fileHash(archive),
      dockerfileSha256: createHash("sha256").update(recipe).digest("hex"),
    };
    await writeFile(
      join(output, "image.json"), `${JSON.stringify(metadata, null, 2)}\n`,
      { flag: "wx" },
    );
    await writeFile(join(output, "SHA256SUMS"), [
      `${metadata.archiveSha256}  image.tar`,
      `${metadata.dockerfileSha256}  Dockerfile`,
      `${await fileHash(join(output, "image.json"))}  image.json`,
      "",
    ].join("\n"), { flag: "wx" });
    console.log(`Exported ${image} (${info.Id}) with Dockerfile and checksums to ${output}`);
    return metadata;
  } catch (error) {
    await rm(output, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { values } = parseArgs({
      options: {
        image: { type: "string" },
        dockerfile: { type: "string" },
        output: { type: "string" },
      },
    });
    await exportImageArtifact(values.image, values.dockerfile, values.output);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
