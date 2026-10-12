import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { loadConfig, names, assertContext, assertOwned, root } from "../shared/config.mjs";
import { AzureClient } from "../shared/azure.mjs";
import { az, run, requireConfirmation } from "./lib/lifecycle.mjs";
import { buildCoreImage } from "./lib/image-build.mjs";
import { buildDrowsyDragon } from "./lib/drowsy-dragon.mjs";
import { buildNginxProxy } from "./lib/nginx-proxy.mjs";
import { publishImageArchive, imageArchiveSummary } from "./lib/image-archive.mjs";
import { discoverImageHashes, experimentImages, experimentBaseSelection, hashCatalogMarkdown, writeHashCatalog } from "./lib/image-catalog.mjs";
import { smokeTestImage } from "./lib/image-smoke.mjs";
import { exportImageArtifact } from "./export-image-artifact.mjs";

try {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      image: { type: "string", default: "all" },
      "base-sha": { type: "string", default: "latest" },
      "build-sha": { type: "string", default: "latest" },
      "smoke-test": { type: "boolean" },
      confirm: { type: "string" },
      audit: { type: "boolean" },
    },
  });
  const operation = positionals[0];
  if (!["detect", "build-test"].includes(operation) || positionals.length !== 1)
    throw new Error("Choose detect or build-test for container hash experiments");
  if (operation === "detect" && (values["base-sha"] !== "latest" || values["build-sha"] !== "latest" || values["smoke-test"]))
    throw new Error("Hash selections and smoke tests apply only to build-test");
  if (values.image !== "all" && !Object.hasOwn(experimentImages, values.image))
    throw new Error("Select all or one supported image");
  const baseOverrides = operation === "build-test"
    ? experimentBaseSelection(values.image, values["base-sha"], values["build-sha"])
    : {};
  const config = await loadConfig({ offline: values.audit });
  if (values.audit) {
    console.log(JSON.stringify({ operation, image: values.image, baseOverrides, audit: true, note: "No registry requests, builds, pushes or runtime changes" }, null, 2));
  } else {
    if (operation === "build-test") {
      requireConfirmation(config, "image-test", values.confirm);
      if (run("git", ["status", "--porcelain"]))
        throw new Error("Commit reviewed changes before building or publishing a manual image test");
    }
    assertContext(config, az(config, ["account", "show"], { json: true }));
    const client = new AzureClient(config);
    assertOwned(config, await client.request(`${client.scope}/resourceGroups/${config.resourceGroup}?api-version=2021-04-01`));
    const output = fileURLToPath(new URL("output/image-experiments/", root));
    if (operation === "build-test") {
      const resourceNames = names(config);
      const component = experimentImages[values.image];
      const repository = values.image === "secret-bootstrap" ? "secret-bootstrap" : resourceNames[component];
      const image = `${resourceNames.registry}.azurecr.io/${repository}:test-${run("git", ["rev-parse", "--short=12", "HEAD"])}-${Date.now()}`;
      const buildOutput = join(output, "build");
      const options = { baseOverrides, repository, latest: true, source: config.source };
      let entry;
      if (["dojo", "portal", "secretBootstrap"].includes(component))
        entry = await buildCoreImage(component, image, buildOutput, options);
      else if (component === "drowsyDragon")
        entry = await buildDrowsyDragon(image, buildOutput, options);
      else
        entry = await buildNginxProxy(image, buildOutput, config.nginxProxyMode, options);
      if (values["smoke-test"]) {
        const smoke = await smokeTestImage(values.image, entry);
        await writeFile(join(buildOutput, "smoke-test.json"), JSON.stringify(smoke, null, 2));
      }
      const published = await publishImageArchive(config, entry, buildOutput);
      if (process.env.GITHUB_STEP_SUMMARY)
        await appendFile(process.env.GITHUB_STEP_SUMMARY, imageArchiveSummary(published));
      await mkdir(join(output, "container"), { recursive: true });
      await exportImageArtifact(entry.image, entry.dockerfilePath, join(output, "container", repository), {
        expectedImageId: entry.imageId,
      });
      console.log(`[test] Archived ${published.image}@${published.digest}. Scan archive=${published.scanArchive.image}. Latest tags and infrastructure pins were not changed.`);
    } else {
      const catalog = await discoverImageHashes(config, values.image);
      await writeHashCatalog(catalog, config, output);
      if (process.env.GITHUB_STEP_SUMMARY)
        await appendFile(process.env.GITHUB_STEP_SUMMARY, hashCatalogMarkdown(catalog, config));
      console.log(`[catalog] Detected ${catalog.images.length} image families; catalog=${output}. Discovery only: no build, push, runtime or infrastructure changes.`);
    }
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
