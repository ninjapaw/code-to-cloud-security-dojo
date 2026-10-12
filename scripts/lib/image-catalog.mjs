import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { root, names } from "../../shared/config.mjs";
import { drowsyDragonRecipe } from "../../shared/drowsy-dragon.mjs";
import { imageRecipe, verifySource } from "./dojo-source.mjs";
import { nginxLatestRecipe, verifyNginxSource } from "./nginx-proxy.mjs";
import { imageBaseDefaults, resolveLatestBaseImage } from "./image-build.mjs";
import { az } from "./lifecycle.mjs";

export const experimentImages = Object.freeze({
  dojo: "dojo",
  portal: "portal",
  "secret-bootstrap": "secretBootstrap",
  "drowsy-dragon": "drowsyDragon",
  "nginx-proxy": "nginxProxy",
});

export function experimentBaseSelection(image, baseSha = "latest", buildSha = "latest") {
  if (!Object.hasOwn(experimentImages, image))
    throw new Error("Select one supported image for a manual test build");
  for (const selection of [baseSha, buildSha])
    if (selection !== "latest" && !/^sha256:[a-f0-9]{64}$/.test(selection))
      throw new Error("Hash inputs must be latest or complete sha256 digests, not tags or URLs");
  if (["portal", "secret-bootstrap"].includes(image))
    return { RUNTIME_IMAGE: baseSha, BUILD_IMAGE: buildSha };
  if (buildSha !== "latest")
    throw new Error("The separate build-sha input applies only to Node multi-stage images");
  return { BASE_IMAGE: baseSha };
}

async function approvedRecipe(image, config) {
  if (image === "dojo") {
    const home = fileURLToPath(new URL("apps/dojo/", root));
    await verifySource(home, config.source);
    return imageRecipe(await readFile(join(home, "upstream", "Dockerfile"), "utf8"));
  }
  if (image === "nginx-proxy") {
    await verifyNginxSource();
    return nginxLatestRecipe(await readFile(new URL("apps/nginx-proxy/upstream/Dockerfile", root), "utf8"));
  }
  const recipe = await readFile(new URL({
    portal: "apps/control-portal/Dockerfile",
    "secret-bootstrap": "scripts/Dockerfile.secret-bootstrap",
    "drowsy-dragon": "apps/drowsy-dragon/Dockerfile",
  }[image], root), "utf8");
  if (image === "drowsy-dragon" && recipe.replace(/\r\n/g, "\n") !== drowsyDragonRecipe)
    throw new Error("Drowsy Dragon recipe and approved pin must agree before catalog discovery");
  return recipe;
}

export async function discoverImageHashes(config, selected = "all", {
  execute,
  executeAz = (args, options) => az(config, args, options),
  log = console.log,
} = {}) {
  if (selected !== "all" && !Object.hasOwn(experimentImages, selected))
    throw new Error("Catalog image must be all or a supported image");
  const resourceNames = names(config);
  const repositories = await executeAz(["acr", "repository", "list", "--name", resourceNames.registry], { json: true });
  if (!Array.isArray(repositories) || repositories.some((repository) => typeof repository !== "string"))
    throw new Error("ACR did not return its repository inventory for hash discovery");
  const catalog = { schemaVersion: 1, generatedAt: new Date().toISOString(), images: [] };
  const selectedImages = selected === "all"
    ? Object.keys(experimentImages).filter((image) =>
      (image !== "drowsy-dragon" || config.drowsyDragonEnabled) &&
      (image !== "nginx-proxy" || config.nginxProxyEnabled))
    : [selected];
  for (const image of selectedImages) {
    const component = experimentImages[image];
    const repository = image === "secret-bootstrap" ? "secret-bootstrap" : resourceNames[component];
    const defaults = imageBaseDefaults(await approvedRecipe(image, config));
    const tags = repositories.includes(repository)
      ? await executeAz([
        "acr", "repository", "show-tags", "--name", resourceNames.registry,
        "--repository", repository, "--detail", "--orderby", "time_desc", "--top", "100",
      ], { json: true })
      : [];
    if (!Array.isArray(tags) || tags.some((tag) => typeof tag?.name !== "string" || !/^sha256:[a-f0-9]{64}$/.test(tag.digest || "")))
      throw new Error("ACR returned invalid hash catalog tag metadata");
    const bases = [];
    for (const [argument, approved] of Object.entries(defaults)) {
      const current = await resolveLatestBaseImage(approved, { execute, log });
      const currentDigest = current.split("@")[1];
      const choices = new Map([[currentDigest, { digest: currentDigest, statuses: ["current"], archives: [] }]]);
      if (approved.includes("@")) {
        const pin = approved.split("@")[1];
        if (!/^sha256:[a-f0-9]{64}$/.test(pin))
          throw new Error("Approved base pin is not a complete SHA256 digest");
        if (choices.has(pin)) choices.get(pin).statuses.push("approved");
        else choices.set(pin, { digest: pin, statuses: ["approved"], archives: [] });
      }
      const kind = argument.toLowerCase().replace(/_image$/, "");
      const prefix = kind === "base" ? "base" : `base-${kind}`;
      for (const tag of tags) {
        const match = tag.name.match(new RegExp(`^${prefix}-sha256-([a-f0-9]{64})-([a-f0-9]{16})$`));
        if (!match) continue;
        if (tag.digest.slice(7, 23) !== match[2])
          throw new Error("Archived source hash tag does not match its image manifest");
        const digest = `sha256:${match[1]}`;
        if (!choices.has(digest)) choices.set(digest, { digest, statuses: [], archives: [] });
        const choice = choices.get(digest);
        if (!choice.statuses.includes("archived")) choice.statuses.push("archived");
        choice.archives.push({ tag: tag.name, imageDigest: tag.digest });
      }
      bases.push({ argument, approved, current, choices: [...choices.values()] });
      log(`[catalog] ${image} ${argument}: approved=${approved}; current=${currentDigest}; detected source choices=${choices.size}`);
    }
    catalog.images.push({
      image, component, repository, bases, recentTagLimit: 100,
      archives: tags.filter((tag) => /^sha256-[a-f0-9]{64}$/.test(tag.name)),
      scans: tags.filter((tag) => /^scan-[a-f0-9]{64}-[a-f0-9]{32}$/.test(tag.name)),
    });
  }
  return catalog;
}

function buildCommand(config, image, argument, digest) {
  const field = argument === "BUILD_IMAGE" ? "build-sha" : "base-sha";
  return `gh workflow run image-experiments.yml --repo ninjapaw/code-to-cloud-security-dojo --ref dev -f operation=build-test -f image=${image} -f ${field}=${digest} -f confirm-resource-group=${config.resourceGroup}`;
}

export function hashCatalogMarkdown(catalog, config) {
  const workflow = "https://github.com/ninjapaw/code-to-cloud-security-dojo/actions/workflows/image-experiments.yml";
  const rows = catalog.images.flatMap((image) => image.bases.flatMap((base) => base.choices.map((choice) =>
    `| ${image.image} | ${base.argument} | \`${choice.digest}\` | ${choice.statuses.join(", ")} |`)));
  return [
    "# Detected container source hashes", "",
    `Detected at ${catalog.generatedAt}. [Open manual workflow](${workflow}).`,
    "GitHub dropdown choices are static. Select build-test and the image, then paste a detected SHA into base-sha (runtime/base) or build-sha (Node builder), or use latest to resolve the current registry hash at build time.",
    "Download hash-catalog.html for per-hash copy buttons and exact CLI dispatch commands. Discovery does not build, publish, deploy or run images.",
    "", "| Image | Base argument | Source manifest SHA | State |", "| --- | --- | --- | --- |",
    ...rows, "",
    "Recent archive discovery is limited to the 100 most recently updated tags per image repository. Older archives remain in ACR and exact SHA input is not limited to this catalog.",
    "",
    ...catalog.images.flatMap((image) => image.bases.map((base) => [
      `### ${image.image} ${base.argument}`,
      `Approved default: \`${base.approved}\``,
      `Current registry reference: \`${base.current}\``,
      "Example exact-hash dispatch:",
      "```text",
      buildCommand(config, image.image, base.argument, base.current.split("@")[1]),
      "```", "",
    ].join("\n"))),
  ].join("\n");
}

export function hashCatalogHtml(catalog, config) {
  const escape = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
  const rows = catalog.images.flatMap((image) => image.bases.flatMap((base) => base.choices.map((choice) => {
    const command = buildCommand(config, image.image, base.argument, choice.digest);
    return `<tr><td>${escape(image.image)}</td><td>${escape(base.argument)}</td><td><code>${escape(choice.digest)}</code></td><td>${escape(choice.statuses.join(", "))}</td><td><button data-copy="${escape(choice.digest)}">Copy SHA</button> <button data-copy="${escape(command)}">Copy build command</button></td></tr>`;
  }))).join("\n");
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Container hash catalog</title>
<style>body{font:16px/1.5 system-ui;margin:2rem;color:#20272c}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd5d5;padding:.6rem;text-align:left}code{overflow-wrap:anywhere}button{margin:.2rem;padding:.4rem}#status{min-height:1.5rem}</style>
<h1>Detected container source hashes</h1><p>Detected ${escape(catalog.generatedAt)}. <a href="https://github.com/ninjapaw/code-to-cloud-security-dojo/actions/workflows/image-experiments.yml">Open manual workflow</a>.</p>
<p>Click a copy button, then paste the SHA into the matching native workflow field or run the copied command with your authenticated GitHub CLI. GitHub does not dynamically populate its Run workflow dropdown. Use latest instead of a SHA for the current registry version. No credentials are stored in this report.</p>
<p id="status" role="status" aria-live="polite"></p><table><thead><tr><th>Image</th><th>Input argument</th><th>Source SHA</th><th>State</th><th>Selection</th></tr></thead><tbody>${rows}</tbody></table>
<script>for(const button of document.querySelectorAll("button[data-copy]"))button.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(button.dataset.copy);document.getElementById("status").textContent="Copied. Paste into the workflow field or your GitHub CLI."}catch{document.getElementById("status").textContent="Clipboard permission denied. Select and copy the displayed SHA manually."}});</script></html>`;
}

export async function writeHashCatalog(catalog, config, output) {
  await mkdir(output, { recursive: true });
  await writeFile(join(output, "hash-catalog.json"), JSON.stringify(catalog, null, 2));
  await writeFile(join(output, "hash-catalog.md"), hashCatalogMarkdown(catalog, config));
  await writeFile(join(output, "hash-catalog.html"), hashCatalogHtml(catalog, config));
}
