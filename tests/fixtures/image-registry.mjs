import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { sha256 } from "../../shared/image-evidence.mjs";
import { names } from "../../shared/config.mjs";

export function registryFixture(config, baseExecute, {
  imageId = `sha256:${"a".repeat(64)}`,
  digest = `sha256:${"c".repeat(64)}`,
  azureCalls = [],
} = {}) {
  const registry = names(config).registry;
  const local = new Map();
  const tags = new Map();
  const manifests = new Map();
  let clock = 0;
  const reference = (repository, tag) => `${registry}.azurecr.io/${repository}:${tag}`;
  const argument = (args, key) => args[args.indexOf(key) + 1];
  const execute = async (command, args, options) => {
    const result = await baseExecute(command, args, options);
    if (command !== "docker") return result;
    if (args[0] === "build") {
      const target = argument(args, "-t");
      const evidence = argument(args, "-f").endsWith("Evidence.Dockerfile");
      const id = evidence
        ? `sha256:${sha256(await readFile(join(args.at(-1), "manifest.json")))}`
        : imageId;
      local.set(target, { id, evidence });
    } else if (args[0] === "image" && args[1] === "inspect" && local.get(args[2])?.evidence) {
      return local.get(args[2]).id;
    } else if (args[0] === "tag") {
      if (!local.has(args[1])) throw new Error("Fixture image was not built");
      local.set(args[2], local.get(args[1]));
    } else if (args[0] === "push") {
      const value = local.get(args[1]);
      if (!value) throw new Error("Fixture push requires a local image");
      if (tags.get(args[1])?.changeableAttributes.writeEnabled === false)
        throw new Error("Fixture registry rejected a locked tag write");
      const repository = args[1].split("/").slice(1).join("/").split(":")[0];
      const manifestDigest = value.evidence ? `sha256:${sha256(`manifest:${value.id}`)}` : digest;
      tags.set(args[1], {
        name: args[1].split(":").at(-1), digest: manifestDigest,
        lastUpdateTime: new Date(++clock * 1000).toISOString(),
        changeableAttributes: { writeEnabled: true, deleteEnabled: true },
      });
      const key = `${repository}@${manifestDigest}`;
      if (!manifests.has(key))
        manifests.set(key, { config: { digest: value.id }, changeableAttributes: { deleteEnabled: true } });
    } else if (args[0] === "buildx" && args.includes("--raw")) {
      const key = args[3].split("/").slice(1).join("/");
      if (!manifests.has(key)) throw new Error("Fixture archive manifest was not pushed");
      return JSON.stringify(manifests.get(key));
    }
    return result;
  };
  const executeAz = async (args, options) => {
    azureCalls.push([args, options]);
    if (args[0] !== "acr") throw new Error("Fixture forbids non-registry Azure writes");
    if (args[1] === "login") return "";
    if (args[1] === "repository" && args[2] === "list")
      return [...new Set([...tags.keys()].map((key) => key.split("/").slice(1).join("/").split(":")[0]))];
    if (args[1] === "repository" && args[2] === "show-tags") {
      const repository = argument(args, "--repository");
      let rows = [...tags.entries()].filter(([key]) => key.startsWith(`${registry}.azurecr.io/${repository}:`)).map(([, value]) => value);
      if (args.includes("--query")) {
        const match = argument(args, "--query").match(/name=='([^']+)'/);
        if (!match) throw new Error("Fixture expected an exact tag query");
        rows = rows.filter((row) => row.name === match[1]);
      }
      if (args.includes("--top")) rows = rows.slice(0, Number(argument(args, "--top")));
      return rows;
    }
    if (args[1] === "repository" && ["show", "update"].includes(args[2])) {
      const image = argument(args, "--image");
      const record = image.includes("@")
        ? manifests.get(image)
        : tags.get(`${registry}.azurecr.io/${image}`);
      if (!record) throw new Error("Fixture archive metadata is missing");
      if (args[2] === "update") {
        for (const [field, flag] of [["writeEnabled", "--write-enabled"], ["deleteEnabled", "--delete-enabled"]])
          if (args.includes(flag)) record.changeableAttributes[field] = argument(args, flag) === "true";
        return "";
      }
      return record;
    }
    if (args[1] === "manifest" && args[2] === "show-metadata") {
      const image = argument(args, "--name");
      if (argument(args, "--query") === "changeableAttributes.deleteEnabled")
        return manifests.get(image)?.changeableAttributes.deleteEnabled;
      const record = tags.get(`${registry}.azurecr.io/${image}`);
      if (!record) throw new Error("Fixture image metadata is missing");
      return record.digest;
    }
    throw new Error(`Fixture does not implement ${args.join(" ")}`);
  };
  return { execute, executeAz, tags, manifests, local, reference, azureCalls };
}
