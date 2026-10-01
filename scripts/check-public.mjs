import { readFile, lstat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve, basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { run } from "./lib/lifecycle.mjs";
import { root } from "../shared/config.mjs";
import { verifySource } from "./lib/dojo-source.mjs";
import { verifyNginxSource } from "./lib/nginx-proxy.mjs";

const patterns = [
  [
    "private-key marker",
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  ],
  [
    "GitHub token",
    /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/,
  ],
  ["AWS access key", /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ["storage account key", /AccountKey=[A-Za-z0-9+/=]{40,}/i],
  ["signed access URL", /[?&]sig=[A-Za-z0-9%+/=]{20,}/i],
  ["credential-bearing URL", /https?:\/\/[^\s/@:]+:[^\s/@]+@/i],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{20,}/],
  ["workstation user path", /\b[A-Z]:[\\/]Users[\\/][^\s/\\]+/i],
];

export function publicationFindings(path, content) {
  const findings = [];
  const name = basename(path);
  if (
    /^(?:output|node_modules|test-results|playwright-report|credentials|secrets|\.azure|\.ssh|\.terraform)\//.test(
      path,
    ) ||
    /^\.env(?:\.|$)/.test(name) ||
    /\.(?:pem|key|pfx|p12|jks|keystore)$/i.test(name) ||
    name === ".npmrc" ||
    name.endsWith(".local.json") ||
    path.includes(".source-stage-") ||
    name === ".source-sync.lock"
  )
    findings.push("private or generated artifact");
  for (const [label, expression] of patterns)
    if (expression.test(content)) findings.push(label);
  if (path === "config/deploy.config.json") {
    try {
      const config = JSON.parse(content);
      if (
        ["tenantId", "subscriptionId", "operatorObjectId", "adminCidr"].some(
          (key) => config[key],
        )
      )
        findings.push("environment-specific public defaults");
    } catch {
      findings.push("invalid public configuration");
    }
  }
  return findings;
}

export function reviewedUpstreamMarker(path, content) {
  return (
    path ===
      "apps/dojo/upstream/src/main/java/org/owasp/webgoat/lessons/cryptography/CryptoUtil.java" &&
    createHash("sha256").update(content).digest("hex") ===
      "ce023d1873845d708d8578f2181d1e698932376ebe39ba44fa559b7766b5839f"
  );
}

async function main() {
  const directory = fileURLToPath(root);
  const defaults = JSON.parse(
    await readFile(new URL("config/deploy.config.json", root), "utf8"),
  );
  const source = await verifySource(
    fileURLToPath(new URL("apps/dojo/", root)),
    defaults.source,
  );
  const nginxSource = await verifyNginxSource();
  const files = [
    ...new Set(
      run("git", [
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
      ])
        .split("\0")
        .filter(Boolean),
    ),
  ];
  let ownedCount = 0;
  let upstreamCount = 0;
  let nginxCount = 0;
  let failures = 0;
  for (const path of files) {
    const absolute = resolve(directory, path);
    let info;
    try {
      info = await lstat(absolute);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (!info.isFile()) {
      console.error(`${path}: unsupported publication entry`);
      failures++;
      continue;
    }
    const content = (await readFile(absolute)).toString("utf8");
    const findings = publicationFindings(path, content);
    if (path.startsWith("apps/dojo/upstream/")) {
      upstreamCount++;
    } else if (path.startsWith("apps/nginx-proxy/upstream/")) {
      nginxCount++;
    } else {
      ownedCount++;
    }
    if (findings.length) {
      if (
        findings.length === 1 &&
        findings[0] === "private-key marker" &&
        reviewedUpstreamMarker(path, content)
      )
        console.log(
          `${path}: reviewed upstream PEM-formatting marker; exact file hash matched`,
        );
      else {
        failures++;
        console.error(`${path}: ${findings.join(", ")}`);
      }
    }
  }
  if (upstreamCount !== source.files || nginxCount !== nginxSource.files) {
    failures++;
    console.error(
      "Imported source files are missing from the publication set; check ignore rules before publishing.",
    );
  }
  console.log(`Verified ${nginxCount} imported NGINX source files against their reviewed pin.`);
  console.log(
    `Checked ${ownedCount} owned files and ${upstreamCount} verified upstream files. ${failures} publication issue(s). Matched values are never printed.`,
  );
  console.log(
    "This is a working-tree guard, not exhaustive secret/history detection. Upstream training fixtures must never be used as real credentials.",
  );
  if (failures) process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
