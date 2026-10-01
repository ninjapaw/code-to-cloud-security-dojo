import { summarizeImageReceipt } from "./image-evidence.mjs";

export const nginxProxy = Object.freeze({
  id: "nginx-proxy",
  title: "NGINX Proxy",
  packages: Object.freeze(["nginx"]),
  platform: "linux/amd64",
  targetCve: "CVE-2026-42533",
  advisory: "https://my.f5.com/manage/s/article/K000162097",
  dockerfileHash: "5ca1588bccf0752731d69227a176b977df0b5d3b5c933618cd301eadd388a4d5",
  source: Object.freeze({
    repository: "https://github.com/ninjapaw/ninjapaws-cloud-security-dojo.git",
    revision: "7a6d8fbd232000ab2de43f59a05ba5cdbc1e16c9",
    tree: "a68fba840083aeed83a94ce2d72d7db3011884d6",
    files: 8,
    sha256: "ef687664020bc7c8db0f0c7214d7166b73b7511a59527a2993ba6981ce8c5012",
  }),
});

export function nginxMode(mode = "vulnerable") {
  if (!["vulnerable", "remediated"].includes(mode))
    throw new Error("nginxProxyMode must be vulnerable or remediated");
  return {
    mode,
    version: mode === "vulnerable" ? "1.30.3" : "1.30.4",
    mapRegexEnabled: mode === "vulnerable",
    configState: mode === "vulnerable" ? "affected" : "remediated",
  };
}

export function validateNginxSourceLock(manifest) {
  if (
    manifest?.schemaVersion !== 1 ||
    Object.entries(nginxProxy.source).some(([key, value]) => manifest[key] !== value)
  )
    throw new Error("NGINX Proxy snapshot does not match the reviewed upstream pin");
  return manifest;
}

export function summarizeNginxReceipt(receipt, digest, scanHash) {
  const summary = summarizeImageReceipt(receipt, nginxProxy, digest, scanHash, ["sourceLock"]);
  const mode = nginxMode(receipt.mode);
  if (receipt.mode === undefined)
    throw new Error("NGINX Proxy receipt is missing its release mode");
  const source = validateNginxSourceLock(JSON.parse(receipt.artifacts.sourceLock));
  if (receipt.hashes.dockerfile !== nginxProxy.dockerfileHash)
    throw new Error("NGINX Proxy recipe does not match the reviewed source");
  validateNginxInventory(summary.packages, mode.mode);
  return {
    ...summary,
    mode: mode.mode,
    scanVersion: mode.version,
    upstream: source,
    targetFindingObserved: summary.vulnerabilities.some((item) => item.id === nginxProxy.targetCve),
  };
}

export function validateNginxInventory(packages, selectedMode) {
  const expected = nginxMode(selectedMode);
  const installed = packages.find((pkg) => pkg.name === "nginx")?.version;
  if (installed !== expected.version && !installed?.startsWith(`${expected.version}-`))
    throw new Error("NGINX Proxy inventory does not match its approved release mode");
}

export function validateNginxRuntime(payload, selectedMode) {
  const actual = payload?.runtime_verification;
  if (
    !actual ||
    typeof actual.nginx_binary_version !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(actual.nginx_binary_version || "") ||
    typeof actual.nginx_package_version !== "string" ||
    !actual.nginx_package_version ||
    !["affected", "remediated"].includes(actual.scenario_config_state) ||
    typeof actual.map_regex_enabled !== "boolean" ||
    typeof actual.vulnerability_detected !== "boolean"
  )
    throw new Error("NGINX Proxy runtime evidence is incomplete; configured status is not proof");
  const expected = nginxMode(selectedMode);
  return {
    binaryVersion: actual.nginx_binary_version,
    packageVersion: actual.nginx_package_version,
    mapRegexEnabled: actual.map_regex_enabled,
    configurationState: actual.scenario_config_state,
    targetConditionsReported: actual.nginx_binary_version === "1.30.3" && actual.map_regex_enabled,
    matchesExpectedMode:
      actual.nginx_binary_version === expected.version &&
      (actual.nginx_package_version === expected.version ||
        actual.nginx_package_version.startsWith(`${expected.version}-`)) &&
      actual.scenario_config_state === expected.configState &&
      actual.map_regex_enabled === expected.mapRegexEnabled &&
      actual.vulnerability_detected === expected.mapRegexEnabled,
  };
}
