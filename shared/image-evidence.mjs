import { createHash } from "node:crypto";

export const sha256 = (value) =>
  createHash("sha256").update(value).digest("hex");

export function imageEvidenceKey(id, digest, scanHash) {
  if (
    !/^[a-z][a-z0-9-]+$/.test(id || "") ||
    !/^sha256:[a-f0-9]{64}$/.test(digest || "") ||
    !/^[a-f0-9]{64}$/.test(scanHash || "")
  )
    throw new Error("Image evidence requires a demo ID, image digest and scan hash");
  return `images/${id}/${digest.slice(7)}/${scanHash}.json`;
}

export function parsePackageInventory(text, definition) {
  const versions = new Map();
  for (const line of text.trim().split(/\r?\n/)) {
    const [qualifiedName, version, extra] = line.split("\t");
    const name = qualifiedName.split(":")[0];
    if (
      !definition.packages.includes(name) ||
      !version?.trim() ||
      extra !== undefined ||
      versions.has(name)
    )
      throw new Error(`Invalid ${definition.title} package inventory`);
    versions.set(name, version.trim());
  }
  if (versions.size !== definition.packages.length)
    throw new Error(`${definition.title} package inventory is incomplete`);
  return definition.packages.map((name) => ({ name, version: versions.get(name) }));
}

export function summarizePackageScan(scan, imageId, packages, definition) {
  if (
    scan?.SchemaVersion !== 2 ||
    scan.ArtifactType !== "container_image" ||
    scan.Metadata?.ImageID !== imageId ||
    !Array.isArray(scan.Results) ||
    scan.Results.some(
      (result) =>
        !result ||
        (result.Packages !== undefined && !Array.isArray(result.Packages)) ||
        (result.Vulnerabilities !== undefined &&
          !Array.isArray(result.Vulnerabilities)),
    )
  )
    throw new Error(`${definition.title} scan is incomplete or belongs to another image`);
  const assessed = new Set(
    scan.Results.flatMap((result) => result.Packages || []).map(
      (pkg) => pkg.Name?.split(":")[0],
    ),
  );
  if (packages.some((pkg) => !assessed.has(pkg.name)))
    throw new Error(`${definition.title} scan does not cover every tracked package`);
  const findings = scan.Results.flatMap(
    (result) => result.Vulnerabilities || [],
  );
  if (findings.some(
    (finding) => !finding?.VulnerabilityID || !finding.PkgName ||
      !finding.InstalledVersion || !finding.Severity,
  ))
    throw new Error(`${definition.title} scan contains an incomplete finding`);
  return {
    imageFindingCount: findings.length,
    vulnerabilities: findings
      .filter((finding) => definition.packages.includes(finding.PkgName.split(":")[0]))
      .map((finding) => ({
        id: finding.VulnerabilityID,
        package: finding.PkgName,
        severity: finding.Severity,
        installedVersion: finding.InstalledVersion,
        fixedVersion: finding.FixedVersion || "",
        status: finding.Status || "",
        advisory: finding.PrimaryURL || "",
      })),
  };
}

export function summarizeImageReceipt(receipt, definition, digest, scanHash, extraArtifacts = []) {
  imageEvidenceKey(definition.id, digest, scanHash);
  if (
    receipt?.schemaVersion !== 1 ||
    receipt.demoId !== definition.id ||
    receipt.imageDigest !== digest ||
    receipt.hashes?.scanJson !== scanHash ||
    !/^sha256:[a-f0-9]{64}$/.test(receipt.imageId || "") ||
    !/^[a-f0-9]{40}$/.test(receipt.sourceRevision || "") ||
    !Number.isFinite(Date.parse(receipt.scannedAt)) ||
    !/^[a-f0-9]{64}$/.test(receipt.hashes?.sarif || "")
  )
    throw new Error(`${definition.title} receipt does not match the deployed release`);
  for (const key of ["dockerfile", "inventory", "scanJson", ...extraArtifacts]) {
    if (
      typeof receipt.artifacts?.[key] !== "string" ||
      sha256(receipt.artifacts[key]) !== receipt.hashes[key]
    )
      throw new Error(`${definition.title} ${key} evidence hash mismatch`);
  }
  const packages = parsePackageInventory(receipt.artifacts.inventory, definition);
  return {
    scanner: "Trivy",
    scannedAt: receipt.scannedAt,
    imageDigest: digest,
    sourceRevision: receipt.sourceRevision,
    hashes: receipt.hashes,
    packages,
    ...summarizePackageScan(JSON.parse(receipt.artifacts.scanJson), receipt.imageId, packages, definition),
  };
}
