import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  configHash,
  requireConfirmation,
  validateRelease,
} from "../scripts/lib/lifecycle.mjs";
import { confirmation } from "../shared/config.mjs";
import { isLabHostname, names } from "../shared/config.mjs";
import { ownedReaderAssignments } from "../scripts/lib/lifecycle.mjs";
const config = JSON.parse(
  await readFile(new URL("../config/deploy.config.json", import.meta.url)),
);
test("hostnames accept Azure-generated names but reject foreign sites and suffix attacks", () => {
  const name = "dojo-123456789abc-app";
  assert.equal(
    isLabHostname("dojo-123456789abc-portal.azurewebsites.net", name),
    false,
  );
  assert.equal(Object.hasOwn(names(config), "webgoat"), false);
  assert.match(names(config).dojo, /^dojo-[a-f0-9]{12}-app$/);
  assert.equal(isLabHostname(`${name}.azurewebsites.net`, name), true);
  assert.equal(
    isLabHostname(`${name}-hash.centralus-01.azurewebsites.net`, name),
    true,
  );
  assert.equal(
    isLabHostname(`${name}.azurewebsites.net.attacker.example`, name),
    false,
  );
  assert.equal(isLabHostname("169.254.169.254", name), false);
  assert.deepEqual(
    names({ ...config, subscriptionId: "ABC", resourceGroup: "GROUP" }),
    names({ ...config, subscriptionId: "abc", resourceGroup: "group" }),
  );
});
test("teardown removes only the owned subscription role for the exact principal", () => {
  const scope = `/subscriptions/${config.subscriptionId}`;
  const assignment = {
    id: `${scope}/providers/Microsoft.Authorization/roleAssignments/owned`,
    properties: {
      description: `CodeToCloud:${config.labId}`,
      scope,
      principalId: "portal",
      roleDefinitionId: `${scope}/providers/Microsoft.Authorization/roleDefinitions/39bc4728-0917-49c7-9d2c-d95423bc2eb4`,
    },
  };
  assert.deepEqual(ownedReaderAssignments(config, "portal", [assignment]), [
    assignment,
  ]);
  assert.deepEqual(
    ownedReaderAssignments(config, "different", [assignment]),
    [],
  );
  assert.deepEqual(
    ownedReaderAssignments(config, "portal", [
      {
        ...assignment,
        properties: {
          ...assignment.properties,
          description: "someone else's grant",
        },
      },
    ]),
    [],
  );
});
test("destructive confirmation is action and subscription bound", () => {
  requireConfirmation(
    config,
    "deprovision",
    confirmation(config, "deprovision"),
  );
  assert.throws(() => requireConfirmation(config, "deprovision", "yes"));
  assert.throws(() =>
    requireConfirmation(
      { ...config, subscriptionId: "other" },
      "deprovision",
      confirmation(config, "deprovision"),
    ),
  );
});
test("release must carry immutable digests, scan hashes and exact config provenance", () => {
  const release = {
    schemaVersion: 1,
    configHash: configHash(config),
    source: {
      ...config.source,
      tree: "e".repeat(40),
      snapshotSha256: "f".repeat(64),
      files: 1,
    },
    images: {
      portal: { digest: `sha256:${"a".repeat(64)}`, scanHash: "b".repeat(64) },
      dojo: { digest: `sha256:${"c".repeat(64)}`, scanHash: "d".repeat(64) },
    },
  };
  validateRelease(config, release);
  assert.throws(
    () => validateRelease(config, { ...release, source: config.source }),
    /snapshot provenance/,
  );
  assert.throws(() =>
    validateRelease({ ...config, location: "other" }, release),
  );
  assert.throws(() => validateRelease(config, { ...release, images: {} }));
});
