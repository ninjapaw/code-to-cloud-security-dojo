import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  validateConfig,
  assertContext,
  assertOwned,
  names,
  accessSettings,
} from "../shared/config.mjs";

const base = JSON.parse(
  await readFile(new URL("../config/deploy.config.json", import.meta.url)),
);
const config = {
  ...base,
  tenantId: "11111111-1111-4111-8111-111111111111",
  subscriptionId: "22222222-2222-4222-8222-222222222222",
  operatorObjectId: "33333333-3333-4333-8333-333333333333",
  adminCidr: "203.0.113.10/32",
};
test("offline plan accepts unselected context but online fails closed", () => {
  assert.equal(validateConfig(base, { offline: true }), base);
  assert.throws(() => validateConfig(base), /tenantId/);
  assert.equal(validateConfig(config), config);
});
test("access defaults preserve current behavior without rewriting older configurations", () => {
  const expected = {
    keyVaultPublicAccess: true,
    keyVaultRestrictToAdminIp: false,
    dojoPublicAccess: true,
    dojoRestrictToAdminIp: false,
    keyVaultPublicAccessTags: { SecurityControl: "Ignore" },
  };
  assert.deepEqual(accessSettings(base), expected);
  const legacy = structuredClone(config);
  for (const key of Object.keys(expected)) delete legacy[key];
  const before = JSON.stringify(legacy);
  assert.equal(validateConfig(legacy), legacy);
  assert.deepEqual(accessSettings(legacy), expected);
  assert.equal(JSON.stringify(legacy), before);
});
test("public and admin-IP access switches accept only booleans", () => {
  for (const key of [
    "keyVaultPublicAccess",
    "keyVaultRestrictToAdminIp",
    "dojoPublicAccess",
    "dojoRestrictToAdminIp",
  ]) {
    for (const value of [true, false]) {
      const selected = { ...config, [key]: value };
      assert.equal(validateConfig(selected), selected);
      assert.equal(accessSettings(selected)[key], value);
    }
    for (const value of [null, "true", "false", 0, 1, [], {}]) {
      assert.throws(
        () => validateConfig({ ...config, [key]: value }),
        new RegExp(`${key} must be a boolean`),
      );
    }
  }
});
test("vault policy tags are configurable, optional and cannot change lab ownership", () => {
  for (const tags of [{}, { NetworkException: "ApprovedForTraining" }]) {
    const selected = { ...config, keyVaultPublicAccessTags: tags };
    assert.equal(validateConfig(selected), selected);
    const resolved = accessSettings(selected).keyVaultPublicAccessTags;
    assert.deepEqual(resolved, tags);
    assert.notEqual(resolved, tags);
  }
  for (const tags of [
    null,
    [],
    true,
    "SecurityControl=Ignore",
    { SecurityControl: false },
    { "": "Ignore" },
    { "dojo.labId": "another-lab" },
    { "DOJO.MANAGEDBY": "another-owner" },
  ]) {
    assert.throws(
      () => validateConfig({ ...config, keyVaultPublicAccessTags: tags }),
      /keyVaultPublicAccessTags/,
    );
  }
});
test("rejects broad, malformed and special-use admin CIDRs", () => {
  for (const adminCidr of [
    "0.0.0.0/0",
    "::/0",
    "203.0.113.0/24",
    "999.2.3.4/32",
    "127.0.0.1/32",
    "169.254.169.254/32",
    "224.0.0.1/32",
    "1.2.3.4/32/32",
  ]) {
    assert.throws(
      () => validateConfig({ ...config, adminCidr }),
      undefined,
      adminCidr,
    );
  }
});
test("binds context and ownership without selecting a global default", () => {
  assertContext(config, {
    id: config.subscriptionId,
    tenantId: config.tenantId,
    state: "Enabled",
    environmentName: "AzureCloud",
  });
  assert.throws(() =>
    assertContext(config, {
      id: config.tenantId,
      tenantId: config.tenantId,
      state: "Enabled",
    }),
  );
  assert.throws(() =>
    assertOwned(config, { name: config.resourceGroup, tags: {} }),
  );
  assertOwned(config, {
    name: config.resourceGroup,
    tags: {
      "dojo.labId": config.labId,
      "dojo.managedBy": "code-to-cloud-security-dojo",
    },
  });
  assert.deepEqual(names(config), names(structuredClone(config)));
});
test("private admin networks and missing required extensions fail before Azure calls", () => {
  for (const adminCidr of [
    "10.0.0.1/32",
    "192.168.1.2/32",
    "172.16.0.1/32",
    "100.64.0.1/32",
  ])
    assert.throws(
      () => validateConfig({ ...config, adminCidr }),
      /public IPv4/,
    );
  const incomplete = structuredClone(config);
  incomplete.protection.Containers.extensions = [];
  assert.throws(
    () => validateConfig(incomplete),
    /Required Defender extension/,
  );
});
