import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { githubEnvironmentSubject } from "../scripts/github-oidc-subject.mjs";

test("GitHub environment trust uses immutable owner and repository IDs", () => {
  const repository = {
    id: 1395015776,
    name: "code-to-cloud-security-dojo",
    owner: { id: 301718044, login: "ninjapaw" },
  };
  assert.equal(
    githubEnvironmentSubject(repository, "code-to-cloud-training"),
    "repo:ninjapaw@301718044/code-to-cloud-security-dojo@1395015776:environment:code-to-cloud-training",
  );
  assert.throws(
    () => githubEnvironmentSubject({ name: repository.name }, "dev"),
    /repository IDs/,
  );
  assert.throws(
    () => githubEnvironmentSubject(repository, "Invalid Environment"),
    /valid environment/,
  );
});

test("bootstrap is dry-run by default and delegates only required scopes", async () => {
  const source = await readFile(
    new URL("../scripts/setup-azure-github-oidc.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /const dryRun = !values\.apply/);
  assert.match(source, /defenderReaderRole/);
  assert.match(source, /defenderOperatorRole/);
  assert.match(source, /AZURE_PROTECTION_CLIENT_ID/);
  assert.match(
    source,
    /RoleDefinitionId\] ForAnyOfAnyValues:GuidEquals \{\$\{groupAssignableRoles\}\}/,
  );
  assert.match(source, /PrincipalType\].*\{'User', 'ServicePrincipal'\}/);
  assert.match(source, /remove legacy Security Admin/);
  assert.match(source, /remove legacy subscription RBAC Administrator/);
  assert.match(
    source,
    /Refusing to retire OIDC while the lab resource group still exists/,
  );
  assert.match(source, /retire:\$\{subscriptionId\}:\$\{resourceGroup\}/);
  assert.doesNotMatch(source, /client.?secret|credential reset/i);
});
