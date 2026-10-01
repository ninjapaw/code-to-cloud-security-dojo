import { writeFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { isIP } from "node:net";
import spawn from "cross-spawn";
import { githubEnvironmentSubject } from "./github-oidc-subject.mjs";
import { names } from "../shared/config.mjs";

const { values } = parseArgs({
  options: {
    apply: { type: "boolean", default: false },
    remove: { type: "boolean", default: false },
    "confirm-remove": { type: "string" },
    repo: { type: "string", default: "ninjapaw/code-to-cloud-security-dojo" },
    environment: { type: "string", default: "code-to-cloud-training" },
    subscription: { type: "string" },
    "resource-group": { type: "string", default: "code-to-cloud-training" },
    location: { type: "string", default: "centralus" },
    "operator-object-id": { type: "string" },
    "admin-cidr": { type: "string" },
    "reviewer-id": { type: "string" },
    "app-name": {
      type: "string",
      default: "code-to-cloud-security-dojo-code-to-cloud-training-github",
    },
    "protection-app-name": {
      type: "string",
      default:
        "code-to-cloud-security-dojo-code-to-cloud-training-protection-github",
    },
    "adopt-app-id": { type: "string" },
    "adopt-protection-app-id": { type: "string" },
  },
});

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const dryRun = !values.apply;
const subscriptionId = values.subscription;
const resourceGroup = values["resource-group"];
const subscriptionScope = `/subscriptions/${subscriptionId}`;
const groupScope = `${subscriptionScope}/resourceGroups/${resourceGroup}`;
const managedTag = "code-to-cloud-security-dojo-managed";
const issuer = "https://token.actions.githubusercontent.com";
const audience = "api://AzureADTokenExchange";
const assignmentDescription =
  "Code to Cloud Security Dojo GitHub OIDC deployment";
const defenderReaderRole = "Code to Cloud Dojo Defender Pricing Reader";
const defenderOperatorRole = "Code to Cloud Dojo Defender Pricing Operator";
const roles = {
  contributor: "b24988ac-6180-42a0-ab88-20f7382dd24c",
  rbacAdmin: "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
  keyVaultSecretsOfficer: "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
  acrPush: "8311e382-0749-4cb8-b61a-304f252e45ec",
  blobContributor: "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
  securityAdmin: "fb1c8493-542b-48eb-b624-b4c8fea62acd",
  securityReader: "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
  acrPull: "7f951dda-4ed3-4680-a7ca-43fe172d538d",
  keyVaultSecretsUser: "4633458b-17de-408a-b874-0445c86b69e6",
  reader: "acdd72a7-3385-48ef-bd42-f606fba81ae7",
};
const providers = [
  "Microsoft.Web",
  "Microsoft.Network",
  "Microsoft.ContainerRegistry",
  "Microsoft.KeyVault",
  "Microsoft.Storage",
  "Microsoft.OperationalInsights",
  "Microsoft.Insights",
  "Microsoft.ManagedIdentity",
  "Microsoft.Security",
];

function fail(message) {
  throw new Error(message);
}

function run(command, args, { allowFailure = false, input } = {}) {
  const result = spawn.sync(command, args, {
    encoding: "utf8",
    input,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  if (result.status !== 0 && !allowFailure)
    fail(
      result.stderr.trim() || `${command} failed with exit ${result.status}`,
    );
  return result.status === 0 ? result.stdout.trim() : "";
}

const az = (args, options) => run("az", args, options);
const gh = (args, options) => run("gh", args, options);

function json(command, args, options) {
  const output = run(command, args, options);
  return output ? JSON.parse(output) : null;
}

function status(kind, message) {
  process.stdout.write(`${kind.padEnd(6)} ${message}\n`);
}

function applyStep(message, action) {
  if (dryRun) return status("would", message);
  action();
  status("done", message);
}

function getVariable(name) {
  return json(
    "gh",
    [
      "variable",
      "list",
      "--repo",
      values.repo,
      "--env",
      values.environment,
      "--json",
      "name,value",
    ],
    { allowFailure: true },
  )?.find((item) => item.name === name)?.value;
}

function validateInputs() {
  if (!uuid.test(subscriptionId || "")) fail("--subscription must be a UUID");
  if (!uuid.test(values["operator-object-id"] || ""))
    fail("--operator-object-id must be a UUID");
  const [adminAddress, adminPrefix] = (values["admin-cidr"] || "").split("/");
  if (
    isIP(adminAddress) !== 4 ||
    adminPrefix !== "32" ||
    /^(0|10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01])|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])|22[4-9]|23\d|24\d|25[0-5])\./.test(
      adminAddress,
    )
  )
    fail("--admin-cidr must be one public IPv4 /32");
  if (!/^[a-z][a-z0-9-]{2,35}$/.test(resourceGroup))
    fail("--resource-group is invalid");
  if (!/^[a-z]+[0-9]?$/.test(values.location)) fail("--location is invalid");
  if (values["reviewer-id"] && !/^\d+$/.test(values["reviewer-id"]))
    fail("--reviewer-id must be numeric");
}

function ensureEnvironment(repository) {
  const reviewerId =
    values["reviewer-id"] || gh(["api", "user", "--jq", ".id"]);
  const body = {
    wait_timer: 0,
    prevent_self_review: true,
    reviewers: [{ type: "User", id: Number(reviewerId) }],
    deployment_branch_policy: {
      protected_branches: false,
      custom_branch_policies: true,
    },
  };
  const current = json(
    "gh",
    ["api", `repos/${values.repo}/environments/${values.environment}`],
    { allowFailure: true },
  );
  const reviewerRule = (current?.protection_rules || []).find(
    (rule) => rule.type === "required_reviewers",
  );
  const currentReviewers = reviewerRule?.reviewers?.map(
    (item) => item.reviewer?.id,
  );
  if (
    current?.deployment_branch_policy?.custom_branch_policies === true &&
    current?.deployment_branch_policy?.protected_branches === false &&
    reviewerRule?.prevent_self_review === true &&
    currentReviewers?.includes(Number(reviewerId))
  )
    status("ok", `GitHub environment ${values.environment} is protected`);
  else
    applyStep(`protect GitHub environment ${values.environment}`, () => {
      gh(
        [
          "api",
          "--method",
          "PUT",
          `repos/${values.repo}/environments/${values.environment}`,
          "--input",
          "-",
        ],
        { input: JSON.stringify(body) },
      );
    });
  const policies = json(
    "gh",
    [
      "api",
      `repos/${values.repo}/environments/${values.environment}/deployment-branch-policies`,
    ],
    { allowFailure: true },
  );
  if (!(policies?.branch_policies || []).some((item) => item.name === "dev"))
    applyStep("bind deployment environment to dev", () => {
      gh(
        [
          "api",
          "--method",
          "POST",
          `repos/${values.repo}/environments/${values.environment}/deployment-branch-policies`,
          "--input",
          "-",
        ],
        { input: JSON.stringify({ name: "dev", type: "branch" }) },
      );
    });
  else status("ok", "deployment environment is bound to dev");
  return githubEnvironmentSubject(repository, values.environment);
}

function ensureApplication(displayName, objectIdVariable, adoptAppId) {
  const matches = json("az", [
    "ad",
    "app",
    "list",
    "--display-name",
    displayName,
    "--output",
    "json",
  ]);
  if (matches.length > 1) fail(`Multiple applications named ${displayName}`);
  let application = matches[0];
  const persistedObjectId = getVariable(objectIdVariable);
  if (
    application &&
    (persistedObjectId !== application.id ||
      !application.tags?.includes(managedTag)) &&
    adoptAppId !== application.appId
  )
    fail(
      `Refusing unowned Entra application ${displayName}; pass its explicit adoption option with ${application.appId} only after reviewing owners and credentials`,
    );
  if (!application) {
    if (dryRun) {
      status("would", `create Entra application ${displayName}`);
      return { appId: "<new>", id: "<new>", principalId: "<new>" };
    }
    application = json("az", [
      "ad",
      "app",
      "create",
      "--display-name",
      displayName,
      "--sign-in-audience",
      "AzureADMyOrg",
      "--output",
      "json",
    ]);
    status("done", `create Entra application ${displayName}`);
  } else status("ok", `Entra application ${displayName} exists`);
  if (
    (application.passwordCredentials?.length || 0) > 0 ||
    (application.keyCredentials?.length || 0) > 0
  )
    fail(
      `Refusing ${displayName}: GitHub OIDC applications must be secretless`,
    );
  if (!application.tags?.includes(managedTag)) {
    applyStep(`tag Entra application ${displayName}`, () => {
      az([
        "ad",
        "app",
        "update",
        "--id",
        application.appId,
        "--set",
        `tags=["${managedTag}"]`,
      ]);
    });
    application.tags = [managedTag];
  } else status("ok", "Entra application management tag is current");
  let principal = json(
    "az",
    ["ad", "sp", "show", "--id", application.appId, "--output", "json"],
    { allowFailure: true },
  );
  if (!principal) {
    if (dryRun) status("would", "create service principal");
    else {
      principal = json("az", [
        "ad",
        "sp",
        "create",
        "--id",
        application.appId,
        "--output",
        "json",
      ]);
      status("done", "create service principal");
    }
  } else status("ok", "service principal exists");
  if (
    (principal?.passwordCredentials?.length || 0) > 0 ||
    (principal?.keyCredentials?.length || 0) > 0
  )
    fail(`Refusing ${displayName}: its service principal must be secretless`);
  return { ...application, principalId: principal?.id || "<new>" };
}

async function ensureCredential(application, subject, name) {
  if (application.id === "<new>")
    return status("would", `trust GitHub subject ${subject}`);
  const credentials = json("az", [
    "ad",
    "app",
    "federated-credential",
    "list",
    "--id",
    application.id,
    "--output",
    "json",
  ]);
  if (credentials.length > 1)
    fail(
      `Refusing ${application.appId}: unexpected additional federated credentials`,
    );
  const existing = credentials.find((item) => item.subject === subject);
  if (existing) {
    if (
      existing.name !== name ||
      existing.issuer !== issuer ||
      existing.audiences?.length !== 1 ||
      existing.audiences[0] !== audience
    )
      fail(
        `Federated credential for ${subject} has unexpected issuer, audience, or name`,
      );
    return status("ok", `federated credential ${existing.name} exists`);
  }
  if (credentials.length)
    fail(`Refusing unexpected federated credential ${credentials[0].name}`);
  const path = join(tmpdir(), `dojo-fic-${process.pid}.json`);
  if (dryRun) return status("would", `trust GitHub subject ${subject}`);
  await writeFile(
    path,
    JSON.stringify({
      name,
      issuer,
      subject,
      audiences: [audience],
    }),
  );
  try {
    az([
      "ad",
      "app",
      "federated-credential",
      "create",
      "--id",
      application.id,
      "--parameters",
      `@${path}`,
    ]);
    status("done", `trust GitHub subject ${subject}`);
  } finally {
    await rm(path, { force: true });
  }
}

function ensureGroup() {
  const group = json(
    "az",
    [
      "group",
      "show",
      "--name",
      resourceGroup,
      "--subscription",
      subscriptionId,
      "--output",
      "json",
    ],
    { allowFailure: true },
  );
  if (group) {
    if (
      group.tags?.["dojo.labId"] !== "code-to-cloud-training" ||
      group.tags?.["dojo.managedBy"] !== "code-to-cloud-security-dojo"
    )
      fail(`Refusing existing unowned resource group ${resourceGroup}`);
    return status("ok", `owned resource group ${resourceGroup} exists`);
  }
  applyStep(`create owned resource group ${resourceGroup}`, () => {
    az([
      "group",
      "create",
      "--name",
      resourceGroup,
      "--location",
      values.location,
      "--subscription",
      subscriptionId,
      "--tags",
      "dojo.labId=code-to-cloud-training",
      "dojo.managedBy=code-to-cloud-security-dojo",
    ]);
  });
}

function ensureProviders() {
  for (const namespace of providers) {
    const state = az(
      [
        "provider",
        "show",
        "--namespace",
        namespace,
        "--subscription",
        subscriptionId,
        "--query",
        "registrationState",
        "--output",
        "tsv",
      ],
      { allowFailure: true },
    );
    if (state === "Registered") status("ok", `${namespace} is registered`);
    else
      applyStep(`register ${namespace}`, () =>
        az([
          "provider",
          "register",
          "--namespace",
          namespace,
          "--subscription",
          subscriptionId,
          "--wait",
        ]),
      );
  }
}

async function ensureCustomRole(roleName, actions) {
  const matches = json("az", [
    "role",
    "definition",
    "list",
    "--name",
    roleName,
    "--subscription",
    subscriptionId,
    "--output",
    "json",
  ]);
  if (matches.length > 1) fail(`Multiple custom roles named ${roleName}`);
  if (matches[0]) {
    const permissions = matches[0].permissions || [];
    const assignableScopes = [...(matches[0].assignableScopes || [])].sort();
    if (
      matches[0].roleType !== "CustomRole" ||
      permissions.length !== 1 ||
      JSON.stringify([...(permissions[0].actions || [])].sort()) !==
        JSON.stringify([...actions].sort()) ||
      (permissions[0].notActions || []).length ||
      (permissions[0].dataActions || []).length ||
      (permissions[0].notDataActions || []).length ||
      JSON.stringify(assignableScopes) !== JSON.stringify([subscriptionScope])
    )
      fail(`Custom role ${roleName} has unexpected actions`);
    status("ok", `custom role ${roleName} is current`);
    return matches[0].name;
  }
  if (dryRun) {
    status("would", `create custom role ${roleName}`);
    return `<new:${roleName}>`;
  }
  const path = join(tmpdir(), `dojo-role-${process.pid}.json`);
  await writeFile(
    path,
    JSON.stringify({
      Name: roleName,
      Description: `${roleName} for the Code to Cloud Security Dojo workflow`,
      Actions: actions,
      NotActions: [],
      DataActions: [],
      NotDataActions: [],
      AssignableScopes: [subscriptionScope],
    }),
  );
  try {
    const created = json("az", [
      "role",
      "definition",
      "create",
      "--role-definition",
      `@${path}`,
      "--subscription",
      subscriptionId,
      "--output",
      "json",
    ]);
    status("done", `create custom role ${roleName}`);
    return created.name;
  } finally {
    await rm(path, { force: true });
  }
}

function ensurePortalIdentity() {
  const portalName = names({
    subscriptionId,
    resourceGroup,
    labId: "code-to-cloud-training",
  }).portal;
  const identityName = `${portalName}-identity`;
  let identity = json(
    "az",
    [
      "identity",
      "show",
      "--resource-group",
      resourceGroup,
      "--name",
      identityName,
      "--subscription",
      subscriptionId,
      "--output",
      "json",
    ],
    { allowFailure: true },
  );
  if (!identity) {
    if (dryRun) {
      status("would", `create portal identity ${identityName}`);
      return { name: identityName, principalId: "<new>" };
    }
    identity = json("az", [
      "identity",
      "create",
      "--resource-group",
      resourceGroup,
      "--name",
      identityName,
      "--location",
      values.location,
      "--subscription",
      subscriptionId,
      "--output",
      "json",
    ]);
    status("done", `create portal identity ${identityName}`);
  } else {
    if (
      identity.tags?.["dojo.labId"] !== "code-to-cloud-training" ||
      identity.tags?.["dojo.managedBy"] !== "code-to-cloud-security-dojo"
    )
      fail(`Refusing existing unowned portal identity ${identityName}`);
    status("ok", `portal identity ${identityName} exists`);
  }
  if (
    identity.tags?.["dojo.labId"] !== "code-to-cloud-training" ||
    identity.tags?.["dojo.managedBy"] !== "code-to-cloud-security-dojo"
  ) {
    applyStep(`tag portal identity ${identityName}`, () =>
      az([
        "tag",
        "create",
        "--resource-id",
        identity.id,
        "--tags",
        "dojo.labId=code-to-cloud-training",
        "dojo.managedBy=code-to-cloud-security-dojo",
      ]),
    );
    identity.tags = {
      "dojo.labId": "code-to-cloud-training",
      "dojo.managedBy": "code-to-cloud-security-dojo",
    };
  } else status("ok", "portal identity ownership tags are current");
  return identity;
}

function ensureRole(
  principalId,
  roleId,
  scope,
  description,
  condition,
  {
    reconcileCondition = false,
    expectedDescription = assignmentDescription,
  } = {},
) {
  if (principalId === "<new>") return status("would", description);
  if (roleId.startsWith("<new:")) return status("would", description);
  const existing = json("az", [
    "role",
    "assignment",
    "list",
    "--assignee-object-id",
    principalId,
    "--scope",
    scope,
    "--role",
    roleId,
    "--output",
    "json",
  ]);
  const match = existing.find(
    (item) => item.scope.toLowerCase() === scope.toLowerCase(),
  );
  if (match) {
    if (
      (condition || null) === (match.condition || null) &&
      match.description === expectedDescription
    )
      return status("ok", description);
    if (!reconcileCondition || match.description !== assignmentDescription)
      fail(
        `${description} exists without the required least-privilege condition`,
      );
    applyStep(`replace legacy grant: ${description}`, () =>
      az(["role", "assignment", "delete", "--ids", match.id]),
    );
  }
  applyStep(description, () => {
    az([
      "role",
      "assignment",
      "create",
      "--assignee-object-id",
      principalId,
      "--assignee-principal-type",
      "ServicePrincipal",
      "--role",
      roleId,
      "--scope",
      scope,
      "--description",
      expectedDescription,
      ...(condition
        ? ["--condition-version", "2.0", "--condition", condition]
        : []),
    ]);
  });
}

function verifyExactAssignments(principalId, expected, name) {
  if (
    principalId === "<new>" ||
    expected.some((item) => item.roleId.startsWith("<new:"))
  )
    return status("would", `verify exact ${name} role assignments`);
  const actual = json("az", [
    "role",
    "assignment",
    "list",
    "--assignee-object-id",
    principalId,
    "--subscription",
    subscriptionId,
    "--all",
    "--include-inherited",
    "--include-groups",
    "--output",
    "json",
  ]);
  const unexpected = actual.filter(
    (assignment) =>
      !expected.some(
        (item) =>
          assignment.roleDefinitionId
            .toLowerCase()
            .endsWith(item.roleId.toLowerCase()) &&
          assignment.scope.toLowerCase() === item.scope.toLowerCase() &&
          (assignment.condition || null) === (item.condition || null),
      ),
  );
  if (unexpected.length)
    fail(
      `${name} has unexpected effective role assignments: ${unexpected
        .map((item) => `${item.roleDefinitionName}@${item.scope}`)
        .join(", ")}`,
    );
  if (actual.length !== expected.length)
    fail(`${name} role assignment count does not match the required allowlist`);
  status("ok", `${name} role assignments exactly match the allowlist`);
}

function removeManagedRole(principalId, roleId, scope, description) {
  const existing = json("az", [
    "role",
    "assignment",
    "list",
    "--assignee-object-id",
    principalId,
    "--scope",
    scope,
    "--role",
    roleId,
    "--output",
    "json",
  ]).find((item) => item.scope.toLowerCase() === scope.toLowerCase());
  if (!existing) return status("ok", `${description} is absent`);
  if (existing.description !== assignmentDescription)
    fail(`Refusing to remove unmanaged assignment: ${description}`);
  applyStep(description, () =>
    az(["role", "assignment", "delete", "--ids", existing.id]),
  );
}

function setVariable(name, value) {
  if (value === "<new>") return status("would", `set GitHub variable ${name}`);
  const existing = json(
    "gh",
    [
      "variable",
      "list",
      "--repo",
      values.repo,
      "--env",
      values.environment,
      "--json",
      "name,value",
    ],
    { allowFailure: true },
  );
  if (existing?.some((item) => item.name === name && item.value === value))
    return status("ok", `GitHub variable ${name} is current`);
  applyStep(`set GitHub variable ${name}`, () =>
    gh([
      "variable",
      "set",
      name,
      "--repo",
      values.repo,
      "--env",
      values.environment,
      "--body",
      value,
    ]),
  );
}

function retireBootstrap() {
  const expected = `retire:${subscriptionId}:${resourceGroup}`;
  if (values["confirm-remove"] !== expected)
    fail(`Retirement requires --confirm-remove ${expected}`);
  const groupExists = az(
    [
      "group",
      "exists",
      "--name",
      resourceGroup,
      "--subscription",
      subscriptionId,
      "--output",
      "tsv",
    ],
    { allowFailure: true },
  );
  if (groupExists === "true")
    fail("Refusing to retire OIDC while the lab resource group still exists");
  const appObjects = [
    ["AZURE_APP_OBJECT_ID", "AZURE_CLIENT_ID"],
    ["AZURE_PROTECTION_APP_OBJECT_ID", "AZURE_PROTECTION_CLIENT_ID"],
  ].map(([objectVariable, clientVariable]) => ({
    objectId: getVariable(objectVariable),
    appId: getVariable(clientVariable),
  }));
  for (const application of appObjects) {
    if (
      !uuid.test(application.objectId || "") ||
      !uuid.test(application.appId || "")
    )
      fail("Persisted app object/client IDs are required for safe retirement");
    const app = json("az", [
      "ad",
      "app",
      "show",
      "--id",
      application.objectId,
      "--output",
      "json",
    ]);
    if (app.appId !== application.appId || !app.tags?.includes(managedTag))
      fail(`Refusing to retire unowned app object ${application.objectId}`);
    const principal = json("az", [
      "ad",
      "sp",
      "show",
      "--id",
      application.appId,
      "--output",
      "json",
    ]);
    const assignments = json("az", [
      "role",
      "assignment",
      "list",
      "--assignee-object-id",
      principal.id,
      "--subscription",
      subscriptionId,
      "--all",
      "--output",
      "json",
    ]);
    if (assignments.some((item) => item.description !== assignmentDescription))
      fail(
        `Refusing to remove unmanaged assignments from ${application.appId}`,
      );
    for (const assignment of assignments)
      applyStep(`remove assignment ${assignment.id}`, () =>
        az(["role", "assignment", "delete", "--ids", assignment.id]),
      );
    applyStep(`delete service principal ${principal.id}`, () =>
      az(["ad", "sp", "delete", "--id", principal.id]),
    );
    applyStep(`delete Entra application ${application.objectId}`, () =>
      az(["ad", "app", "delete", "--id", application.objectId]),
    );
  }
  for (const roleName of [defenderReaderRole, defenderOperatorRole]) {
    const definitions = json("az", [
      "role",
      "definition",
      "list",
      "--name",
      roleName,
      "--subscription",
      subscriptionId,
      "--output",
      "json",
    ]);
    if (definitions[0])
      applyStep(`delete custom role ${roleName}`, () =>
        az([
          "role",
          "definition",
          "delete",
          "--name",
          definitions[0].name,
          "--subscription",
          subscriptionId,
        ]),
      );
  }
  for (const name of [
    "AZURE_CLIENT_ID",
    "AZURE_APP_OBJECT_ID",
    "AZURE_PROTECTION_CLIENT_ID",
    "AZURE_PROTECTION_APP_OBJECT_ID",
  ])
    applyStep(`delete GitHub variable ${name}`, () =>
      gh([
        "variable",
        "delete",
        name,
        "--repo",
        values.repo,
        "--env",
        values.environment,
      ]),
    );
  process.stdout.write(
    dryRun
      ? "\nNothing was changed. Re-run with --apply after review.\n"
      : "\nGitHub OIDC bootstrap retired.\n",
  );
}

async function main() {
  validateInputs();
  const account = json("az", [
    "account",
    "show",
    "--subscription",
    subscriptionId,
    "--output",
    "json",
  ]);
  if (account.state !== "Enabled" || account.environmentName !== "AzureCloud")
    fail("The selected Azure subscription must be enabled in AzureCloud");
  gh(["auth", "status"]);
  const repository = json("gh", ["api", `repos/${values.repo}`]);
  if (values.remove) return retireBootstrap();
  const subject = ensureEnvironment(repository);
  const application = ensureApplication(
    values["app-name"],
    "AZURE_APP_OBJECT_ID",
    values["adopt-app-id"],
  );
  await ensureCredential(application, subject, "github-code-to-cloud-training");
  const protectionApplication = ensureApplication(
    values["protection-app-name"],
    "AZURE_PROTECTION_APP_OBJECT_ID",
    values["adopt-protection-app-id"],
  );
  await ensureCredential(
    protectionApplication,
    subject,
    "github-code-to-cloud-training-protection",
  );
  ensureGroup();
  ensureProviders();
  const portalIdentity = ensurePortalIdentity();
  for (const [roleId, description] of [
    [roles.contributor, "grant Contributor on the dedicated lab group"],
    [
      roles.keyVaultSecretsOfficer,
      "grant Key Vault Secrets Officer on the dedicated lab group",
    ],
    [roles.acrPush, "grant AcrPush on the dedicated lab group"],
    [
      roles.blobContributor,
      "grant Storage Blob Data Contributor on the dedicated lab group",
    ],
  ])
    ensureRole(application.principalId, roleId, groupScope, description);
  const groupAssignableRoles = [
    roles.acrPull,
    roles.keyVaultSecretsUser,
    roles.keyVaultSecretsOfficer,
    roles.blobContributor,
    roles.reader,
  ].join(", ");
  const groupCondition = `((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${groupAssignableRoles}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'User', 'ServicePrincipal'})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${groupAssignableRoles}} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'User', 'ServicePrincipal'}))`;
  ensureRole(
    application.principalId,
    roles.rbacAdmin,
    groupScope,
    "grant conditioned RBAC Administrator on the dedicated lab group",
    groupCondition,
    { reconcileCondition: true },
  );
  ensureRole(
    portalIdentity.principalId,
    roles.securityReader,
    subscriptionScope,
    "grant portal identity Security Reader",
    undefined,
    {
      reconcileCondition: true,
      expectedDescription: "CodeToCloud:code-to-cloud-training",
    },
  );
  const pricingReaderId = await ensureCustomRole(defenderReaderRole, [
    "Microsoft.Security/pricings/read",
  ]);
  const pricingOperatorId = await ensureCustomRole(defenderOperatorRole, [
    "Microsoft.Security/pricings/read",
    "Microsoft.Security/pricings/write",
  ]);
  ensureRole(
    application.principalId,
    pricingReaderId,
    subscriptionScope,
    "grant Defender pricing readback",
  );
  ensureRole(
    protectionApplication.principalId,
    pricingOperatorId,
    subscriptionScope,
    "grant Defender pricing reconciliation",
  );
  removeManagedRole(
    application.principalId,
    roles.securityAdmin,
    subscriptionScope,
    "remove legacy Security Admin",
  );
  removeManagedRole(
    application.principalId,
    roles.rbacAdmin,
    subscriptionScope,
    "remove legacy subscription RBAC Administrator",
  );
  verifyExactAssignments(
    application.principalId,
    [
      { roleId: roles.contributor, scope: groupScope },
      { roleId: roles.keyVaultSecretsOfficer, scope: groupScope },
      { roleId: roles.acrPush, scope: groupScope },
      { roleId: roles.blobContributor, scope: groupScope },
      { roleId: roles.rbacAdmin, scope: groupScope, condition: groupCondition },
      { roleId: pricingReaderId, scope: subscriptionScope },
    ],
    "infrastructure identity",
  );
  verifyExactAssignments(
    protectionApplication.principalId,
    [{ roleId: pricingOperatorId, scope: subscriptionScope }],
    "protection identity",
  );
  for (const [name, value] of Object.entries({
    AZURE_CLIENT_ID: application.appId,
    AZURE_APP_OBJECT_ID: application.id,
    AZURE_PROTECTION_CLIENT_ID: protectionApplication.appId,
    AZURE_PROTECTION_APP_OBJECT_ID: protectionApplication.id,
    AZURE_TENANT_ID: account.tenantId,
    AZURE_SUBSCRIPTION_ID: subscriptionId,
    DOJO_RESOURCE_GROUP: resourceGroup,
    DOJO_LOCATION: values.location,
    DOJO_OPERATOR_OBJECT_ID: values["operator-object-id"],
    DOJO_ADMIN_CIDR: values["admin-cidr"],
  }))
    setVariable(name, value);
  if (!dryRun) {
    await mkdir(".azure", { recursive: true });
    await writeFile(
      ".azure/oidc-bootstrap.json",
      `${JSON.stringify(
        {
          schemaVersion: 1,
          repository: values.repo,
          environment: values.environment,
          subject,
          applicationId: application.appId,
          principalId: application.principalId,
          protectionApplicationId: protectionApplication.appId,
          protectionPrincipalId: protectionApplication.principalId,
          portalPrincipalId: portalIdentity.principalId,
          subscriptionId,
          resourceGroup,
        },
        null,
        2,
      )}\n`,
    );
  }
  process.stdout.write(
    dryRun
      ? "\nNothing was changed. Re-run with --apply after review.\n"
      : "\nGitHub OIDC bootstrap completed. Re-run to verify idempotency.\n",
  );
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
